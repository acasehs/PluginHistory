"""
RAG Sync Module
Handles synchronization of threat intelligence data to OpenWebUI knowledge collections.
"""

import requests
import json
import threading
import time
import os
import tempfile
from typing import Dict, List, Any, Optional, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime

from .threat_intel import NormalizedVulnData, ThreatFeedSource


@dataclass
class RAGSyncResult:
    """Result from a RAG sync operation."""
    success: bool
    collection_name: str
    documents_uploaded: int = 0
    documents_failed: int = 0
    error: str = ""
    duration_seconds: float = 0.0


@dataclass
class RAGSyncProgress:
    """Progress update during RAG sync."""
    status: str  # "preparing", "uploading", "processing", "complete", "error"
    progress_pct: float = 0.0
    message: str = ""
    documents_processed: int = 0
    total_documents: int = 0


class RAGSyncManager:
    """
    Manages synchronization of threat intelligence data to OpenWebUI RAG collections.
    """

    # Batch size for document uploads
    BATCH_SIZE = 100

    def __init__(
        self,
        base_url: str,
        api_key: str,
        collection_name: str = "vuln_intelligence"
    ):
        """
        Initialize RAG sync manager.

        Args:
            base_url: OpenWebUI base URL
            api_key: OpenWebUI API key
            collection_name: Name of the knowledge collection to use/create
        """
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.collection_name = collection_name
        self._collection_id: Optional[str] = None
        self._progress_callbacks: List[Callable[[RAGSyncProgress], None]] = []

    def add_progress_callback(self, callback: Callable[[RAGSyncProgress], None]):
        """Add callback for sync progress updates."""
        self._progress_callbacks.append(callback)

    def _notify_progress(self, progress: RAGSyncProgress):
        """Notify all progress callbacks."""
        for callback in self._progress_callbacks:
            try:
                callback(progress)
            except Exception:
                pass

    def _get_headers(self) -> Dict[str, str]:
        """Get request headers with authentication."""
        return {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }

    def _get_or_create_collection(self) -> Tuple[Optional[str], Optional[str]]:
        """
        Get existing collection or create a new one.

        Returns:
            Tuple of (collection_id, error_message)
        """
        # First, try to find existing collection
        try:
            response = requests.get(
                f"{self.base_url}/api/v1/knowledge",
                headers=self._get_headers(),
                timeout=30
            )

            if response.status_code == 200:
                collections = response.json()
                if isinstance(collections, dict):
                    collections = collections.get('data', [])

                for col in collections:
                    if col.get('name') == self.collection_name:
                        self._collection_id = col.get('id')
                        return self._collection_id, None

            # Collection not found, create it
            create_response = requests.post(
                f"{self.base_url}/api/v1/knowledge/create",
                headers=self._get_headers(),
                json={
                    'name': self.collection_name,
                    'description': 'Vulnerability intelligence data (CVE, EPSS, KEV, IAVM)'
                },
                timeout=30
            )

            if create_response.status_code in [200, 201]:
                result = create_response.json()
                self._collection_id = result.get('id')
                return self._collection_id, None
            else:
                return None, f"Failed to create collection: HTTP {create_response.status_code}"

        except Exception as e:
            return None, f"Error accessing collections: {str(e)}"

    def _prepare_documents(
        self,
        data: List[NormalizedVulnData],
        include_raw: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Prepare normalized data as documents for RAG upload.

        Args:
            data: List of normalized vulnerability data
            include_raw: Include raw data in documents (increases size)

        Returns:
            List of document dictionaries
        """
        documents = []

        for item in data:
            # Create text content for RAG
            content = item.to_rag_document()

            # Create metadata
            metadata = {
                'source': item.source,
                'identifier': item.identifier,
                'cvss_score': item.cvss_score,
                'epss_score': item.epss_score,
                'actively_exploited': item.actively_exploited,
                'last_updated': item.last_updated
            }

            if include_raw:
                metadata['raw_data'] = json.dumps(item.raw_data)

            documents.append({
                'content': content,
                'metadata': metadata,
                'id': f"{item.source}_{item.identifier}"  # Unique ID for updates
            })

        return documents

    def _upload_batch(
        self,
        collection_id: str,
        documents: List[Dict[str, Any]]
    ) -> Tuple[int, int, Optional[str]]:
        """
        Upload a batch of documents to the collection.

        Returns:
            Tuple of (success_count, fail_count, error_message)
        """
        success_count = 0
        fail_count = 0

        # OpenWebUI uses file upload for knowledge bases
        # We'll create a temporary JSON file and upload it

        try:
            # Create temporary file with documents
            with tempfile.NamedTemporaryFile(
                mode='w',
                suffix='.json',
                delete=False
            ) as f:
                # Format as array of text documents
                doc_texts = [d['content'] for d in documents]
                json.dump(doc_texts, f)
                temp_path = f.name

            try:
                # Upload file to collection
                with open(temp_path, 'rb') as f:
                    files = {'file': (f'{self.collection_name}_batch.json', f, 'application/json')}

                    # Remove Content-Type from headers for multipart upload
                    headers = {'Authorization': f'Bearer {self.api_key}'}

                    response = requests.post(
                        f"{self.base_url}/api/v1/knowledge/{collection_id}/file/add",
                        headers=headers,
                        files=files,
                        timeout=120
                    )

                    if response.status_code in [200, 201]:
                        success_count = len(documents)
                    else:
                        # Try alternative endpoint
                        response = requests.post(
                            f"{self.base_url}/api/v1/files/",
                            headers=headers,
                            files=files,
                            data={'collection_id': collection_id},
                            timeout=120
                        )

                        if response.status_code in [200, 201]:
                            success_count = len(documents)
                        else:
                            fail_count = len(documents)
                            return success_count, fail_count, f"Upload failed: HTTP {response.status_code}"

            finally:
                # Clean up temp file
                os.unlink(temp_path)

            return success_count, fail_count, None

        except Exception as e:
            return 0, len(documents), str(e)

    def _upload_as_text_documents(
        self,
        collection_id: str,
        documents: List[Dict[str, Any]]
    ) -> Tuple[int, int, Optional[str]]:
        """
        Alternative upload method: create individual text documents.

        Returns:
            Tuple of (success_count, fail_count, error_message)
        """
        success_count = 0
        fail_count = 0

        for doc in documents:
            try:
                # Try direct document creation endpoint
                response = requests.post(
                    f"{self.base_url}/api/v1/knowledge/{collection_id}/doc/add",
                    headers=self._get_headers(),
                    json={
                        'content': doc['content'],
                        'name': doc['id'],
                        'metadata': doc.get('metadata', {})
                    },
                    timeout=30
                )

                if response.status_code in [200, 201]:
                    success_count += 1
                else:
                    fail_count += 1

                # Small delay to avoid rate limiting
                time.sleep(0.1)

            except Exception:
                fail_count += 1

        return success_count, fail_count, None

    def sync(
        self,
        data: List[NormalizedVulnData],
        clear_existing: bool = False
    ) -> RAGSyncResult:
        """
        Sync threat intelligence data to RAG collection.

        Args:
            data: List of normalized vulnerability data
            clear_existing: Clear existing collection data before sync

        Returns:
            RAGSyncResult with sync outcome
        """
        start_time = time.time()

        self._notify_progress(RAGSyncProgress(
            status="preparing",
            message="Preparing documents for upload..."
        ))

        # Get or create collection
        collection_id, error = self._get_or_create_collection()
        if error:
            return RAGSyncResult(
                success=False,
                collection_name=self.collection_name,
                error=error,
                duration_seconds=time.time() - start_time
            )

        # Clear existing if requested
        if clear_existing:
            self._notify_progress(RAGSyncProgress(
                status="preparing",
                message="Clearing existing collection data..."
            ))
            # Note: OpenWebUI may not have a clear endpoint, skip if not available
            try:
                requests.delete(
                    f"{self.base_url}/api/v1/knowledge/{collection_id}/clear",
                    headers=self._get_headers(),
                    timeout=30
                )
            except Exception:
                pass  # Ignore if endpoint doesn't exist

        # Prepare documents
        documents = self._prepare_documents(data)
        total_docs = len(documents)

        if total_docs == 0:
            return RAGSyncResult(
                success=True,
                collection_name=self.collection_name,
                documents_uploaded=0,
                duration_seconds=time.time() - start_time
            )

        self._notify_progress(RAGSyncProgress(
            status="uploading",
            message=f"Uploading {total_docs} documents...",
            total_documents=total_docs
        ))

        # Upload in batches
        total_success = 0
        total_fail = 0

        for i in range(0, total_docs, self.BATCH_SIZE):
            batch = documents[i:i + self.BATCH_SIZE]

            success, fail, error = self._upload_batch(collection_id, batch)

            # If batch upload fails, try individual documents
            if fail > 0 and error:
                success2, fail2, _ = self._upload_as_text_documents(collection_id, batch)
                success = success2
                fail = fail2

            total_success += success
            total_fail += fail

            self._notify_progress(RAGSyncProgress(
                status="uploading",
                progress_pct=(i + len(batch)) / total_docs * 100,
                message=f"Uploaded {total_success}/{total_docs} documents...",
                documents_processed=total_success,
                total_documents=total_docs
            ))

        self._notify_progress(RAGSyncProgress(
            status="complete",
            progress_pct=100,
            message=f"Sync complete: {total_success} uploaded, {total_fail} failed",
            documents_processed=total_success,
            total_documents=total_docs
        ))

        return RAGSyncResult(
            success=total_fail == 0,
            collection_name=self.collection_name,
            documents_uploaded=total_success,
            documents_failed=total_fail,
            error=f"{total_fail} documents failed to upload" if total_fail > 0 else "",
            duration_seconds=time.time() - start_time
        )

    def sync_async(
        self,
        data: List[NormalizedVulnData],
        callback: Callable[[RAGSyncResult], None],
        clear_existing: bool = False
    ):
        """
        Sync data asynchronously.

        Args:
            data: Normalized data to sync
            callback: Called with result when complete
            clear_existing: Clear existing data first
        """
        def _sync():
            result = self.sync(data, clear_existing)
            callback(result)

        thread = threading.Thread(target=_sync, daemon=True)
        thread.start()

    def get_collection_stats(self) -> Optional[Dict[str, Any]]:
        """Get statistics about the current collection."""
        if not self._collection_id:
            collection_id, _ = self._get_or_create_collection()
            if not collection_id:
                return None
        else:
            collection_id = self._collection_id

        try:
            response = requests.get(
                f"{self.base_url}/api/v1/knowledge/{collection_id}",
                headers=self._get_headers(),
                timeout=30
            )

            if response.status_code == 200:
                return response.json()

        except Exception:
            pass

        return None

    def test_connection(self) -> Tuple[bool, str]:
        """
        Test connection to OpenWebUI and verify collection access.

        Returns:
            Tuple of (success, message)
        """
        try:
            # Test basic connectivity
            response = requests.get(
                f"{self.base_url}/api/v1/knowledge",
                headers=self._get_headers(),
                timeout=10
            )

            if response.status_code == 401:
                return False, "Invalid API key"
            elif response.status_code != 200:
                return False, f"Connection failed: HTTP {response.status_code}"

            # Try to access/create collection
            collection_id, error = self._get_or_create_collection()
            if error:
                return False, error

            return True, f"Connected. Collection '{self.collection_name}' ready."

        except requests.exceptions.Timeout:
            return False, "Connection timed out"
        except requests.exceptions.ConnectionError as e:
            return False, f"Connection failed: {str(e)[:50]}"
        except Exception as e:
            return False, f"Error: {str(e)[:50]}"


def create_combined_rag_document(
    merged_data: Dict[str, NormalizedVulnData],
    plugins_data: Optional[List[Dict[str, Any]]] = None
) -> List[NormalizedVulnData]:
    """
    Create a combined list of documents for RAG from merged threat intel
    and optional plugins database data.

    Args:
        merged_data: Dictionary of CVE ID -> NormalizedVulnData (from ThreatIntelManager.merge_data_by_cve)
        plugins_data: Optional list of plugin info from plugins database

    Returns:
        List of NormalizedVulnData ready for RAG sync
    """
    documents = list(merged_data.values())

    # Add plugins database entries if provided
    if plugins_data:
        for plugin in plugins_data:
            plugin_id = plugin.get('plugin_id', plugin.get('id', ''))
            if not plugin_id:
                continue

            # Check if we already have CVE data for this plugin
            cves = plugin.get('cves', plugin.get('cve', ''))
            if cves:
                cve_list = [c.strip() for c in str(cves).split(',') if c.strip()]
                # Skip if we already have this CVE in merged data
                if any(cve in merged_data for cve in cve_list):
                    continue

            doc = NormalizedVulnData(
                source=ThreatFeedSource.PLUGINS_DB.value,
                identifier=f"PLUGIN-{plugin_id}",
                title=plugin.get('name', plugin.get('plugin_name', f'Plugin {plugin_id}')),
                description=plugin.get('description', plugin.get('synopsis', '')),
                cvss_score=plugin.get('cvss_base_score', plugin.get('cvss3_base_score')),
                vendor=plugin.get('vendor', ''),
                product=plugin.get('product', ''),
                remediation=plugin.get('solution', ''),
                last_updated=datetime.now().isoformat(),
                raw_data=plugin
            )

            # Add CVE reference if present
            if cves:
                doc.description += f"\n\nRelated CVEs: {cves}"

            documents.append(doc)

    return documents
