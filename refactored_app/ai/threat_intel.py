"""
Threat Intelligence Module
Fetches and normalizes data from CISA KEV, EPSS, NVD, and DISA IAVM feeds.
"""

import requests
import json
import csv
import io
import threading
import time
from typing import Dict, List, Any, Optional, Callable, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
import gzip


class ThreatFeedSource(Enum):
    """Available threat intelligence feed sources."""
    CISA_KEV = "cisa_kev"
    EPSS = "epss"
    NVD = "nvd"
    DISA_IAVM = "disa_iavm"
    PLUGINS_DB = "plugins_db"


@dataclass
class NormalizedVulnData:
    """
    Standardized vulnerability data structure across all sources.
    This is the common schema for RAG ingestion.
    """
    source: str
    identifier: str  # CVE ID or IAVM ID
    title: str = ""
    description: str = ""

    # Scoring
    cvss_score: Optional[float] = None
    cvss_vector: str = ""
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None

    # KEV specific
    kev_added_date: str = ""
    kev_due_date: str = ""
    actively_exploited: bool = False

    # Product info
    vendor: str = ""
    product: str = ""
    affected_versions: str = ""

    # Remediation
    remediation: str = ""
    references: List[str] = field(default_factory=list)

    # Metadata
    last_updated: str = ""
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)

    def to_rag_document(self) -> str:
        """Convert to text format suitable for RAG ingestion."""
        parts = [
            f"Identifier: {self.identifier}",
            f"Source: {self.source}",
            f"Title: {self.title}" if self.title else "",
            f"Description: {self.description}" if self.description else "",
        ]

        if self.cvss_score is not None:
            parts.append(f"CVSS Score: {self.cvss_score}")

        if self.epss_score is not None:
            parts.append(f"EPSS Score: {self.epss_score} (Percentile: {self.epss_percentile})")

        if self.actively_exploited:
            parts.append("STATUS: ACTIVELY EXPLOITED (CISA KEV)")
            if self.kev_due_date:
                parts.append(f"KEV Remediation Due: {self.kev_due_date}")

        if self.vendor or self.product:
            parts.append(f"Affected: {self.vendor} {self.product} {self.affected_versions}".strip())

        if self.remediation:
            parts.append(f"Remediation: {self.remediation}")

        return "\n".join(p for p in parts if p)


@dataclass
class SyncResult:
    """Result from a threat intel sync operation."""
    success: bool
    source: ThreatFeedSource
    records_fetched: int = 0
    records_processed: int = 0
    error: str = ""
    duration_seconds: float = 0.0


@dataclass
class SyncProgress:
    """Progress update during sync."""
    source: ThreatFeedSource
    status: str
    progress_pct: float = 0.0
    message: str = ""


class ThreatIntelManager:
    """
    Manages threat intelligence feeds.
    Fetches, normalizes, and prepares data for RAG ingestion.
    """

    # API endpoints
    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    # DISA IAVM - URL configured by user (requires authentication)

    def __init__(
        self,
        nvd_api_key: str = "",
        iavm_url: str = "",
        iavm_api_key: str = ""
    ):
        """Initialize threat intel manager."""
        self.nvd_api_key = nvd_api_key
        self.iavm_url = iavm_url
        self.iavm_api_key = iavm_api_key

        self._cache: Dict[str, List[NormalizedVulnData]] = {}
        self._sync_in_progress = False
        self._progress_callbacks: List[Callable[[SyncProgress], None]] = []

    def add_progress_callback(self, callback: Callable[[SyncProgress], None]):
        """Add callback for sync progress updates."""
        self._progress_callbacks.append(callback)

    def _notify_progress(self, progress: SyncProgress):
        """Notify all progress callbacks."""
        for callback in self._progress_callbacks:
            try:
                callback(progress)
            except Exception:
                pass

    # =========================================================================
    # CISA KEV
    # =========================================================================

    def fetch_cisa_kev(self) -> Tuple[List[NormalizedVulnData], Optional[str]]:
        """
        Fetch CISA Known Exploited Vulnerabilities catalog.
        No API key required.

        Returns:
            Tuple of (list of normalized data, error message or None)
        """
        self._notify_progress(SyncProgress(
            source=ThreatFeedSource.CISA_KEV,
            status="fetching",
            message="Downloading CISA KEV catalog..."
        ))

        try:
            response = requests.get(self.CISA_KEV_URL, timeout=60)
            response.raise_for_status()

            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])

            normalized = []
            total = len(vulnerabilities)

            for i, vuln in enumerate(vulnerabilities):
                cve_id = vuln.get('cveID', '')
                if not cve_id:
                    continue

                norm = NormalizedVulnData(
                    source=ThreatFeedSource.CISA_KEV.value,
                    identifier=cve_id,
                    title=vuln.get('vulnerabilityName', ''),
                    description=vuln.get('shortDescription', ''),
                    vendor=vuln.get('vendorProject', ''),
                    product=vuln.get('product', ''),
                    kev_added_date=vuln.get('dateAdded', ''),
                    kev_due_date=vuln.get('dueDate', ''),
                    actively_exploited=True,
                    remediation=vuln.get('requiredAction', ''),
                    last_updated=data.get('catalogVersion', datetime.now().isoformat()),
                    raw_data=vuln
                )
                normalized.append(norm)

                if i % 100 == 0:
                    self._notify_progress(SyncProgress(
                        source=ThreatFeedSource.CISA_KEV,
                        status="processing",
                        progress_pct=(i / total) * 100,
                        message=f"Processing {i}/{total} KEV entries..."
                    ))

            self._cache[ThreatFeedSource.CISA_KEV.value] = normalized

            self._notify_progress(SyncProgress(
                source=ThreatFeedSource.CISA_KEV,
                status="complete",
                progress_pct=100,
                message=f"Fetched {len(normalized)} KEV entries"
            ))

            return normalized, None

        except requests.exceptions.RequestException as e:
            error = f"Failed to fetch CISA KEV: {str(e)}"
            self._notify_progress(SyncProgress(
                source=ThreatFeedSource.CISA_KEV,
                status="error",
                message=error
            ))
            return [], error
        except Exception as e:
            error = f"Error processing CISA KEV: {str(e)}"
            self._notify_progress(SyncProgress(
                source=ThreatFeedSource.CISA_KEV,
                status="error",
                message=error
            ))
            return [], error

    # =========================================================================
    # EPSS
    # =========================================================================

    def fetch_epss(self) -> Tuple[List[NormalizedVulnData], Optional[str]]:
        """
        Fetch EPSS (Exploit Prediction Scoring System) data.
        No API key required.

        Returns:
            Tuple of (list of normalized data, error message or None)
        """
        self._notify_progress(SyncProgress(
            source=ThreatFeedSource.EPSS,
            status="fetching",
            message="Downloading EPSS scores (this may take a moment)..."
        ))

        try:
            response = requests.get(self.EPSS_URL, timeout=120, stream=True)
            response.raise_for_status()

            # Decompress gzip content
            decompressed = gzip.decompress(response.content)
            csv_content = decompressed.decode('utf-8')

            # Parse CSV
            reader = csv.DictReader(io.StringIO(csv_content))
            normalized = []

            rows = list(reader)
            total = len(rows)

            for i, row in enumerate(rows):
                cve_id = row.get('cve', '')
                if not cve_id:
                    continue

                try:
                    epss_score = float(row.get('epss', 0))
                    percentile = float(row.get('percentile', 0))
                except (ValueError, TypeError):
                    continue

                norm = NormalizedVulnData(
                    source=ThreatFeedSource.EPSS.value,
                    identifier=cve_id,
                    epss_score=round(epss_score, 6),
                    epss_percentile=round(percentile * 100, 2),  # Convert to percentage
                    last_updated=datetime.now().isoformat(),
                    raw_data={'epss': epss_score, 'percentile': percentile}
                )
                normalized.append(norm)

                if i % 10000 == 0:
                    self._notify_progress(SyncProgress(
                        source=ThreatFeedSource.EPSS,
                        status="processing",
                        progress_pct=(i / total) * 100,
                        message=f"Processing {i}/{total} EPSS entries..."
                    ))

            self._cache[ThreatFeedSource.EPSS.value] = normalized

            self._notify_progress(SyncProgress(
                source=ThreatFeedSource.EPSS,
                status="complete",
                progress_pct=100,
                message=f"Fetched {len(normalized)} EPSS scores"
            ))

            return normalized, None

        except requests.exceptions.RequestException as e:
            error = f"Failed to fetch EPSS: {str(e)}"
            self._notify_progress(SyncProgress(
                source=ThreatFeedSource.EPSS,
                status="error",
                message=error
            ))
            return [], error
        except Exception as e:
            error = f"Error processing EPSS: {str(e)}"
            self._notify_progress(SyncProgress(
                source=ThreatFeedSource.EPSS,
                status="error",
                message=error
            ))
            return [], error

    # =========================================================================
    # NVD
    # =========================================================================

    def fetch_nvd(
        self,
        days_back: int = 30,
        cve_ids: Optional[List[str]] = None
    ) -> Tuple[List[NormalizedVulnData], Optional[str]]:
        """
        Fetch NVD (National Vulnerability Database) data.
        API key optional but recommended for higher rate limits.

        Args:
            days_back: Number of days to look back for modified CVEs
            cve_ids: Optional list of specific CVE IDs to fetch

        Returns:
            Tuple of (list of normalized data, error message or None)
        """
        self._notify_progress(SyncProgress(
            source=ThreatFeedSource.NVD,
            status="fetching",
            message="Querying NVD API..."
        ))

        headers = {}
        if self.nvd_api_key:
            headers['apiKey'] = self.nvd_api_key

        normalized = []

        try:
            if cve_ids:
                # Fetch specific CVEs
                total = len(cve_ids)
                for i, cve_id in enumerate(cve_ids):
                    params = {'cveId': cve_id}

                    response = requests.get(
                        self.NVD_API_URL,
                        params=params,
                        headers=headers,
                        timeout=30
                    )

                    if response.status_code == 200:
                        data = response.json()
                        vulns = data.get('vulnerabilities', [])
                        for v in vulns:
                            norm = self._parse_nvd_cve(v)
                            if norm:
                                normalized.append(norm)

                    # Rate limiting: with key 50/30s, without 5/30s
                    sleep_time = 0.6 if self.nvd_api_key else 6
                    time.sleep(sleep_time)

                    if i % 10 == 0:
                        self._notify_progress(SyncProgress(
                            source=ThreatFeedSource.NVD,
                            status="processing",
                            progress_pct=(i / total) * 100,
                            message=f"Fetching {i}/{total} CVEs from NVD..."
                        ))
            else:
                # Fetch by date range
                end_date = datetime.now()
                start_date = end_date - timedelta(days=days_back)

                params = {
                    'lastModStartDate': start_date.strftime('%Y-%m-%dT00:00:00.000'),
                    'lastModEndDate': end_date.strftime('%Y-%m-%dT23:59:59.999'),
                    'resultsPerPage': 2000,
                    'startIndex': 0
                }

                total_results = None
                fetched = 0

                while True:
                    response = requests.get(
                        self.NVD_API_URL,
                        params=params,
                        headers=headers,
                        timeout=60
                    )

                    if response.status_code != 200:
                        error = f"NVD API error: HTTP {response.status_code}"
                        if response.status_code == 403:
                            error += " (rate limited - consider adding API key)"
                        return normalized, error

                    data = response.json()

                    if total_results is None:
                        total_results = data.get('totalResults', 0)

                    vulns = data.get('vulnerabilities', [])
                    for v in vulns:
                        norm = self._parse_nvd_cve(v)
                        if norm:
                            normalized.append(norm)
                        fetched += 1

                    self._notify_progress(SyncProgress(
                        source=ThreatFeedSource.NVD,
                        status="processing",
                        progress_pct=(fetched / max(total_results, 1)) * 100,
                        message=f"Fetched {fetched}/{total_results} CVEs from NVD..."
                    ))

                    # Check if more pages
                    if fetched >= total_results:
                        break

                    params['startIndex'] = fetched

                    # Rate limiting
                    sleep_time = 0.6 if self.nvd_api_key else 6
                    time.sleep(sleep_time)

            self._cache[ThreatFeedSource.NVD.value] = normalized

            self._notify_progress(SyncProgress(
                source=ThreatFeedSource.NVD,
                status="complete",
                progress_pct=100,
                message=f"Fetched {len(normalized)} CVEs from NVD"
            ))

            return normalized, None

        except requests.exceptions.RequestException as e:
            error = f"Failed to fetch NVD: {str(e)}"
            self._notify_progress(SyncProgress(
                source=ThreatFeedSource.NVD,
                status="error",
                message=error
            ))
            return normalized, error
        except Exception as e:
            error = f"Error processing NVD: {str(e)}"
            self._notify_progress(SyncProgress(
                source=ThreatFeedSource.NVD,
                status="error",
                message=error
            ))
            return normalized, error

    def _parse_nvd_cve(self, vuln_data: Dict[str, Any]) -> Optional[NormalizedVulnData]:
        """Parse a single NVD CVE entry into normalized format."""
        try:
            cve = vuln_data.get('cve', {})
            cve_id = cve.get('id', '')
            if not cve_id:
                return None

            # Get descriptions (prefer English)
            descriptions = cve.get('descriptions', [])
            description = ""
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            if not description and descriptions:
                description = descriptions[0].get('value', '')

            # Get CVSS scores (prefer v3.1, then v3.0, then v2)
            cvss_score = None
            cvss_vector = ""

            metrics = cve.get('metrics', {})

            # Try CVSS 3.1
            cvss31 = metrics.get('cvssMetricV31', [])
            if cvss31:
                cvss_data = cvss31[0].get('cvssData', {})
                cvss_score = cvss_data.get('baseScore')
                cvss_vector = cvss_data.get('vectorString', '')

            # Try CVSS 3.0
            if cvss_score is None:
                cvss30 = metrics.get('cvssMetricV30', [])
                if cvss30:
                    cvss_data = cvss30[0].get('cvssData', {})
                    cvss_score = cvss_data.get('baseScore')
                    cvss_vector = cvss_data.get('vectorString', '')

            # Try CVSS 2.0
            if cvss_score is None:
                cvss2 = metrics.get('cvssMetricV2', [])
                if cvss2:
                    cvss_data = cvss2[0].get('cvssData', {})
                    cvss_score = cvss_data.get('baseScore')
                    cvss_vector = cvss_data.get('vectorString', '')

            # Get references
            refs = cve.get('references', [])
            reference_urls = [r.get('url', '') for r in refs if r.get('url')]

            # Get affected products (simplified)
            vendor = ""
            product = ""
            affected_versions = ""

            configurations = cve.get('configurations', [])
            if configurations:
                for config in configurations:
                    nodes = config.get('nodes', [])
                    for node in nodes:
                        cpe_matches = node.get('cpeMatch', [])
                        if cpe_matches:
                            cpe = cpe_matches[0].get('criteria', '')
                            # Parse CPE: cpe:2.3:a:vendor:product:version:...
                            parts = cpe.split(':')
                            if len(parts) >= 5:
                                vendor = parts[3]
                                product = parts[4]
                                if len(parts) >= 6 and parts[5] != '*':
                                    affected_versions = parts[5]
                            break
                    if vendor:
                        break

            return NormalizedVulnData(
                source=ThreatFeedSource.NVD.value,
                identifier=cve_id,
                title=cve_id,  # NVD doesn't have titles
                description=description,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                vendor=vendor,
                product=product,
                affected_versions=affected_versions,
                references=reference_urls[:5],  # Limit references
                last_updated=cve.get('lastModified', datetime.now().isoformat()),
                raw_data=cve
            )

        except Exception as e:
            print(f"Error parsing NVD CVE: {e}")
            return None

    # =========================================================================
    # DISA IAVM
    # =========================================================================

    def fetch_disa_iavm(self) -> Tuple[List[NormalizedVulnData], Optional[str]]:
        """
        Fetch DISA IAVM (DoD Information Assurance Vulnerability Management) data.
        Requires configured URL and API key.

        Returns:
            Tuple of (list of normalized data, error message or None)
        """
        if not self.iavm_url:
            return [], "DISA IAVM URL not configured"

        self._notify_progress(SyncProgress(
            source=ThreatFeedSource.DISA_IAVM,
            status="fetching",
            message="Fetching DISA IAVM data..."
        ))

        headers = {}
        if self.iavm_api_key:
            headers['Authorization'] = f'Bearer {self.iavm_api_key}'
            headers['X-API-Key'] = self.iavm_api_key  # Some APIs use this

        try:
            response = requests.get(
                self.iavm_url,
                headers=headers,
                timeout=60
            )
            response.raise_for_status()

            # Try to parse as JSON first, then XML
            normalized = []

            try:
                data = response.json()
                # Handle common JSON structures
                iavms = data if isinstance(data, list) else data.get('iavms', data.get('data', []))

                for iavm in iavms:
                    norm = self._parse_iavm_entry(iavm)
                    if norm:
                        normalized.append(norm)

            except json.JSONDecodeError:
                # Try XML parsing
                try:
                    import xml.etree.ElementTree as ET
                    root = ET.fromstring(response.text)

                    # Find IAVM entries (adjust xpath based on actual structure)
                    for entry in root.findall('.//iavm') or root.findall('.//entry') or root.findall('.//*'):
                        norm = self._parse_iavm_xml(entry)
                        if norm:
                            normalized.append(norm)
                except Exception as xml_err:
                    return [], f"Could not parse IAVM response: {xml_err}"

            self._cache[ThreatFeedSource.DISA_IAVM.value] = normalized

            self._notify_progress(SyncProgress(
                source=ThreatFeedSource.DISA_IAVM,
                status="complete",
                progress_pct=100,
                message=f"Fetched {len(normalized)} IAVM entries"
            ))

            return normalized, None

        except requests.exceptions.RequestException as e:
            error = f"Failed to fetch DISA IAVM: {str(e)}"
            self._notify_progress(SyncProgress(
                source=ThreatFeedSource.DISA_IAVM,
                status="error",
                message=error
            ))
            return [], error
        except Exception as e:
            error = f"Error processing DISA IAVM: {str(e)}"
            self._notify_progress(SyncProgress(
                source=ThreatFeedSource.DISA_IAVM,
                status="error",
                message=error
            ))
            return [], error

    def _parse_iavm_entry(self, entry: Dict[str, Any]) -> Optional[NormalizedVulnData]:
        """Parse a single IAVM JSON entry."""
        try:
            # Common field names in IAVM feeds
            iavm_id = entry.get('iavmId', entry.get('iavm_id', entry.get('id', '')))
            if not iavm_id:
                return None

            return NormalizedVulnData(
                source=ThreatFeedSource.DISA_IAVM.value,
                identifier=iavm_id,
                title=entry.get('title', entry.get('name', iavm_id)),
                description=entry.get('description', entry.get('summary', '')),
                cvss_score=entry.get('cvss', entry.get('cvssScore')),
                remediation=entry.get('mitigation', entry.get('remediation', entry.get('fix', ''))),
                kev_due_date=entry.get('dueDate', entry.get('due_date', '')),
                last_updated=entry.get('modified', entry.get('lastModified', datetime.now().isoformat())),
                raw_data=entry
            )
        except Exception:
            return None

    def _parse_iavm_xml(self, element) -> Optional[NormalizedVulnData]:
        """Parse a single IAVM XML entry."""
        try:
            def get_text(el, tag):
                found = el.find(tag)
                return found.text if found is not None and found.text else ""

            iavm_id = get_text(element, 'iavmId') or get_text(element, 'id') or element.get('id', '')
            if not iavm_id:
                return None

            return NormalizedVulnData(
                source=ThreatFeedSource.DISA_IAVM.value,
                identifier=iavm_id,
                title=get_text(element, 'title') or iavm_id,
                description=get_text(element, 'description') or get_text(element, 'summary'),
                remediation=get_text(element, 'mitigation') or get_text(element, 'fix'),
                kev_due_date=get_text(element, 'dueDate'),
                last_updated=datetime.now().isoformat()
            )
        except Exception:
            return None

    # =========================================================================
    # Combined Operations
    # =========================================================================

    def fetch_all(
        self,
        include_kev: bool = True,
        include_epss: bool = True,
        include_nvd: bool = True,
        include_iavm: bool = False,
        nvd_days_back: int = 30
    ) -> Dict[str, SyncResult]:
        """
        Fetch from all configured sources.

        Args:
            include_kev: Include CISA KEV
            include_epss: Include EPSS scores
            include_nvd: Include NVD data
            include_iavm: Include DISA IAVM (requires configuration)
            nvd_days_back: Days to look back for NVD

        Returns:
            Dictionary of source -> SyncResult
        """
        results = {}

        if include_kev:
            start = time.time()
            data, error = self.fetch_cisa_kev()
            results[ThreatFeedSource.CISA_KEV.value] = SyncResult(
                success=error is None,
                source=ThreatFeedSource.CISA_KEV,
                records_fetched=len(data),
                records_processed=len(data),
                error=error or "",
                duration_seconds=time.time() - start
            )

        if include_epss:
            start = time.time()
            data, error = self.fetch_epss()
            results[ThreatFeedSource.EPSS.value] = SyncResult(
                success=error is None,
                source=ThreatFeedSource.EPSS,
                records_fetched=len(data),
                records_processed=len(data),
                error=error or "",
                duration_seconds=time.time() - start
            )

        if include_nvd:
            start = time.time()
            data, error = self.fetch_nvd(days_back=nvd_days_back)
            results[ThreatFeedSource.NVD.value] = SyncResult(
                success=error is None,
                source=ThreatFeedSource.NVD,
                records_fetched=len(data),
                records_processed=len(data),
                error=error or "",
                duration_seconds=time.time() - start
            )

        if include_iavm and self.iavm_url:
            start = time.time()
            data, error = self.fetch_disa_iavm()
            results[ThreatFeedSource.DISA_IAVM.value] = SyncResult(
                success=error is None,
                source=ThreatFeedSource.DISA_IAVM,
                records_fetched=len(data),
                records_processed=len(data),
                error=error or "",
                duration_seconds=time.time() - start
            )

        return results

    def fetch_all_async(
        self,
        callback: Callable[[Dict[str, SyncResult]], None],
        **kwargs
    ):
        """
        Fetch all sources asynchronously.

        Args:
            callback: Called with results when complete
            **kwargs: Arguments passed to fetch_all
        """
        def _fetch():
            results = self.fetch_all(**kwargs)
            callback(results)

        thread = threading.Thread(target=_fetch, daemon=True)
        thread.start()

    def get_cached_data(self, source: ThreatFeedSource) -> List[NormalizedVulnData]:
        """Get cached data for a source."""
        return self._cache.get(source.value, [])

    def get_all_cached_data(self) -> List[NormalizedVulnData]:
        """Get all cached data from all sources."""
        all_data = []
        for source_data in self._cache.values():
            all_data.extend(source_data)
        return all_data

    def merge_data_by_cve(self) -> Dict[str, NormalizedVulnData]:
        """
        Merge data from all sources by CVE ID.
        Combines EPSS scores with NVD and KEV data.

        Returns:
            Dictionary of CVE ID -> merged NormalizedVulnData
        """
        merged = {}

        # Start with NVD as base (most comprehensive)
        for data in self._cache.get(ThreatFeedSource.NVD.value, []):
            if data.identifier:
                merged[data.identifier] = data

        # Add KEV data
        for data in self._cache.get(ThreatFeedSource.CISA_KEV.value, []):
            cve_id = data.identifier
            if cve_id in merged:
                # Merge KEV fields into existing entry
                merged[cve_id].actively_exploited = True
                merged[cve_id].kev_added_date = data.kev_added_date
                merged[cve_id].kev_due_date = data.kev_due_date
                if not merged[cve_id].remediation:
                    merged[cve_id].remediation = data.remediation
            else:
                merged[cve_id] = data

        # Add EPSS scores
        for data in self._cache.get(ThreatFeedSource.EPSS.value, []):
            cve_id = data.identifier
            if cve_id in merged:
                merged[cve_id].epss_score = data.epss_score
                merged[cve_id].epss_percentile = data.epss_percentile
            else:
                merged[cve_id] = data

        return merged

    def enrich_findings(
        self,
        findings_df,
        cve_column: str = 'cves'
    ):
        """
        Enrich a findings DataFrame with threat intel data.

        Args:
            findings_df: DataFrame with vulnerability findings
            cve_column: Column containing CVE IDs

        Returns:
            DataFrame with added threat intel columns
        """
        import pandas as pd

        merged_intel = self.merge_data_by_cve()

        # Add new columns
        findings_df = findings_df.copy()
        findings_df['epss_score'] = None
        findings_df['epss_percentile'] = None
        findings_df['in_kev'] = False
        findings_df['kev_due_date'] = None

        for idx, row in findings_df.iterrows():
            cves = row.get(cve_column, '')
            if not cves or pd.isna(cves):
                continue

            # Handle comma-separated CVEs
            cve_list = [c.strip() for c in str(cves).split(',') if c.strip()]

            max_epss = 0
            max_percentile = 0
            in_kev = False
            kev_due = None

            for cve in cve_list:
                intel = merged_intel.get(cve)
                if intel:
                    if intel.epss_score and intel.epss_score > max_epss:
                        max_epss = intel.epss_score
                        max_percentile = intel.epss_percentile or 0
                    if intel.actively_exploited:
                        in_kev = True
                        if intel.kev_due_date:
                            kev_due = intel.kev_due_date

            if max_epss > 0:
                findings_df.at[idx, 'epss_score'] = max_epss
                findings_df.at[idx, 'epss_percentile'] = max_percentile
            findings_df.at[idx, 'in_kev'] = in_kev
            if kev_due:
                findings_df.at[idx, 'kev_due_date'] = kev_due

        return findings_df
