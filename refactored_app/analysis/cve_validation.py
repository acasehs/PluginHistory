"""
CVE Database Validation Module

Validates package version requirements against CVE databases (NVD, etc.)
to verify that recommended versions actually resolve the identified vulnerabilities.
"""

import requests
import json
import re
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import time
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class CVEInfo:
    """Information about a CVE."""
    cve_id: str
    description: str
    severity: str
    cvss_score: float
    affected_products: List[Dict[str, Any]]
    fixed_versions: List[str]
    published_date: Optional[datetime]
    last_modified: Optional[datetime]
    references: List[str] = field(default_factory=list)


@dataclass
class ValidationResult:
    """Result of validating a package version against CVE database."""
    package_name: str
    target_version: str
    is_valid: bool
    cves_checked: List[str]
    cves_resolved: List[str]
    cves_unresolved: List[str]
    warnings: List[str]
    details: Dict[str, Any]


class CVEValidator:
    """
    Validates package versions against CVE databases.

    Supports:
    - NVD (National Vulnerability Database) API
    - Local CVE cache for offline validation
    - Custom CVE databases
    """

    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CACHE_EXPIRY_HOURS = 24

    def __init__(self, cache_dir: Optional[str] = None, nvd_api_key: Optional[str] = None):
        """
        Initialize CVE validator.

        Args:
            cache_dir: Directory for caching CVE data
            nvd_api_key: Optional NVD API key for higher rate limits
        """
        self.cache_dir = Path(cache_dir) if cache_dir else Path.home() / ".cve_cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.nvd_api_key = nvd_api_key
        self.cache: Dict[str, CVEInfo] = {}
        self._load_cache()

    def _load_cache(self):
        """Load cached CVE data from disk."""
        cache_file = self.cache_dir / "cve_cache.json"
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    data = json.load(f)
                    cache_time = datetime.fromisoformat(data.get('timestamp', '2000-01-01'))
                    if datetime.now() - cache_time < timedelta(hours=self.CACHE_EXPIRY_HOURS):
                        for cve_id, cve_data in data.get('cves', {}).items():
                            self.cache[cve_id] = self._dict_to_cve_info(cve_data)
                        logger.info(f"Loaded {len(self.cache)} CVEs from cache")
            except Exception as e:
                logger.warning(f"Failed to load CVE cache: {e}")

    def _save_cache(self):
        """Save CVE cache to disk."""
        cache_file = self.cache_dir / "cve_cache.json"
        try:
            data = {
                'timestamp': datetime.now().isoformat(),
                'cves': {cve_id: self._cve_info_to_dict(cve) for cve_id, cve in self.cache.items()}
            }
            with open(cache_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save CVE cache: {e}")

    def _cve_info_to_dict(self, cve: CVEInfo) -> Dict:
        """Convert CVEInfo to dictionary for JSON serialization."""
        return {
            'cve_id': cve.cve_id,
            'description': cve.description,
            'severity': cve.severity,
            'cvss_score': cve.cvss_score,
            'affected_products': cve.affected_products,
            'fixed_versions': cve.fixed_versions,
            'published_date': cve.published_date.isoformat() if cve.published_date else None,
            'last_modified': cve.last_modified.isoformat() if cve.last_modified else None,
            'references': cve.references
        }

    def _dict_to_cve_info(self, data: Dict) -> CVEInfo:
        """Convert dictionary to CVEInfo."""
        return CVEInfo(
            cve_id=data['cve_id'],
            description=data['description'],
            severity=data['severity'],
            cvss_score=data['cvss_score'],
            affected_products=data['affected_products'],
            fixed_versions=data['fixed_versions'],
            published_date=datetime.fromisoformat(data['published_date']) if data.get('published_date') else None,
            last_modified=datetime.fromisoformat(data['last_modified']) if data.get('last_modified') else None,
            references=data.get('references', [])
        )

    def fetch_cve_info(self, cve_id: str) -> Optional[CVEInfo]:
        """
        Fetch CVE information from NVD API.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-44228")

        Returns:
            CVEInfo object or None if not found
        """
        # Check cache first
        if cve_id in self.cache:
            return self.cache[cve_id]

        # Normalize CVE ID
        cve_id = cve_id.upper().strip()
        if not re.match(r'^CVE-\d{4}-\d+$', cve_id):
            logger.warning(f"Invalid CVE ID format: {cve_id}")
            return None

        try:
            headers = {'Accept': 'application/json'}
            if self.nvd_api_key:
                headers['apiKey'] = self.nvd_api_key

            params = {'cveId': cve_id}
            response = requests.get(self.NVD_API_BASE, params=params, headers=headers, timeout=30)

            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])

                if vulnerabilities:
                    cve_data = vulnerabilities[0].get('cve', {})
                    cve_info = self._parse_nvd_cve(cve_data)
                    if cve_info:
                        self.cache[cve_id] = cve_info
                        self._save_cache()
                        return cve_info

            elif response.status_code == 403:
                logger.warning("NVD API rate limit reached. Consider using an API key.")
            else:
                logger.warning(f"NVD API returned status {response.status_code} for {cve_id}")

        except requests.exceptions.Timeout:
            logger.warning(f"Timeout fetching CVE {cve_id}")
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error fetching CVE {cve_id}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error fetching CVE {cve_id}: {e}")

        return None

    def _parse_nvd_cve(self, cve_data: Dict) -> Optional[CVEInfo]:
        """Parse NVD CVE response into CVEInfo."""
        try:
            cve_id = cve_data.get('id', '')

            # Get description
            descriptions = cve_data.get('descriptions', [])
            description = next(
                (d.get('value', '') for d in descriptions if d.get('lang') == 'en'),
                descriptions[0].get('value', '') if descriptions else ''
            )

            # Get CVSS score and severity
            metrics = cve_data.get('metrics', {})
            cvss_score = 0.0
            severity = 'Unknown'

            # Try CVSS 3.1, then 3.0, then 2.0
            for metric_type in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                if metric_type in metrics and metrics[metric_type]:
                    cvss_data = metrics[metric_type][0].get('cvssData', {})
                    cvss_score = cvss_data.get('baseScore', 0.0)
                    severity = cvss_data.get('baseSeverity', 'Unknown')
                    break

            # Get affected products (CPE)
            affected_products = []
            configurations = cve_data.get('configurations', [])
            for config in configurations:
                for node in config.get('nodes', []):
                    for cpe_match in node.get('cpeMatch', []):
                        if cpe_match.get('vulnerable', False):
                            affected_products.append({
                                'cpe': cpe_match.get('criteria', ''),
                                'version_start': cpe_match.get('versionStartIncluding'),
                                'version_end': cpe_match.get('versionEndExcluding'),
                                'version_end_including': cpe_match.get('versionEndIncluding')
                            })

            # Get references
            references = [
                ref.get('url', '') for ref in cve_data.get('references', [])
            ]

            # Get dates
            published = cve_data.get('published')
            last_modified = cve_data.get('lastModified')

            return CVEInfo(
                cve_id=cve_id,
                description=description[:500] if description else '',
                severity=severity,
                cvss_score=cvss_score,
                affected_products=affected_products,
                fixed_versions=[],  # NVD doesn't always provide this directly
                published_date=datetime.fromisoformat(published.replace('Z', '+00:00')) if published else None,
                last_modified=datetime.fromisoformat(last_modified.replace('Z', '+00:00')) if last_modified else None,
                references=references[:10]  # Limit references
            )

        except Exception as e:
            logger.error(f"Error parsing CVE data: {e}")
            return None

    def validate_version_resolves_cve(
        self,
        package_name: str,
        target_version: str,
        cve_id: str
    ) -> Tuple[bool, str]:
        """
        Validate if a target version resolves a specific CVE.

        Args:
            package_name: Name of the package
            target_version: Version to validate
            cve_id: CVE to check

        Returns:
            Tuple of (is_resolved, message)
        """
        cve_info = self.fetch_cve_info(cve_id)

        if not cve_info:
            return False, f"Could not fetch CVE information for {cve_id}"

        # Check affected products
        for product in cve_info.affected_products:
            cpe = product.get('cpe', '').lower()

            # Simple name matching (CPE format: cpe:2.3:a:vendor:product:version:...)
            if package_name.lower() in cpe:
                version_end = product.get('version_end') or product.get('version_end_including')

                if version_end:
                    # Compare versions
                    from .package_version_impact import compare_versions
                    if compare_versions(target_version, version_end) >= 0:
                        return True, f"Target version {target_version} >= fixed version {version_end}"
                    else:
                        return False, f"Target version {target_version} < required version {version_end}"

        return True, f"Package {package_name} not found in {cve_id} affected products (may be resolved)"

    def validate_package_versions(
        self,
        package_name: str,
        target_version: str,
        cve_list: List[str],
        rate_limit_delay: float = 0.6
    ) -> ValidationResult:
        """
        Validate a package version against multiple CVEs.

        Args:
            package_name: Name of the package
            target_version: Proposed target version
            cve_list: List of CVE IDs to validate against
            rate_limit_delay: Delay between API calls (NVD has rate limits)

        Returns:
            ValidationResult with validation details
        """
        cves_resolved = []
        cves_unresolved = []
        warnings = []
        details = {}

        for cve_id in cve_list:
            is_resolved, message = self.validate_version_resolves_cve(
                package_name, target_version, cve_id
            )

            if is_resolved:
                cves_resolved.append(cve_id)
            else:
                cves_unresolved.append(cve_id)
                warnings.append(f"{cve_id}: {message}")

            details[cve_id] = {
                'resolved': is_resolved,
                'message': message
            }

            # Rate limiting for API calls
            time.sleep(rate_limit_delay)

        is_valid = len(cves_unresolved) == 0

        return ValidationResult(
            package_name=package_name,
            target_version=target_version,
            is_valid=is_valid,
            cves_checked=cve_list,
            cves_resolved=cves_resolved,
            cves_unresolved=cves_unresolved,
            warnings=warnings,
            details=details
        )

    def batch_validate(
        self,
        packages: List[Dict[str, Any]],
        rate_limit_delay: float = 0.6
    ) -> List[ValidationResult]:
        """
        Validate multiple packages in batch.

        Args:
            packages: List of dicts with keys: package_name, target_version, cves
            rate_limit_delay: Delay between API calls

        Returns:
            List of ValidationResult objects
        """
        results = []

        for pkg in packages:
            result = self.validate_package_versions(
                package_name=pkg.get('package_name', ''),
                target_version=pkg.get('target_version', ''),
                cve_list=pkg.get('cves', []),
                rate_limit_delay=rate_limit_delay
            )
            results.append(result)

        return results


def search_cve_by_keyword(keyword: str, max_results: int = 20) -> List[CVEInfo]:
    """
    Search for CVEs by keyword using NVD API.

    Args:
        keyword: Search keyword (e.g., package name)
        max_results: Maximum results to return

    Returns:
        List of CVEInfo objects
    """
    validator = CVEValidator()

    try:
        params = {
            'keywordSearch': keyword,
            'resultsPerPage': min(max_results, 100)
        }

        headers = {'Accept': 'application/json'}
        response = requests.get(
            CVEValidator.NVD_API_BASE,
            params=params,
            headers=headers,
            timeout=30
        )

        if response.status_code == 200:
            data = response.json()
            results = []

            for vuln in data.get('vulnerabilities', [])[:max_results]:
                cve_data = vuln.get('cve', {})
                cve_info = validator._parse_nvd_cve(cve_data)
                if cve_info:
                    results.append(cve_info)

            return results

    except Exception as e:
        logger.error(f"Error searching CVEs: {e}")

    return []


def get_cve_details(cve_ids: List[str]) -> Dict[str, Optional[CVEInfo]]:
    """
    Get detailed information for multiple CVEs.

    Args:
        cve_ids: List of CVE identifiers

    Returns:
        Dictionary mapping CVE ID to CVEInfo (or None if not found)
    """
    validator = CVEValidator()
    results = {}

    for cve_id in cve_ids:
        results[cve_id] = validator.fetch_cve_info(cve_id)
        time.sleep(0.6)  # Rate limiting

    return results


def enrich_remediation_plan_with_cve_data(plan) -> None:
    """
    Enrich a RemediationPlan with CVE details from NVD.

    Modifies the plan in place, adding CVE severity and description data.

    Args:
        plan: RemediationPlan object from package_version_impact
    """
    if not plan.packages:
        return

    validator = CVEValidator()

    # Collect all unique CVEs
    all_cves = set()
    for pkg in plan.packages:
        all_cves.update(pkg.cves)

    # Fetch CVE details
    logger.info(f"Fetching details for {len(all_cves)} unique CVEs...")

    for cve_id in all_cves:
        validator.fetch_cve_info(cve_id)
        time.sleep(0.6)

    logger.info("CVE enrichment complete")


def create_cve_validation_report(
    validation_results: List[ValidationResult]
) -> Dict[str, Any]:
    """
    Create a summary report from validation results.

    Args:
        validation_results: List of ValidationResult objects

    Returns:
        Dictionary with report data
    """
    total_packages = len(validation_results)
    valid_packages = sum(1 for r in validation_results if r.is_valid)
    total_cves_checked = sum(len(r.cves_checked) for r in validation_results)
    total_resolved = sum(len(r.cves_resolved) for r in validation_results)
    total_unresolved = sum(len(r.cves_unresolved) for r in validation_results)

    failed_validations = [
        {
            'package': r.package_name,
            'target_version': r.target_version,
            'unresolved_cves': r.cves_unresolved,
            'warnings': r.warnings
        }
        for r in validation_results if not r.is_valid
    ]

    return {
        'summary': {
            'total_packages': total_packages,
            'valid_packages': valid_packages,
            'invalid_packages': total_packages - valid_packages,
            'validation_rate': round(valid_packages / total_packages * 100, 1) if total_packages > 0 else 0,
            'total_cves_checked': total_cves_checked,
            'cves_resolved': total_resolved,
            'cves_unresolved': total_unresolved
        },
        'failed_validations': failed_validations,
        'recommendations': _generate_validation_recommendations(validation_results)
    }


def _generate_validation_recommendations(results: List[ValidationResult]) -> List[str]:
    """Generate recommendations based on validation results."""
    recommendations = []

    failed = [r for r in results if not r.is_valid]

    if not failed:
        recommendations.append("All package versions validated successfully against CVE database.")
    else:
        recommendations.append(
            f"WARNING: {len(failed)} package(s) may not fully resolve associated CVEs. "
            "Review target versions."
        )

        # Specific recommendations
        for result in failed[:5]:  # Top 5 failures
            recommendations.append(
                f"- {result.package_name}: Version {result.target_version} may not resolve "
                f"{len(result.cves_unresolved)} CVE(s). Consider higher version."
            )

    return recommendations
