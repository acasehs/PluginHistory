"""
Finding data models for vulnerability tracking.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any


@dataclass
class Finding:
    """Represents a single vulnerability finding from a Nessus scan."""

    plugin_id: str
    hostname: str
    ip_address: str
    scan_date: datetime
    scan_file: str
    name: str
    family: str = ''
    severity: str = '0'
    severity_text: str = 'Info'
    severity_value: int = 0
    port: str = 'N/A'
    protocol: str = 'N/A'

    # CVSS scores
    cvss3_base_score: Optional[float] = None
    cvss3_temporal_score: Optional[float] = None
    cvss2_base_score: Optional[float] = None
    cvss_v3_vector: str = ''

    # Vulnerability details
    description: str = ''
    synopsis: str = ''
    solution: str = ''
    see_also: str = ''
    output: str = ''

    # References
    cves: str = ''
    iavx: str = ''
    bid: str = ''
    cross_references: str = ''

    # Risk information
    risk_factor: str = ''
    stig_severity: str = ''
    vpr_score: str = ''
    exploit_available: str = 'No'
    exploit_ease: str = ''
    exploit_frameworks: str = ''

    # Dates
    first_discovered: str = ''
    last_observed: str = ''
    vuln_publication_date: str = ''
    patch_publication_date: str = ''
    plugin_publication_date: str = ''
    plugin_modification_date: str = ''

    # Additional
    cpe: str = ''
    age_bucket: str = ''

    @property
    def finding_key(self) -> str:
        """Generate unique finding key."""
        return f"{self.hostname}|{self.plugin_id}"

    @property
    def gmp_uid(self) -> str:
        """Generate GMP-style unique identifier."""
        return f"{self.plugin_id}.{self.hostname}"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'plugin_id': self.plugin_id,
            'hostname': self.hostname,
            'ip_address': self.ip_address,
            'scan_date': self.scan_date.isoformat() if self.scan_date else None,
            'scan_file': self.scan_file,
            'name': self.name,
            'family': self.family,
            'severity_text': self.severity_text,
            'severity_value': self.severity_value,
            'port': self.port,
            'protocol': self.protocol,
            'cvss3_base_score': self.cvss3_base_score,
            'cvss2_base_score': self.cvss2_base_score,
            'cves': self.cves,
            'iavx': self.iavx,
            'description': self.description,
            'solution': self.solution,
            'exploit_available': self.exploit_available
        }


@dataclass
class FindingLifecycle:
    """Tracks the lifecycle of a finding across multiple scans."""

    hostname: str
    ip_address: str
    plugin_id: str
    plugin_name: str
    severity_text: str
    severity_value: int
    first_seen: datetime
    last_seen: datetime
    days_open: int
    total_observations: int
    reappearances: int
    status: str  # 'Active' or 'Resolved'

    # CVSS and references
    cvss3_base_score: Optional[float] = None
    cves: str = ''
    iavx: str = ''

    # Gap details (JSON string)
    gap_details: str = ''

    # OPDIR compliance (optional)
    opdir_number: str = ''
    opdir_subject: str = ''
    opdir_release_date: Optional[datetime] = None
    opdir_final_due_date: Optional[datetime] = None
    opdir_days_to_remediate: Optional[int] = None
    opdir_status: str = ''
    opdir_days_until_due: Optional[int] = None

    # IAVx mapping
    iavx_mapped: str = ''

    @property
    def finding_key(self) -> str:
        """Generate unique finding key."""
        return f"{self.hostname}|{self.plugin_id}"

    @property
    def is_active(self) -> bool:
        """Check if finding is currently active."""
        return self.status == 'Active'

    @property
    def has_reappeared(self) -> bool:
        """Check if finding has ever reappeared after being resolved."""
        return self.reappearances > 0

    @property
    def is_overdue(self) -> bool:
        """Check if finding is overdue based on OPDIR."""
        return self.opdir_status == 'Overdue'

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'hostname': self.hostname,
            'ip_address': self.ip_address,
            'plugin_id': self.plugin_id,
            'plugin_name': self.plugin_name,
            'severity_text': self.severity_text,
            'severity_value': self.severity_value,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'days_open': self.days_open,
            'total_observations': self.total_observations,
            'reappearances': self.reappearances,
            'status': self.status,
            'cvss3_base_score': self.cvss3_base_score,
            'cves': self.cves,
            'iavx': self.iavx,
            'opdir_number': self.opdir_number,
            'opdir_status': self.opdir_status
        }
