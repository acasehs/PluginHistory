"""
Host data models for tracking host presence across scans.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any


@dataclass
class Host:
    """Represents a host discovered in Nessus scans."""

    hostname: str
    ip_address: str

    # Scan information
    report_name: str = ''
    original_filename: str = ''
    safe_hostname: str = ''
    total_reportitems: int = 0

    # Credential scan information
    proper_scan: str = 'No'
    cred_checks_value: str = 'N/A'
    cred_scan_value: str = 'N/A'
    auth_method: str = 'None'

    # Network information
    mac_address: str = ''
    dns_name: str = ''
    netbios_name: str = ''
    operating_system: str = ''

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'hostname': self.hostname,
            'ip_address': self.ip_address,
            'report_name': self.report_name,
            'safe_hostname': self.safe_hostname,
            'total_reportitems': self.total_reportitems,
            'proper_scan': self.proper_scan,
            'auth_method': self.auth_method
        }


@dataclass
class HostPresence:
    """Tracks a host's presence across multiple scans."""

    hostname: str
    ip_address: str
    first_seen: datetime
    last_seen: datetime
    total_scans_available: int
    scans_present: int
    scans_missing: int
    presence_percentage: float
    status: str  # 'Active' or 'Missing'
    missing_scan_dates: str = ''  # Comma-separated list

    @property
    def is_active(self) -> bool:
        """Check if host is currently active."""
        return self.status == 'Active'

    @property
    def is_reliable(self) -> bool:
        """Check if host has reliable scan coverage (>75%)."""
        return self.presence_percentage >= 75.0

    @property
    def days_since_last_seen(self) -> int:
        """Calculate days since host was last seen."""
        if self.last_seen:
            return (datetime.now() - self.last_seen).days
        return 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'hostname': self.hostname,
            'ip_address': self.ip_address,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'total_scans_available': self.total_scans_available,
            'scans_present': self.scans_present,
            'scans_missing': self.scans_missing,
            'presence_percentage': self.presence_percentage,
            'status': self.status,
            'missing_scan_dates': self.missing_scan_dates
        }


@dataclass
class ScanChange:
    """Tracks changes between consecutive scans."""

    scan_date: datetime
    previous_scan: datetime
    hosts_added: int
    hosts_removed: int
    hosts_unchanged: int
    total_hosts_current: int
    total_hosts_previous: int
    net_change: int
    added_host_list: str = ''  # Comma-separated
    removed_host_list: str = ''  # Comma-separated

    @property
    def growth_rate(self) -> float:
        """Calculate percentage growth from previous scan."""
        if self.total_hosts_previous > 0:
            return (self.net_change / self.total_hosts_previous) * 100
        return 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'scan_date': self.scan_date.isoformat() if self.scan_date else None,
            'previous_scan': self.previous_scan.isoformat() if self.previous_scan else None,
            'hosts_added': self.hosts_added,
            'hosts_removed': self.hosts_removed,
            'hosts_unchanged': self.hosts_unchanged,
            'total_hosts_current': self.total_hosts_current,
            'total_hosts_previous': self.total_hosts_previous,
            'net_change': self.net_change
        }
