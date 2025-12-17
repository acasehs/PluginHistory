"""
Configuration constants for the Nessus Historical Analysis System.
"""

from dataclasses import dataclass
from typing import Dict, List, Tuple


# Application version
VERSION = "2.0"

# Severity mappings
SEVERITY_MAPPING = {
    0: 'Info',
    1: 'Low',
    2: 'Medium',
    3: 'High',
    4: 'Critical'
}
SEVERITY_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Info']

SEVERITY_COLORS = {
    'Critical': '#dc3545',
    'High': '#fd7e14',
    'Medium': '#B8860B',  # Dark goldenrod (changed from #ffc107 yellow)
    'Low': '#007bff',
    'Info': '#6c757d'
}

SEVERITY_WEIGHTS = {
    'Critical': 4,
    'High': 3,
    'Medium': 2,
    'Low': 1,
    'Info': 0
}

# CVSS score thresholds for severity mapping
CVSS_THRESHOLDS = {
    'Critical': (9.0, 10.0),
    'High': (7.0, 8.9),
    'Medium': (4.0, 6.9),
    'Low': (0.1, 3.9),
    'Info': (0.0, 0.0)
}

# Finding lifecycle settings
REAPPEARANCE_GAP_DAYS = 45  # Days gap to consider finding as reappeared

# Hostname structure configuration
@dataclass
class HostnameFormat:
    """Configuration for hostname structure parsing."""
    length: int
    location_start: int
    location_end: int
    tier_start: int
    tier_end: int
    cluster_pos: int
    environment_pos: int
    type_pos: int


# 9-character hostname format: LLLLTTCEP
# L=Location(4), T=Tier(2), C=Cluster(1), E=Environment(1), P=Physical/Virtual(1)
HOSTNAME_FORMAT_9 = HostnameFormat(
    length=9,
    location_start=0,
    location_end=4,
    tier_start=4,
    tier_end=6,
    cluster_pos=6,
    environment_pos=7,
    type_pos=8
)

# Host type indicators
HOST_TYPE_PHYSICAL = 'p'
HOST_TYPE_VIRTUAL = 'v'
HOST_TYPE_ILOM = 'ilom'

# Environment type configuration
# Labels for environment types
ENV_TYPE_LABELS = {
    'production': 'Production',
    'pre_production': 'PSS',  # Pre-Production Support Systems
    'shared': 'Shared',
    'unknown': 'Unknown'
}

# Explicit hostname-to-environment mappings (checked FIRST before auto-detection)
# Add hostnames or patterns that should be explicitly mapped to an environment
# Format: 'hostname_pattern': 'environment_type'
# environment_type can be: 'production', 'pre_production', 'shared'
EXPLICIT_ENV_MAPPINGS = {
    # Example network devices - add your shared infrastructure here
    # 'core-switch-01': 'shared',
    # 'fw-main-01': 'shared',
    # 'lb-prod-01': 'production',
}

# Hostname patterns for shared resources (regex patterns)
# These are checked if hostname doesn't match explicit mappings or standard format
SHARED_RESOURCE_PATTERNS = [
    r'^fw-',           # Firewalls
    r'^lb-',           # Load balancers
    r'^switch-',       # Switches
    r'^router-',       # Routers
    r'^core-',         # Core infrastructure
    r'^san-',          # Storage area network
    r'^nas-',          # Network attached storage
    r'^dns-',          # DNS servers
    r'^ntp-',          # NTP servers
    r'^proxy-',        # Proxy servers
    r'^vpn-',          # VPN devices
    r'^mgmt-',         # Management devices
]

# Whether to auto-classify unmatched hostnames as shared (False = Unknown)
AUTO_CLASSIFY_UNMATCHED_AS_SHARED = False

# OPDIR compliance status colors
OPDIR_STATUS_COLORS = {
    'On Track': '#28a745',
    'Due Soon': '#ffc107',
    'Overdue': '#dc3545',
    'Unknown': '#6c757d'
}

# Age buckets for finding age categorization
AGE_BUCKETS = [
    (0, 30, '0-30'),
    (31, 60, '31-60'),
    (61, 90, '61-90'),
    (91, 120, '91-120'),
    (121, float('inf'), '121+')
]

# SLA Compliance Targets (in days) - configurable per severity
# These define the maximum allowed days to remediate findings
SLA_TARGETS_DAYS = {
    'Critical': 15,    # Critical findings must be remediated within 15 days
    'High': 30,        # High findings within 30 days
    'Medium': 60,      # Medium findings within 60 days
    'Low': 90,         # Low findings within 90 days
    'Info': None       # Informational findings have no SLA
}

# SLA Warning threshold (percentage of SLA remaining to trigger "Approaching" status)
SLA_WARNING_THRESHOLD = 0.25  # 25% - e.g., Critical at 11+ days is "Approaching"

# SLA Status definitions
SLA_STATUS_OVERDUE = 'Overdue'
SLA_STATUS_APPROACHING = 'Approaching'
SLA_STATUS_ON_TRACK = 'On Track'
SLA_STATUS_NO_SLA = 'No SLA'

SLA_STATUS_COLORS = {
    'Overdue': '#dc3545',       # Red
    'Approaching': '#ffc107',    # Yellow/Orange
    'On Track': '#28a745',       # Green
    'No SLA': '#6c757d'          # Gray
}

# GUI settings
GUI_WINDOW_SIZE = "1400x900"
GUI_DARK_THEME = {
    'bg': '#2b2b2b',
    'fg': 'white',
    'entry_bg': '#404040',
    'button_bg': '#404040',
    'button_active': '#505050',
    'text_bg': '#1e1e1e'
}

# Export settings
EXCEL_MAX_COLUMN_WIDTH = 50
SQLITE_INDEXES = {
    'historical_findings': ['hostname', 'plugin_id', 'scan_date', 'ip_address', 'port', 'protocol'],
    'finding_lifecycle': ['hostname', 'plugin_id', 'status', 'opdir_number', 'opdir_status'],
    'host_presence': ['hostname', 'status'],
    'scan_changes': ['scan_date'],
    'opdir_mapping': ['opdir_number', 'opdir_number_normalized', 'opdir_year'],
    'iavm_notices': ['iavm_number', 'iavm_number_normalized', 'iavm_year', 'iavm_type', 'status']
}

# Date formats
DATE_FORMAT_DISPLAY = '%Y-%m-%d'
DATE_FORMAT_FULL = '%Y-%m-%d %H:%M:%S'
DATE_FORMAT_ISO = '%Y-%m-%dT%H:%M:%S'

# Scan date extraction patterns
DATE_PATTERNS = [
    r'(\d{4})[-_](\d{2})[-_](\d{2})',  # YYYY-MM-DD or YYYY_MM_DD
    r'(\d{2})[-_](\d{2})[-_](\d{4})',  # MM-DD-YYYY or MM_DD_YYYY
    r'(\d{8})',  # YYYYMMDD
    r'(\d{6})',  # YYMMDD or MMDDYY
]
