"""
Hostname structure parsing for environment segregation.

Hostname formats:
- 9 characters: LLLLTTCEP
  - L (4): Physical location code
  - T (2): Tier code (numeric)
  - C (1): Cluster identifier
  - E (1): Environment sequence - Letter (A-Z) = Production, Number (0-9) = Pre-Production/PSS
  - P (1): Physical (p) or Virtual (v)

- 13 characters (with -ilom suffix): hostname-ilom
  - Indicates ILOM/management port (environment type still detected from base hostname)

Physical/Virtual indicators:
- Ends with 'p': Physical server
- Ends with 'v': Virtual server
- Contains 'ilom': ILOM management port

Environment indicators:
- Letter (A, B, C...): Production systems (sequence within cluster)
- Number (1, 2, 3...): Pre-Production/PSS systems (sequence within cluster)
- Shared: Network devices and infrastructure shared between environments

Detection priority:
1. Explicit hostname mappings (EXPLICIT_ENV_MAPPINGS in config.py)
2. Shared resource patterns (SHARED_RESOURCE_PATTERNS in config.py)
3. Auto-detection based on 9-char hostname format
"""

from dataclasses import dataclass
from typing import Optional, Tuple
from enum import Enum
import re

# Import config - handle both relative and absolute imports
try:
    from ..config import (
        ENV_TYPE_LABELS, EXPLICIT_ENV_MAPPINGS, SHARED_RESOURCE_PATTERNS,
        AUTO_CLASSIFY_UNMATCHED_AS_SHARED
    )
except ImportError:
    # Fallback defaults if config not available
    ENV_TYPE_LABELS = {
        'production': 'Production',
        'pre_production': 'PSS',
        'shared': 'Shared',
        'unknown': 'Unknown'
    }
    EXPLICIT_ENV_MAPPINGS = {}
    SHARED_RESOURCE_PATTERNS = []
    AUTO_CLASSIFY_UNMATCHED_AS_SHARED = False


class HostType(Enum):
    """Host type classification."""
    PHYSICAL = 'physical'
    VIRTUAL = 'virtual'
    ILOM = 'ilom'
    UNKNOWN = 'unknown'


class EnvironmentType(Enum):
    """Environment type classification based on sequence character or explicit mapping."""
    PRODUCTION = 'production'
    PRE_PRODUCTION = 'pre_production'
    SHARED = 'shared'
    UNKNOWN = 'unknown'


@dataclass
class HostnameStructure:
    """Parsed hostname structure with environment information."""

    original_hostname: str
    location: str = ''
    tier: str = ''
    cluster: str = ''
    environment: str = ''  # The sequence character (A, B, 1, 2, etc.)
    host_type: HostType = HostType.UNKNOWN
    environment_type: EnvironmentType = EnvironmentType.UNKNOWN
    is_ilom: bool = False
    is_valid_format: bool = False

    @property
    def is_physical(self) -> bool:
        """Check if host is physical."""
        return self.host_type == HostType.PHYSICAL

    @property
    def is_virtual(self) -> bool:
        """Check if host is virtual."""
        return self.host_type == HostType.VIRTUAL

    @property
    def is_production(self) -> bool:
        """Check if host is in production environment (letter sequence)."""
        return self.environment_type == EnvironmentType.PRODUCTION

    @property
    def is_preprod(self) -> bool:
        """Check if host is in pre-production/PSS environment (number sequence)."""
        return self.environment_type == EnvironmentType.PRE_PRODUCTION

    @property
    def is_shared(self) -> bool:
        """Check if host is a shared resource between environments."""
        return self.environment_type == EnvironmentType.SHARED

    @property
    def environment_label(self) -> str:
        """Get human-readable environment label from config."""
        return ENV_TYPE_LABELS.get(self.environment_type.value, 'Unknown')

    @property
    def location_tier(self) -> str:
        """Get combined location-tier identifier."""
        return f"{self.location}-{self.tier}" if self.location and self.tier else ''

    @property
    def full_identifier(self) -> str:
        """Get full environment identifier."""
        parts = [self.location, self.tier, self.cluster, self.environment]
        return '-'.join(p for p in parts if p)

    def matches_location(self, location: str) -> bool:
        """Check if hostname matches given location."""
        return self.location.lower() == location.lower()

    def matches_tier(self, tier: str) -> bool:
        """Check if hostname matches given tier."""
        return self.tier.lower() == tier.lower()

    def matches_environment(self, environment: str) -> bool:
        """Check if hostname matches given environment."""
        return self.environment.lower() == environment.lower()

    def to_dict(self) -> dict:
        """Convert to dictionary representation."""
        return {
            'original_hostname': self.original_hostname,
            'location': self.location,
            'tier': self.tier,
            'cluster': self.cluster,
            'environment': self.environment,
            'host_type': self.host_type.value,
            'environment_type': self.environment_type.value,
            'is_production': self.is_production,
            'is_preprod': self.is_preprod,
            'is_shared': self.is_shared,
            'environment_label': self.environment_label,
            'is_ilom': self.is_ilom,
            'is_valid_format': self.is_valid_format
        }


def _check_explicit_mapping(hostname: str) -> Optional[EnvironmentType]:
    """
    Check if hostname matches an explicit environment mapping.

    Args:
        hostname: The hostname to check

    Returns:
        EnvironmentType if matched, None otherwise
    """
    hostname_lower = hostname.lower().strip()

    # Check exact matches first
    if hostname_lower in EXPLICIT_ENV_MAPPINGS:
        env_str = EXPLICIT_ENV_MAPPINGS[hostname_lower]
        return _env_str_to_type(env_str)

    # Check case-insensitive matches
    for pattern, env_str in EXPLICIT_ENV_MAPPINGS.items():
        if pattern.lower() == hostname_lower:
            return _env_str_to_type(env_str)

    return None


def _check_shared_patterns(hostname: str) -> bool:
    """
    Check if hostname matches any shared resource pattern.

    Args:
        hostname: The hostname to check

    Returns:
        True if matches a shared resource pattern
    """
    hostname_lower = hostname.lower().strip()

    for pattern in SHARED_RESOURCE_PATTERNS:
        try:
            if re.match(pattern, hostname_lower, re.IGNORECASE):
                return True
        except re.error:
            # Invalid regex pattern, skip it
            continue

    return False


def _env_str_to_type(env_str: str) -> EnvironmentType:
    """Convert environment string to EnvironmentType enum."""
    env_str_lower = env_str.lower()
    if env_str_lower in ('production', 'prod'):
        return EnvironmentType.PRODUCTION
    elif env_str_lower in ('pre_production', 'preprod', 'pss', 'pre-prod'):
        return EnvironmentType.PRE_PRODUCTION
    elif env_str_lower == 'shared':
        return EnvironmentType.SHARED
    return EnvironmentType.UNKNOWN


def parse_hostname(hostname: str) -> HostnameStructure:
    """
    Parse a hostname into its structural components.

    Detection priority:
    1. Explicit hostname mappings (EXPLICIT_ENV_MAPPINGS)
    2. Shared resource patterns (SHARED_RESOURCE_PATTERNS)
    3. Auto-detection based on 9-char hostname format

    Args:
        hostname: The hostname string to parse

    Returns:
        HostnameStructure object with parsed components
    """
    if not hostname:
        return HostnameStructure(original_hostname=hostname)

    hostname_lower = hostname.lower().strip()
    result = HostnameStructure(original_hostname=hostname)

    # PRIORITY 1: Check explicit hostname mappings first
    explicit_env = _check_explicit_mapping(hostname)
    if explicit_env is not None:
        result.environment_type = explicit_env
        # Still parse structure if possible, but env type is already set
        explicit_match = True
    else:
        explicit_match = False

    # PRIORITY 2: Check shared resource patterns (if not explicitly mapped)
    if not explicit_match and _check_shared_patterns(hostname):
        result.environment_type = EnvironmentType.SHARED
        # Shared resources typically don't follow standard naming
        return result

    # Check for ILOM suffix (13-char format: hostname-ilom)
    if '-ilom' in hostname_lower or 'ilom' in hostname_lower:
        result.is_ilom = True
        result.host_type = HostType.ILOM
        # Remove ilom suffix for further parsing - env type still detected from base
        base_hostname = hostname_lower.replace('-ilom', '').replace('ilom', '')
    else:
        base_hostname = hostname_lower

    # Determine host type from last character
    if not result.is_ilom:
        if base_hostname.endswith('p'):
            result.host_type = HostType.PHYSICAL
        elif base_hostname.endswith('v'):
            result.host_type = HostType.VIRTUAL

    # PRIORITY 3: Parse 9-character format for auto-detection: LLLLTTCEP
    if len(base_hostname) == 9:
        result.location = base_hostname[0:4].upper()  # First 4: Location
        result.tier = base_hostname[4:6].upper()      # Next 2: Tier
        result.cluster = base_hostname[6:7].upper()   # Next 1: Cluster
        result.environment = base_hostname[7:8].upper()  # Next 1: Environment sequence
        # Last 1 is type (already parsed above)
        result.is_valid_format = True

        # Only auto-detect environment type if not explicitly mapped
        if not explicit_match:
            env_char = base_hostname[7:8]
            if env_char.isalpha():
                result.environment_type = EnvironmentType.PRODUCTION
            elif env_char.isdigit():
                result.environment_type = EnvironmentType.PRE_PRODUCTION

    # Parse other potential formats
    elif len(base_hostname) >= 8:
        # Try to extract what we can from longer hostnames
        # Assume first 4 might be location if alphanumeric pattern matches
        potential_location = base_hostname[0:4]
        if potential_location.isalnum():
            result.location = potential_location.upper()

            # Try to extract tier from next 2 characters
            if len(base_hostname) >= 6:
                potential_tier = base_hostname[4:6]
                if potential_tier.isalnum():
                    result.tier = potential_tier.upper()

    return result


def classify_environment_type(hostname: str) -> EnvironmentType:
    """
    Classify a host's environment type.

    Detection priority:
    1. Explicit hostname mappings
    2. Shared resource patterns
    3. Auto-detection (letter=Production, number=PSS/Pre-Prod)

    Args:
        hostname: The hostname to classify

    Returns:
        EnvironmentType enum value (PRODUCTION, PRE_PRODUCTION, SHARED, UNKNOWN)
    """
    parsed = parse_hostname(hostname)
    return parsed.environment_type


def is_production_host(hostname: str) -> bool:
    """
    Check if hostname represents a production system.

    Args:
        hostname: The hostname to check

    Returns:
        True if production (letter sequence), False otherwise
    """
    parsed = parse_hostname(hostname)
    return parsed.is_production


def is_preprod_host(hostname: str) -> bool:
    """
    Check if hostname represents a pre-production/PSS system.

    Args:
        hostname: The hostname to check

    Returns:
        True if pre-production (number sequence), False otherwise
    """
    parsed = parse_hostname(hostname)
    return parsed.is_preprod


def is_shared_host(hostname: str) -> bool:
    """
    Check if hostname represents a shared resource between environments.

    Args:
        hostname: The hostname to check

    Returns:
        True if shared (explicit mapping or pattern match), False otherwise
    """
    parsed = parse_hostname(hostname)
    return parsed.is_shared


def get_environment_label(hostname: str) -> str:
    """
    Get the human-readable environment label for a hostname.

    Args:
        hostname: The hostname to check

    Returns:
        Environment label string (Production, PSS, Shared, Unknown)
    """
    parsed = parse_hostname(hostname)
    return parsed.environment_label


def classify_host_type(hostname: str) -> HostType:
    """
    Classify a host as physical, virtual, or ILOM based on hostname.

    Args:
        hostname: The hostname to classify

    Returns:
        HostType enum value
    """
    if not hostname:
        return HostType.UNKNOWN

    hostname_lower = hostname.lower()

    if 'ilom' in hostname_lower:
        return HostType.ILOM
    elif hostname_lower.endswith('p'):
        return HostType.PHYSICAL
    elif hostname_lower.endswith('v'):
        return HostType.VIRTUAL
    else:
        return HostType.UNKNOWN


def extract_location(hostname: str) -> str:
    """
    Extract location code from hostname.

    Args:
        hostname: The hostname to extract from

    Returns:
        Location code or empty string
    """
    parsed = parse_hostname(hostname)
    return parsed.location


def extract_tier(hostname: str) -> str:
    """
    Extract tier code from hostname.

    Args:
        hostname: The hostname to extract from

    Returns:
        Tier code or empty string
    """
    parsed = parse_hostname(hostname)
    return parsed.tier


def extract_environment(hostname: str) -> str:
    """
    Extract environment code from hostname.

    Args:
        hostname: The hostname to extract from

    Returns:
        Environment code or empty string
    """
    parsed = parse_hostname(hostname)
    return parsed.environment


def group_hostnames_by_attribute(hostnames: list, attribute: str) -> dict:
    """
    Group hostnames by a specific attribute (location, tier, environment, host_type).

    Args:
        hostnames: List of hostname strings
        attribute: Attribute to group by ('location', 'tier', 'environment', 'host_type')

    Returns:
        Dictionary mapping attribute values to lists of hostnames
    """
    groups = {}

    for hostname in hostnames:
        parsed = parse_hostname(hostname)

        if attribute == 'location':
            key = parsed.location or 'Unknown'
        elif attribute == 'tier':
            key = parsed.tier or 'Unknown'
        elif attribute == 'environment':
            key = parsed.environment or 'Unknown'
        elif attribute == 'host_type':
            key = parsed.host_type.value
        elif attribute == 'cluster':
            key = parsed.cluster or 'Unknown'
        else:
            key = 'Unknown'

        if key not in groups:
            groups[key] = []
        groups[key].append(hostname)

    return groups


# Hostname normalization patterns for STIG matching
HOSTNAME_STRIP_SUFFIXES = [
    '-ilom', '-mgmt', '-ilo', '-oob', '-bmc',  # Management interfaces
    '-db', '-database', '-ora', '-sql',          # Database instances
    '-app', '-web', '-api',                      # Application roles
    '-prd', '-prod', '-dev', '-test', '-qa', '-uat',  # Environment suffixes
    '-pri', '-sec', '-dr',                       # Redundancy designators
    '-a', '-b', '-c', '-1', '-2', '-3',          # Instance suffixes
]

# Common database instance patterns (hostname_DBNAME, hostname-DBSID)
DB_INSTANCE_PATTERNS = [
    r'[_-][A-Z]{2,8}\d{0,2}$',  # Like _PRODDB, -TESTDB1
    r'[_-][A-Z]+\d+[A-Z]*$',    # Like _DB01, -ORA12C
]


def normalize_hostname_for_matching(hostname: str) -> str:
    """
    Normalize a hostname to its base form for matching across data sources.

    This removes common suffixes like -ilom, -mgmt, database instance names,
    etc. to enable matching between STIG checklists and Tenable findings.

    Args:
        hostname: The hostname to normalize

    Returns:
        Normalized hostname suitable for matching
    """
    if not hostname:
        return ''

    normalized = hostname.lower().strip()

    # Remove common suffixes
    for suffix in HOSTNAME_STRIP_SUFFIXES:
        if normalized.endswith(suffix):
            normalized = normalized[:-len(suffix)]
            break  # Only strip one suffix

    # Check for database instance patterns
    for pattern in DB_INSTANCE_PATTERNS:
        match = re.search(pattern, normalized, re.IGNORECASE)
        if match:
            normalized = normalized[:match.start()]
            break

    return normalized


def get_hostname_variants(hostname: str) -> list:
    """
    Generate possible hostname variants for fuzzy matching.

    Returns the hostname in multiple forms to improve matching
    between STIG checklists and scan data.

    Args:
        hostname: The base hostname

    Returns:
        List of possible hostname variants (all lowercase)
    """
    if not hostname:
        return []

    base = hostname.lower().strip()
    normalized = normalize_hostname_for_matching(base)

    variants = {base, normalized}

    # Add without common suffixes
    for suffix in HOSTNAME_STRIP_SUFFIXES:
        if base.endswith(suffix):
            variants.add(base[:-len(suffix)])

    # Add with .domain stripped
    if '.' in base:
        variants.add(base.split('.')[0])

    return list(variants)


def find_best_hostname_match(target_hostname: str, candidate_hostnames: list) -> str:
    """
    Find the best matching hostname from candidates, preferring simpler names.

    Prioritizes:
    1. Exact match
    2. Normalized match
    3. Match without management suffixes (-ilom, -mgmt)

    Args:
        target_hostname: The hostname to match
        candidate_hostnames: List of possible matches

    Returns:
        Best matching hostname or empty string if no match
    """
    if not target_hostname or not candidate_hostnames:
        return ''

    target_lower = target_hostname.lower().strip()
    target_normalized = normalize_hostname_for_matching(target_lower)
    target_variants = set(get_hostname_variants(target_lower))

    # Build candidate lookup with normalized forms
    candidates_by_normalized = {}
    simple_candidates = []  # Candidates without mgmt suffixes

    for candidate in candidate_hostnames:
        cand_lower = candidate.lower().strip()
        cand_normalized = normalize_hostname_for_matching(cand_lower)

        # Check if this is a "simple" hostname (no management suffix)
        is_simple = not any(cand_lower.endswith(s) for s in ['-ilom', '-mgmt', '-ilo', '-oob', '-bmc'])
        if is_simple:
            simple_candidates.append((candidate, cand_lower, cand_normalized))

        if cand_normalized not in candidates_by_normalized:
            candidates_by_normalized[cand_normalized] = []
        candidates_by_normalized[cand_normalized].append((candidate, is_simple))

    # Priority 1: Exact match
    for candidate in candidate_hostnames:
        if candidate.lower().strip() == target_lower:
            return candidate

    # Priority 2: Simple hostname exact match on normalized
    if target_normalized in candidates_by_normalized:
        matches = candidates_by_normalized[target_normalized]
        # Prefer simple (non-mgmt) hostnames
        simple_matches = [m[0] for m in matches if m[1]]
        if simple_matches:
            return simple_matches[0]
        # Fall back to any match
        return matches[0][0]

    # Priority 3: Check all target variants against normalized candidates
    for variant in target_variants:
        if variant in candidates_by_normalized:
            matches = candidates_by_normalized[variant]
            simple_matches = [m[0] for m in matches if m[1]]
            if simple_matches:
                return simple_matches[0]
            return matches[0][0]

    return ''


def build_hostname_match_index(hostnames: list) -> dict:
    """
    Build an index for fast hostname matching.

    Creates a mapping from normalized hostnames to their original forms,
    useful for batch matching operations.

    Args:
        hostnames: List of hostnames to index

    Returns:
        Dictionary mapping normalized forms to list of (original, is_simple) tuples
    """
    index = {}

    for hostname in hostnames:
        if not hostname:
            continue

        host_lower = hostname.lower().strip()
        normalized = normalize_hostname_for_matching(host_lower)

        is_simple = not any(host_lower.endswith(s) for s in ['-ilom', '-mgmt', '-ilo', '-oob', '-bmc'])

        if normalized not in index:
            index[normalized] = []
        index[normalized].append((hostname, is_simple))

        # Also index by variants
        for variant in get_hostname_variants(host_lower):
            if variant != normalized:
                if variant not in index:
                    index[variant] = []
                index[variant].append((hostname, is_simple))

    return index

