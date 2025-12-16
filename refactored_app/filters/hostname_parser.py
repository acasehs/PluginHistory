"""
Hostname Structure Parser
Re-export from models for convenient access.
"""

# Re-export hostname parsing utilities from models
from ..models.hostname_structure import (
    HostnameStructure,
    HostType,
    EnvironmentType,
    parse_hostname,
    classify_host_type,
    classify_environment_type,
    is_production_host,
    is_preprod_host,
    is_shared_host,
    get_environment_label,
    extract_location,
    extract_tier,
    extract_environment,
    group_hostnames_by_attribute,
    # Hostname normalization for STIG matching
    normalize_hostname_for_matching,
    get_hostname_variants,
    find_best_hostname_match,
    build_hostname_match_index
)

__all__ = [
    'HostnameStructure',
    'HostType',
    'EnvironmentType',
    'parse_hostname',
    'classify_host_type',
    'classify_environment_type',
    'is_production_host',
    'is_preprod_host',
    'is_shared_host',
    'get_environment_label',
    'extract_location',
    'extract_tier',
    'extract_environment',
    'group_hostnames_by_attribute',
    # Hostname normalization for STIG matching
    'normalize_hostname_for_matching',
    'get_hostname_variants',
    'find_best_hostname_match',
    'build_hostname_match_index'
]
