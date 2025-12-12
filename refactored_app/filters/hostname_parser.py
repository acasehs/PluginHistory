"""
Hostname Structure Parser
Re-export from models for convenient access.
"""

# Re-export hostname parsing utilities from models
from ..models.hostname_structure import (
    HostnameStructure,
    HostType,
    parse_hostname,
    classify_host_type,
    extract_location,
    extract_tier,
    extract_environment,
    group_hostnames_by_attribute
)

__all__ = [
    'HostnameStructure',
    'HostType',
    'parse_hostname',
    'classify_host_type',
    'extract_location',
    'extract_tier',
    'extract_environment',
    'group_hostnames_by_attribute'
]
