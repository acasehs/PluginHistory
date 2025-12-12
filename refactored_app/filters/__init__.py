"""
Filter modules for data filtering and custom list management.
"""

from .hostname_parser import (
    parse_hostname,
    classify_host_type,
    group_hostnames_by_attribute,
    HostnameStructure,
    HostType
)

from .custom_lists import (
    FilterList,
    FilterListManager,
    save_filter_list,
    load_filter_list
)

from .filter_engine import (
    FilterEngine,
    FilterCriteria,
    apply_filters
)

__all__ = [
    'parse_hostname',
    'classify_host_type',
    'group_hostnames_by_attribute',
    'HostnameStructure',
    'HostType',
    'FilterList',
    'FilterListManager',
    'save_filter_list',
    'load_filter_list',
    'FilterEngine',
    'FilterCriteria',
    'apply_filters'
]
