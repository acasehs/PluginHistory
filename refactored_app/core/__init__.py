"""
Core modules for Nessus file parsing and data extraction.
"""

from .archive_extraction import (
    extract_nested_archives,
    find_files_by_extension,
    cleanup_temp_directory,
    extract_plugins_from_archive
)

from .nessus_parser import (
    parse_nessus_file,
    parse_multiple_nessus_files,
    extract_finding_data
)

from .plugin_database import (
    load_plugins_database,
    parse_plugins_xml
)

from .data_processing import (
    calculate_severity_from_cvss,
    enrich_findings_with_severity,
    create_severity_summary
)

__all__ = [
    'extract_nested_archives',
    'find_files_by_extension',
    'cleanup_temp_directory',
    'extract_plugins_from_archive',
    'parse_nessus_file',
    'parse_multiple_nessus_files',
    'extract_finding_data',
    'load_plugins_database',
    'parse_plugins_xml',
    'calculate_severity_from_cvss',
    'enrich_findings_with_severity',
    'create_severity_summary'
]
