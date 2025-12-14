"""
IAVM Notice Summaries Parser Module
Parses DISA IAVM Notice Summaries Excel documents and integrates with findings.
"""

import pandas as pd
import numpy as np
import re
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any


def normalize_iavm_number(iavm_str: str) -> Tuple[str, Optional[int], str]:
    """
    Normalize IAVM number to standard format and extract year and type.

    Formats handled:
    - 1998-0009 -> (1998-0009, 1998, 'A')  # Older format without letter
    - 1999-A-0008 -> (1999-A-0008, 1999, 'A')
    - 2000-B-0001 -> (2000-B-0001, 2000, 'B')
    - 1999-T-0002 -> (1999-T-0002, 1999, 'T')
    - 1999-A-0011.0.1 -> (1999-A-0011.0.1, 1999, 'A')  # Revisions

    Args:
        iavm_str: IAVM number string

    Returns:
        Tuple of (normalized_number, year, type_letter)
    """
    if not iavm_str or pd.isna(iavm_str):
        return ('', None, '')

    iavm_str = str(iavm_str).strip()

    # Pattern with type letter: 1999-A-0008 or 1999-A-0011.0.1
    pattern_with_letter = r'^(\d{4})-([ABT])-(\d+(?:\.\d+(?:\.\d+)?)?)$'
    match = re.match(pattern_with_letter, iavm_str, re.IGNORECASE)
    if match:
        year = int(match.group(1))
        type_letter = match.group(2).upper()
        number = match.group(3)
        normalized = f"{year}-{type_letter}-{number}"
        return (normalized, year, type_letter)

    # Older format without type letter: 1998-0009
    pattern_old = r'^(\d{4})-(\d+)$'
    match = re.match(pattern_old, iavm_str)
    if match:
        year = int(match.group(1))
        number = match.group(2)
        # Older format is considered 'A' (IAVA)
        normalized = f"{year}-{number}"
        return (normalized, year, 'A')

    return (iavm_str, None, '')


def parse_stig_severity(severity_str: str) -> Tuple[str, int]:
    """
    Parse STIG Finding Severity to normalized form and numeric value.

    Args:
        severity_str: STIG severity string (e.g., 'CAT I', 'CAT II')

    Returns:
        Tuple of (normalized_string, numeric_value)
    """
    if not severity_str or pd.isna(severity_str):
        return ('', 0)

    severity_str = str(severity_str).strip().upper()

    if 'CAT I' in severity_str and 'II' not in severity_str:
        return ('CAT I', 1)
    elif 'CAT II' in severity_str and 'III' not in severity_str:
        return ('CAT II', 2)
    elif 'CAT III' in severity_str:
        return ('CAT III', 3)

    return (severity_str, 0)


def load_iavm_summaries(iavm_file: str) -> pd.DataFrame:
    """
    Load IAVM Notice Summaries from Excel file.

    Expected columns (case-insensitive):
    - Number (IAVM number)
    - STIG Finding Severity (CAT I, CAT II, etc.)
    - State (Final, Draft)
    - Status (Expired, Superseded, Active)
    - Supersedes (IAVM number this supersedes)
    - Superseded By (IAVM number that supersedes this)
    - Title
    - Last Saved and Send (date)
    - Released (date)
    - Acknowledged (date)
    - First Report (date)
    - Mitigation (date)

    Args:
        iavm_file: Path to IAVM summaries file (xlsx or xls)

    Returns:
        DataFrame with IAVM notice data
    """
    try:
        if iavm_file.lower().endswith('.csv'):
            iavm_df = pd.read_csv(iavm_file)
        else:
            iavm_df = pd.read_excel(iavm_file)

        # Standardize column names
        column_mappings = {
            'number': 'iavm_number',
            'iavm number': 'iavm_number',
            'stig finding severity': 'stig_severity',
            'stig_finding_severity': 'stig_severity',
            'severity': 'stig_severity',
            'state': 'state',
            'status': 'status',
            'supersedes': 'supersedes',
            'superseded by': 'superseded_by',
            'superseded_by': 'superseded_by',
            'title': 'title',
            'subject': 'title',
            'last saved and send': 'last_saved',
            'last_saved_and_send': 'last_saved',
            'released': 'released_date',
            'release date': 'released_date',
            'acknowledged': 'acknowledged_date',
            'first report': 'first_report_date',
            'first_report': 'first_report_date',
            'mitigation': 'mitigation_date',
        }

        iavm_df.columns = iavm_df.columns.str.lower().str.strip()
        iavm_df = iavm_df.rename(columns=column_mappings)

        # Parse IAVM numbers and extract year/type
        if 'iavm_number' in iavm_df.columns:
            normalized_data = iavm_df['iavm_number'].apply(normalize_iavm_number)
            iavm_df['iavm_number_normalized'] = normalized_data.apply(lambda x: x[0])
            iavm_df['iavm_year'] = normalized_data.apply(lambda x: x[1])
            iavm_df['iavm_type'] = normalized_data.apply(lambda x: x[2])

        # Parse STIG severity
        if 'stig_severity' in iavm_df.columns:
            severity_data = iavm_df['stig_severity'].apply(parse_stig_severity)
            iavm_df['stig_severity_normalized'] = severity_data.apply(lambda x: x[0])
            iavm_df['stig_severity_value'] = severity_data.apply(lambda x: x[1])
        else:
            iavm_df['stig_severity_normalized'] = ''
            iavm_df['stig_severity_value'] = 0

        # Parse dates
        date_columns = ['last_saved', 'released_date', 'acknowledged_date',
                       'first_report_date', 'mitigation_date']
        for date_col in date_columns:
            if date_col in iavm_df.columns:
                iavm_df[date_col] = pd.to_datetime(iavm_df[date_col], errors='coerce')

        # Clean up status column
        if 'status' in iavm_df.columns:
            iavm_df['status'] = iavm_df['status'].fillna('').str.strip()
        else:
            iavm_df['status'] = ''

        # Clean up state column
        if 'state' in iavm_df.columns:
            iavm_df['state'] = iavm_df['state'].fillna('').str.strip()
        else:
            iavm_df['state'] = ''

        # Clean supersedes columns
        for col in ['supersedes', 'superseded_by']:
            if col in iavm_df.columns:
                iavm_df[col] = iavm_df[col].fillna('').astype(str).str.strip()
            else:
                iavm_df[col] = ''

        # Create lookup key (same format as OPDIR for compatibility)
        iavm_df['iavm_key'] = iavm_df['iavm_number_normalized'].str.lower()

        print(f"Loaded {len(iavm_df)} IAVM notice entries")
        if 'iavm_year' in iavm_df.columns:
            years = iavm_df['iavm_year'].dropna().unique()
            if len(years) > 0:
                year_range = f"{int(min(years))}-{int(max(years))}"
                print(f"Year range: {year_range}")

        # Count by type
        if 'iavm_type' in iavm_df.columns:
            type_counts = iavm_df['iavm_type'].value_counts().to_dict()
            print(f"Types: IAVA={type_counts.get('A', 0)}, IAVB={type_counts.get('B', 0)}, IAVT={type_counts.get('T', 0)}")

        return iavm_df

    except Exception as e:
        print(f"Error loading IAVM summaries: {e}")
        import traceback
        traceback.print_exc()
        return pd.DataFrame()


def create_iavm_lookup(iavm_df: pd.DataFrame) -> Dict[str, Any]:
    """
    Create optimized lookup dictionary for IAVM matching.

    Args:
        iavm_df: IAVM summaries DataFrame

    Returns:
        Dictionary for fast IAVM lookup
    """
    lookup = {
        'by_number': {},      # 'YYYY-X-NNNN' -> row
        'by_number_lower': {},  # lowercase version
        'supersession_chain': {},  # number -> superseded_by chain
    }

    if iavm_df.empty:
        return lookup

    for _, row in iavm_df.iterrows():
        number = row.get('iavm_number_normalized', '')
        if not number:
            continue

        lookup['by_number'][number] = row.to_dict()
        lookup['by_number_lower'][number.lower()] = row.to_dict()

        # Build supersession chain
        superseded_by = row.get('superseded_by', '')
        if superseded_by:
            lookup['supersession_chain'][number] = superseded_by

    return lookup


def get_current_iavm(iavm_number: str, lookup: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Get the current (non-superseded) IAVM for a given number.

    Follows the supersession chain to find the latest active IAVM.

    Args:
        iavm_number: IAVM number to look up
        lookup: Lookup dictionary from create_iavm_lookup

    Returns:
        Current IAVM data dict or None
    """
    visited = set()
    current = iavm_number

    while current and current not in visited:
        visited.add(current)

        # Check if this number exists
        data = lookup['by_number'].get(current) or lookup['by_number_lower'].get(current.lower())
        if not data:
            return None

        # Check if superseded
        superseded_by = lookup['supersession_chain'].get(current, '')
        if not superseded_by:
            return data

        current = superseded_by

    return lookup['by_number'].get(current) or lookup['by_number_lower'].get(current.lower())


def match_iavx_to_iavm(iavx_string: str, iavm_lookup: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Match IAVx references from findings to IAVM notices.

    Args:
        iavx_string: IAVx string from finding (may contain multiple references)
        iavm_lookup: Lookup dictionary from create_iavm_lookup

    Returns:
        List of matched IAVM records
    """
    if not iavx_string or pd.isna(iavx_string):
        return []

    matches = []

    # Pattern to extract IAVM references
    # Handles: IAVA:2024-A-0073, IAVB:2025-B-0146, IATM:2023-T-0001
    pattern = r'(?:IAVA|IAVB|IATM)[:\s]*(\d{4})[:\-]?([ABT])?[:\-]?(\d+(?:\.\d+)*)'

    for line in str(iavx_string).split('\n'):
        for match in re.finditer(pattern, line, re.IGNORECASE):
            year = match.group(1)
            type_letter = (match.group(2) or 'A').upper()
            number = match.group(3)

            # Build lookup key
            if type_letter:
                iavm_key = f"{year}-{type_letter}-{number}"
            else:
                iavm_key = f"{year}-{number}"

            # Look up in IAVM database
            iavm_data = iavm_lookup['by_number'].get(iavm_key)
            if not iavm_data:
                iavm_data = iavm_lookup['by_number_lower'].get(iavm_key.lower())

            if iavm_data:
                matches.append(iavm_data)

    return matches


def enrich_findings_with_iavm(lifecycle_df: pd.DataFrame, iavm_df: pd.DataFrame) -> pd.DataFrame:
    """
    Enrich finding lifecycle data with IAVM notice information.

    Args:
        lifecycle_df: DataFrame from analyze_finding_lifecycle
        iavm_df: DataFrame from load_iavm_summaries

    Returns:
        DataFrame with IAVM enrichment
    """
    if lifecycle_df.empty:
        return lifecycle_df

    lifecycle_df = lifecycle_df.copy()

    # Initialize IAVM columns
    iavm_columns = {
        'iavm_number': '',
        'iavm_title': '',
        'iavm_stig_severity': '',
        'iavm_status': '',
        'iavm_state': '',
        'iavm_released_date': pd.NaT,
        'iavm_mitigation_date': pd.NaT,
        'iavm_superseded_by': '',
        'iavm_is_current': True,
    }

    for col, default in iavm_columns.items():
        lifecycle_df[col] = default

    if iavm_df.empty:
        return lifecycle_df

    # Create lookup
    lookup = create_iavm_lookup(iavm_df)

    # Process each finding
    for idx, row in lifecycle_df.iterrows():
        if not pd.notna(row.get('iavx')) or not row['iavx']:
            continue

        # Match IAVx to IAVM notices
        iavm_matches = match_iavx_to_iavm(row['iavx'], lookup)

        if not iavm_matches:
            continue

        # Use first match (most specific)
        iavm_data = iavm_matches[0]

        lifecycle_df.at[idx, 'iavm_number'] = iavm_data.get('iavm_number_normalized', '')
        lifecycle_df.at[idx, 'iavm_title'] = iavm_data.get('title', '')
        lifecycle_df.at[idx, 'iavm_stig_severity'] = iavm_data.get('stig_severity_normalized', '')
        lifecycle_df.at[idx, 'iavm_status'] = iavm_data.get('status', '')
        lifecycle_df.at[idx, 'iavm_state'] = iavm_data.get('state', '')
        lifecycle_df.at[idx, 'iavm_released_date'] = iavm_data.get('released_date')
        lifecycle_df.at[idx, 'iavm_mitigation_date'] = iavm_data.get('mitigation_date')
        lifecycle_df.at[idx, 'iavm_superseded_by'] = iavm_data.get('superseded_by', '')
        lifecycle_df.at[idx, 'iavm_is_current'] = not bool(iavm_data.get('superseded_by', ''))

    return lifecycle_df


def get_iavm_summary_stats(iavm_df: pd.DataFrame) -> Dict[str, Any]:
    """
    Generate summary statistics for IAVM notices.

    Args:
        iavm_df: IAVM summaries DataFrame

    Returns:
        Dictionary with summary statistics
    """
    if iavm_df.empty:
        return {
            'total_notices': 0,
            'by_type': {'A': 0, 'B': 0, 'T': 0},
            'by_status': {},
            'by_severity': {},
            'year_range': None,
            'active_count': 0,
            'expired_count': 0,
            'superseded_count': 0,
        }

    total = len(iavm_df)

    # By type
    by_type = {'A': 0, 'B': 0, 'T': 0}
    if 'iavm_type' in iavm_df.columns:
        type_counts = iavm_df['iavm_type'].value_counts().to_dict()
        by_type.update(type_counts)

    # By status
    by_status = {}
    if 'status' in iavm_df.columns:
        by_status = iavm_df['status'].value_counts().to_dict()

    # By severity
    by_severity = {}
    if 'stig_severity_normalized' in iavm_df.columns:
        by_severity = iavm_df[iavm_df['stig_severity_normalized'] != '']['stig_severity_normalized'].value_counts().to_dict()

    # Year range
    year_range = None
    if 'iavm_year' in iavm_df.columns:
        years = iavm_df['iavm_year'].dropna()
        if len(years) > 0:
            year_range = (int(years.min()), int(years.max()))

    return {
        'total_notices': total,
        'by_type': by_type,
        'by_status': by_status,
        'by_severity': by_severity,
        'year_range': year_range,
        'active_count': by_status.get('Active', 0),
        'expired_count': by_status.get('Expired', 0),
        'superseded_count': by_status.get('Superseded', 0),
    }


def merge_opdir_and_iavm(opdir_df: pd.DataFrame, iavm_df: pd.DataFrame) -> pd.DataFrame:
    """
    Merge OPDIR and IAVM data into a unified compliance reference table.

    Creates a combined table with normalized fields from both sources.

    Args:
        opdir_df: OPDIR mapping DataFrame
        iavm_df: IAVM summaries DataFrame

    Returns:
        Combined DataFrame with unified schema
    """
    combined_records = []

    # Process OPDIR records
    if not opdir_df.empty:
        for _, row in opdir_df.iterrows():
            record = {
                'reference_number': row.get('opdir_number', ''),
                'reference_normalized': row.get('opdir_number_normalized', ''),
                'year': row.get('opdir_year'),
                'type': 'OPDIR',
                'title': row.get('opdir_subject', ''),
                'severity': '',
                'status': '',
                'release_date': row.get('opdir_release_date'),
                'due_date': row.get('opdir_final_due_date'),
                'mitigation_date': pd.NaT,
                'days_to_remediate': row.get('opdir_days_to_remediate'),
                'supersedes': '',
                'superseded_by': '',
                'source': 'OPDIR',
            }
            combined_records.append(record)

    # Process IAVM records
    if not iavm_df.empty:
        for _, row in iavm_df.iterrows():
            iavm_type = row.get('iavm_type', 'A')
            type_name = {'A': 'IAVA', 'B': 'IAVB', 'T': 'IAVT'}.get(iavm_type, 'IAVM')

            record = {
                'reference_number': row.get('iavm_number', ''),
                'reference_normalized': row.get('iavm_number_normalized', ''),
                'year': row.get('iavm_year'),
                'type': type_name,
                'title': row.get('title', ''),
                'severity': row.get('stig_severity_normalized', ''),
                'status': row.get('status', ''),
                'release_date': row.get('released_date'),
                'due_date': pd.NaT,  # IAVM uses mitigation date instead
                'mitigation_date': row.get('mitigation_date'),
                'days_to_remediate': np.nan,
                'supersedes': row.get('supersedes', ''),
                'superseded_by': row.get('superseded_by', ''),
                'source': 'IAVM',
            }
            combined_records.append(record)

    if not combined_records:
        return pd.DataFrame()

    combined_df = pd.DataFrame(combined_records)

    # Sort by year descending, then by reference number
    combined_df = combined_df.sort_values(
        ['year', 'reference_normalized'],
        ascending=[False, True],
        na_position='last'
    )

    return combined_df
