"""
OPDIR Compliance Analysis Module
Handles OPDIR mapping and compliance status tracking with year inference.
"""

import pandas as pd
import numpy as np
import re
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any


def normalize_opdir_number(opdir_str: str, reference_year: int = None) -> Tuple[str, Optional[int]]:
    """
    Normalize OPDIR number to standard format and extract/infer year.

    Formats handled:
    - B-0146 -> (b-0146, None)
    - 2025-B-0146 -> (b-0146, 2025)
    - IAVB:2025-B-0146 -> (b-0146, 2025)
    - IAVA-2024-A-0073 -> (a-0073, 2024)

    Args:
        opdir_str: OPDIR number string in various formats
        reference_year: Year to use if not found in string

    Returns:
        Tuple of (normalized_number, year)
    """
    if not opdir_str or pd.isna(opdir_str):
        return ('', None)

    opdir_str = str(opdir_str).strip()

    # Pattern with year: IAVB:2025-B-0146 or 2025-B-0146 or IAVA-2024-A-0073
    year_patterns = [
        r'(?:IAVA|IAVB|IATM)?[:\-]?\s*(\d{4})[:\-]?([ABT])[:\-]?(\d+)',  # With IAV prefix
        r'^(\d{4})[:\-]([ABT])[:\-](\d+)$',  # Just year-type-number
    ]

    for pattern in year_patterns:
        match = re.search(pattern, opdir_str, re.IGNORECASE)
        if match:
            year = int(match.group(1))
            type_letter = match.group(2).lower()
            number = match.group(3).zfill(4)
            return (f"{type_letter}-{number}", year)

    # Pattern without year: B-0146 or B0146
    no_year_pattern = r'^([ABT])[:\-]?(\d+)$'
    match = re.search(no_year_pattern, opdir_str, re.IGNORECASE)
    if match:
        type_letter = match.group(1).lower()
        number = match.group(2).zfill(4)
        return (f"{type_letter}-{number}", reference_year)

    return (opdir_str.lower().strip(), reference_year)


def extract_opdir_from_iavx(iavx_string: str, reference_year: int = None) -> List[Dict[str, Any]]:
    """
    Extract OPDIR numbers from IAVx references, preserving year information.

    Converts formats like:
    - IAVB:2025-B-0146 -> {'number': 'b-0146', 'year': 2025, 'full': '2025-B-0146'}
    - IAVA:2024-A-0073 -> {'number': 'a-0073', 'year': 2024, 'full': '2024-A-0073'}
    - IATM:2023-T-0001 -> {'number': 't-0001', 'year': 2023, 'full': '2023-T-0001'}

    Args:
        iavx_string: String containing IAVx references (newline-separated)
        reference_year: Year to use if not found in reference

    Returns:
        List of dicts with 'number', 'year', 'full' keys
    """
    if not iavx_string or pd.isna(iavx_string):
        return []

    results = []

    # Comprehensive pattern to match IAV references with year
    pattern = r'(IAVA|IAVB|IATM)[:\s]*(\d{4})[:\-]?([ABT])[:\-]?(\d+)'

    for line in str(iavx_string).split('\n'):
        line = line.strip()

        for match in re.finditer(pattern, line, re.IGNORECASE):
            iav_type = match.group(1).upper()
            year = int(match.group(2))
            type_letter = match.group(3).lower()
            number = match.group(4).zfill(4)

            normalized = f"{type_letter}-{number}"
            full_ref = f"{year}-{type_letter.upper()}-{number}"

            results.append({
                'number': normalized,
                'year': year,
                'full': full_ref,
                'iav_type': iav_type
            })

    # Also try simpler patterns without year (use reference_year)
    simple_pattern = r'(IAVA|IAVB|IATM)[:\s]*([ABT])[:\-]?(\d+)'
    for line in str(iavx_string).split('\n'):
        line = line.strip()
        for match in re.finditer(simple_pattern, line, re.IGNORECASE):
            type_letter = match.group(2).lower()
            number = match.group(3).zfill(4)
            normalized = f"{type_letter}-{number}"

            # Skip if we already found this with a year
            if not any(r['number'] == normalized for r in results):
                results.append({
                    'number': normalized,
                    'year': reference_year,
                    'full': f"{reference_year}-{type_letter.upper()}-{number}" if reference_year else normalized,
                    'iav_type': match.group(1).upper()
                })

    return results


def infer_year_from_context(row: pd.Series, opdir_df: pd.DataFrame, normalized_number: str) -> Optional[int]:
    """
    Infer the most likely year for an OPDIR based on context.

    Priority:
    1. Year from scan_date (most recent scan)
    2. Year from first_seen date
    3. Most recent year in OPDIR file for that number
    4. Current year

    Args:
        row: Finding row with scan_date, first_seen
        opdir_df: OPDIR mapping DataFrame
        normalized_number: Normalized OPDIR number (e.g., 'b-0146')

    Returns:
        Inferred year
    """
    candidate_years = []

    # Try scan_date
    scan_date = row.get('scan_date')
    if pd.notna(scan_date):
        try:
            if isinstance(scan_date, str):
                scan_date = pd.to_datetime(scan_date)
            candidate_years.append(scan_date.year)
        except Exception:
            pass

    # Try first_seen
    first_seen = row.get('first_seen')
    if pd.notna(first_seen):
        try:
            if isinstance(first_seen, str):
                first_seen = pd.to_datetime(first_seen)
            candidate_years.append(first_seen.year)
        except Exception:
            pass

    # Check OPDIR file for available years with this number
    if not opdir_df.empty and 'opdir_number_normalized' in opdir_df.columns:
        matching = opdir_df[opdir_df['opdir_number_normalized'] == normalized_number]
        if 'opdir_year' in matching.columns:
            file_years = matching['opdir_year'].dropna().unique().tolist()
            candidate_years.extend(file_years)

    # Default to current year
    if not candidate_years:
        candidate_years.append(datetime.now().year)

    # Return most recent year (likely most relevant)
    return max(candidate_years)


def load_opdir_mapping(opdir_file: str) -> pd.DataFrame:
    """
    Load OPDIR mapping from Excel or CSV file with year extraction.

    Expected columns (case-insensitive):
    - OPDIR Number (e.g., 'B-0146' or '2025-B-0146')
    - Subject
    - Release Date
    - Final Due Date
    - Days to Remediate

    Args:
        opdir_file: Path to OPDIR mapping file (xlsx, xls, or csv)

    Returns:
        DataFrame with OPDIR mapping data including year column
    """
    try:
        if opdir_file.lower().endswith('.csv'):
            opdir_df = pd.read_csv(opdir_file)
        else:
            opdir_df = pd.read_excel(opdir_file)

        # Standardize column names
        column_mappings = {
            'opdir number': 'opdir_number',
            'opdir_number': 'opdir_number',
            'opdir': 'opdir_number',
            'number': 'opdir_number',
            'subject': 'opdir_subject',
            'title': 'opdir_subject',
            'release date': 'opdir_release_date',
            'release_date': 'opdir_release_date',
            'released': 'opdir_release_date',
            'final due date': 'opdir_final_due_date',
            'final_due_date': 'opdir_final_due_date',
            'due date': 'opdir_final_due_date',
            'due_date': 'opdir_final_due_date',
            'days to remediate': 'opdir_days_to_remediate',
            'days_to_remediate': 'opdir_days_to_remediate',
            'remediation days': 'opdir_days_to_remediate',
            'year': 'opdir_year',
        }

        opdir_df.columns = opdir_df.columns.str.lower().str.strip()
        opdir_df = opdir_df.rename(columns=column_mappings)

        # Parse dates
        for date_col in ['opdir_release_date', 'opdir_final_due_date']:
            if date_col in opdir_df.columns:
                opdir_df[date_col] = pd.to_datetime(opdir_df[date_col], errors='coerce')

        # Extract normalized number and year from OPDIR number
        if 'opdir_number' in opdir_df.columns:
            normalized_data = opdir_df['opdir_number'].apply(
                lambda x: normalize_opdir_number(x)
            )
            opdir_df['opdir_number_normalized'] = normalized_data.apply(lambda x: x[0])
            opdir_df['opdir_year_from_number'] = normalized_data.apply(lambda x: x[1])

            # If no explicit year column, infer from number or release date
            if 'opdir_year' not in opdir_df.columns:
                opdir_df['opdir_year'] = opdir_df['opdir_year_from_number']

                # Fill missing years from release date
                if 'opdir_release_date' in opdir_df.columns:
                    mask = opdir_df['opdir_year'].isna()
                    opdir_df.loc[mask, 'opdir_year'] = opdir_df.loc[mask, 'opdir_release_date'].dt.year

        # Create composite key for year-specific matching
        opdir_df['opdir_key'] = opdir_df.apply(
            lambda r: f"{r.get('opdir_year', '')}-{r.get('opdir_number_normalized', '')}"
            if pd.notna(r.get('opdir_year')) else r.get('opdir_number_normalized', ''),
            axis=1
        )

        print(f"Loaded {len(opdir_df)} OPDIR entries")
        if 'opdir_year' in opdir_df.columns:
            years = opdir_df['opdir_year'].dropna().unique()
            print(f"Years covered: {sorted([int(y) for y in years if pd.notna(y)])}")

        return opdir_df

    except Exception as e:
        print(f"Error loading OPDIR mapping: {e}")
        import traceback
        traceback.print_exc()
        return pd.DataFrame()


def create_opdir_lookup(opdir_df: pd.DataFrame) -> Dict[str, Any]:
    """
    Create optimized lookup dictionaries for OPDIR matching.

    Creates two lookup methods:
    1. Year-specific: '2025-b-0146' -> OPDIR data
    2. Number-only: 'b-0146' -> list of OPDIR data by year

    Args:
        opdir_df: OPDIR mapping DataFrame

    Returns:
        Dictionary with 'by_year' and 'by_number' lookups
    """
    lookup = {
        'by_year': {},      # '2025-b-0146' -> row
        'by_number': {},    # 'b-0146' -> [row1, row2] (multiple years)
    }

    if opdir_df.empty:
        return lookup

    for _, row in opdir_df.iterrows():
        normalized = row.get('opdir_number_normalized', '')
        year = row.get('opdir_year')

        if not normalized:
            continue

        # Year-specific lookup
        if pd.notna(year):
            key = f"{int(year)}-{normalized}"
            lookup['by_year'][key] = row.to_dict()

        # Number-only lookup (list for multiple years)
        if normalized not in lookup['by_number']:
            lookup['by_number'][normalized] = []
        lookup['by_number'][normalized].append(row.to_dict())

    return lookup


def match_opdir(opdir_info: Dict[str, Any], lookup: Dict[str, Any],
                reference_year: int = None) -> Optional[Dict[str, Any]]:
    """
    Find matching OPDIR entry using year-aware matching.

    Matching priority:
    1. Exact year match if year is known
    2. Reference year match if provided
    3. Most recent year entry for the number

    Args:
        opdir_info: Dict with 'number', 'year' from extract_opdir_from_iavx
        lookup: Lookup dict from create_opdir_lookup
        reference_year: Year to use as fallback

    Returns:
        Matching OPDIR row dict or None
    """
    normalized = opdir_info.get('number', '')
    year = opdir_info.get('year') or reference_year

    if not normalized:
        return None

    # Try year-specific match first
    if year:
        key = f"{int(year)}-{normalized}"
        if key in lookup['by_year']:
            return lookup['by_year'][key]

    # Fall back to number-only match
    if normalized in lookup['by_number']:
        entries = lookup['by_number'][normalized]
        if len(entries) == 1:
            return entries[0]

        # Multiple years - prefer the one closest to reference year
        if year:
            entries_with_year = [e for e in entries if pd.notna(e.get('opdir_year'))]
            if entries_with_year:
                # Sort by closeness to reference year
                entries_with_year.sort(key=lambda e: abs(int(e['opdir_year']) - year))
                return entries_with_year[0]

        # Return most recent if no reference year
        entries_with_year = [e for e in entries if pd.notna(e.get('opdir_year'))]
        if entries_with_year:
            entries_with_year.sort(key=lambda e: e.get('opdir_year', 0), reverse=True)
            return entries_with_year[0]

        # Last resort: return first entry
        return entries[0]

    return None


def enrich_with_opdir(lifecycle_df: pd.DataFrame, opdir_df: pd.DataFrame) -> pd.DataFrame:
    """
    Enrich finding lifecycle data with OPDIR information using year-aware matching.

    Args:
        lifecycle_df: DataFrame from analyze_finding_lifecycle
        opdir_df: DataFrame from load_opdir_mapping

    Returns:
        DataFrame with OPDIR enrichment
    """
    if lifecycle_df.empty:
        return lifecycle_df

    lifecycle_df = lifecycle_df.copy()

    # Initialize OPDIR columns
    opdir_columns = {
        'opdir_number': '',
        'opdir_year': np.nan,
        'opdir_subject': '',
        'opdir_release_date': pd.NaT,
        'opdir_final_due_date': pd.NaT,
        'opdir_days_to_remediate': np.nan,
        'opdir_status': '',
        'opdir_days_until_due': np.nan,
        'iavx_mapped': '',
        'iavx_year': np.nan,
    }

    for col, default in opdir_columns.items():
        lifecycle_df[col] = default

    if opdir_df.empty:
        return lifecycle_df

    # Create lookup
    lookup = create_opdir_lookup(opdir_df)

    # Process each finding
    for idx, row in lifecycle_df.iterrows():
        if not pd.notna(row.get('iavx')) or not row['iavx']:
            continue

        # Get reference year from scan or finding date
        reference_year = None
        for date_field in ['scan_date', 'first_seen', 'last_seen']:
            if pd.notna(row.get(date_field)):
                try:
                    dt = pd.to_datetime(row[date_field])
                    reference_year = dt.year
                    break
                except Exception:
                    pass

        if not reference_year:
            reference_year = datetime.now().year

        # Extract OPDIR info from IAVx
        opdir_list = extract_opdir_from_iavx(row['iavx'], reference_year)

        if not opdir_list:
            continue

        # Store all mapped references
        mapped_refs = [o['full'] for o in opdir_list]
        lifecycle_df.at[idx, 'iavx_mapped'] = ', '.join(mapped_refs)

        # Match against OPDIR file - use first successful match
        for opdir_info in opdir_list:
            matched = match_opdir(opdir_info, lookup, reference_year)
            if matched:
                lifecycle_df.at[idx, 'opdir_number'] = matched.get('opdir_number', opdir_info['full'])
                lifecycle_df.at[idx, 'opdir_year'] = matched.get('opdir_year', opdir_info.get('year'))
                lifecycle_df.at[idx, 'opdir_subject'] = matched.get('opdir_subject', '')
                lifecycle_df.at[idx, 'opdir_release_date'] = matched.get('opdir_release_date')
                lifecycle_df.at[idx, 'opdir_final_due_date'] = matched.get('opdir_final_due_date')
                lifecycle_df.at[idx, 'opdir_days_to_remediate'] = matched.get('opdir_days_to_remediate')
                lifecycle_df.at[idx, 'iavx_year'] = opdir_info.get('year')
                break
            else:
                # No match in file but we have the reference - store it anyway
                if not lifecycle_df.at[idx, 'opdir_number']:
                    lifecycle_df.at[idx, 'opdir_number'] = opdir_info['full']
                    lifecycle_df.at[idx, 'opdir_year'] = opdir_info.get('year')
                    lifecycle_df.at[idx, 'iavx_year'] = opdir_info.get('year')

    # Calculate compliance status
    lifecycle_df = calculate_opdir_compliance_status(lifecycle_df)

    return lifecycle_df


def calculate_opdir_compliance_status(lifecycle_df: pd.DataFrame) -> pd.DataFrame:
    """
    Calculate OPDIR compliance status for each finding.

    Status values:
    - Overdue: Past final due date
    - Due Soon: Within 14 days of due date
    - On Track: More than 14 days until due
    - N/A: No OPDIR mapping

    Args:
        lifecycle_df: DataFrame with OPDIR due dates

    Returns:
        DataFrame with compliance status
    """
    if lifecycle_df.empty:
        return lifecycle_df

    lifecycle_df = lifecycle_df.copy()
    today = datetime.now()

    for idx, row in lifecycle_df.iterrows():
        due_date = row.get('opdir_final_due_date')

        if pd.isna(due_date):
            lifecycle_df.at[idx, 'opdir_status'] = ''
            lifecycle_df.at[idx, 'opdir_days_until_due'] = np.nan
            continue

        due_date = pd.to_datetime(due_date)
        days_until_due = (due_date - today).days
        lifecycle_df.at[idx, 'opdir_days_until_due'] = days_until_due

        if days_until_due < 0:
            lifecycle_df.at[idx, 'opdir_status'] = 'Overdue'
        elif days_until_due <= 14:
            lifecycle_df.at[idx, 'opdir_status'] = 'Due Soon'
        else:
            lifecycle_df.at[idx, 'opdir_status'] = 'On Track'

    return lifecycle_df


def get_opdir_compliance_summary(lifecycle_df: pd.DataFrame) -> Dict[str, Any]:
    """
    Generate OPDIR compliance summary statistics.

    Args:
        lifecycle_df: DataFrame with OPDIR enrichment

    Returns:
        Dictionary with compliance summary
    """
    if lifecycle_df.empty:
        return {
            'total_findings': 0,
            'with_opdir': 0,
            'without_opdir': 0,
            'coverage_percentage': 0.0,
            'status_breakdown': {},
            'overdue_count': 0,
            'due_soon_count': 0,
            'on_track_count': 0,
            'by_year': {}
        }

    total = len(lifecycle_df)
    with_opdir = len(lifecycle_df[lifecycle_df['opdir_number'] != ''])
    without_opdir = total - with_opdir
    coverage = (with_opdir / total * 100) if total > 0 else 0.0

    status_counts = lifecycle_df[lifecycle_df['opdir_status'] != '']['opdir_status'].value_counts().to_dict()

    # Breakdown by year
    by_year = {}
    if 'opdir_year' in lifecycle_df.columns:
        year_groups = lifecycle_df[lifecycle_df['opdir_year'].notna()].groupby('opdir_year')
        for year, group in year_groups:
            by_year[int(year)] = {
                'count': len(group),
                'status': group['opdir_status'].value_counts().to_dict()
            }

    return {
        'total_findings': total,
        'with_opdir': with_opdir,
        'without_opdir': without_opdir,
        'coverage_percentage': round(coverage, 1),
        'status_breakdown': status_counts,
        'overdue_count': status_counts.get('Overdue', 0),
        'due_soon_count': status_counts.get('Due Soon', 0),
        'on_track_count': status_counts.get('On Track', 0),
        'by_year': by_year
    }


def get_overdue_findings(lifecycle_df: pd.DataFrame) -> pd.DataFrame:
    """
    Get findings that are past their OPDIR due date.

    Args:
        lifecycle_df: DataFrame with OPDIR enrichment

    Returns:
        DataFrame with overdue findings sorted by days overdue
    """
    if lifecycle_df.empty:
        return pd.DataFrame()

    overdue = lifecycle_df[lifecycle_df['opdir_status'] == 'Overdue'].copy()

    if not overdue.empty:
        overdue['days_overdue'] = -overdue['opdir_days_until_due']
        overdue = overdue.sort_values('days_overdue', ascending=False)

    return overdue


def get_opdir_by_year_report(lifecycle_df: pd.DataFrame) -> pd.DataFrame:
    """
    Generate a report of OPDIR coverage grouped by year.

    Args:
        lifecycle_df: DataFrame with OPDIR enrichment

    Returns:
        DataFrame with year-by-year OPDIR statistics
    """
    if lifecycle_df.empty or 'opdir_year' not in lifecycle_df.columns:
        return pd.DataFrame()

    # Filter to findings with OPDIR
    with_opdir = lifecycle_df[lifecycle_df['opdir_number'] != ''].copy()

    if with_opdir.empty:
        return pd.DataFrame()

    # Group by year
    report = with_opdir.groupby('opdir_year').agg({
        'plugin_id': 'count',
        'hostname': 'nunique',
        'opdir_status': lambda x: (x == 'Overdue').sum(),
    }).reset_index()

    report.columns = ['Year', 'Finding Count', 'Hosts Affected', 'Overdue Count']
    report['Year'] = report['Year'].astype(int)
    report = report.sort_values('Year', ascending=False)

    return report
