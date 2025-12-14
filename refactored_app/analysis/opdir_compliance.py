"""
OPDIR Compliance Analysis Module
Handles OPDIR mapping and compliance status tracking with year inference.

OPDIR File Format:
- OPDIR NUMBER: Format XXXX-YY where YY is year suffix (e.g., 0001-24 → 2024)
- IAVA/B: Can be full format (2024-B-0201) or suffix-only (B-0201)
- POA&M DUE DATE: Intermediate deadline
- FINAL DUE DATE: Final compliance deadline

Matching Strategy:
1. Full match: YYYY-A-NNNN (e.g., 2024-B-0201)
2. Suffix fallback: A-NNNN (e.g., B-0201) for findings without explicit year
"""

import pandas as pd
import numpy as np
import re
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any


def parse_opdir_number(opdir_str: str) -> Tuple[str, Optional[int]]:
    """
    Parse OPDIR NUMBER in format XXXX-YY to extract sequence and year.

    Format: XXXX-YY where YY is year suffix (e.g., 0001-24 → year 2024)

    Args:
        opdir_str: OPDIR number string (e.g., "0001-24", "0146-25")

    Returns:
        Tuple of (original_number, inferred_year)
    """
    if not opdir_str or pd.isna(opdir_str):
        return ('', None)

    opdir_str = str(opdir_str).strip()

    # Pattern: XXXX-YY where YY is 2-digit year suffix
    pattern = r'^(\d{4})-(\d{2})$'
    match = re.match(pattern, opdir_str)

    if match:
        seq = match.group(1)
        year_suffix = int(match.group(2))
        # Infer full year: 00-29 → 2000-2029, 30-99 → 1930-1999
        if year_suffix <= 29:
            full_year = 2000 + year_suffix
        else:
            full_year = 1900 + year_suffix
        return (opdir_str, full_year)

    # Return as-is if doesn't match expected format
    return (opdir_str, None)


def parse_iavab_reference(iavab_str: str, opdir_year: Optional[int] = None) -> Dict[str, Any]:
    """
    Parse IAVA/B reference column, enhancing suffix-only format with year.

    Formats handled:
    - Full format: 2024-B-0201 → {'full': '2024-B-0201', 'suffix': 'B-0201', 'year': 2024}
    - Suffix-only: B-0201 → {'full': 'YYYY-B-0201', 'suffix': 'B-0201', 'year': from OPDIR}

    Args:
        iavab_str: IAVA/B reference string
        opdir_year: Year from OPDIR NUMBER to use for suffix-only format

    Returns:
        Dict with 'full', 'suffix', 'year', 'type' (A, B, or T)
    """
    if not iavab_str or pd.isna(iavab_str):
        return {'full': '', 'suffix': '', 'year': None, 'type': ''}

    iavab_str = str(iavab_str).strip()

    # Try full format first: YYYY-X-NNNN
    full_pattern = r'^(\d{4})-([ABT])-(\d+)$'
    match = re.match(full_pattern, iavab_str, re.IGNORECASE)
    if match:
        year = int(match.group(1))
        type_letter = match.group(2).upper()
        number = match.group(3).zfill(4)
        suffix = f"{type_letter}-{number}"
        full = f"{year}-{type_letter}-{number}"
        return {'full': full, 'suffix': suffix, 'year': year, 'type': type_letter}

    # Try suffix-only format: X-NNNN
    suffix_pattern = r'^([ABT])-(\d+)$'
    match = re.match(suffix_pattern, iavab_str, re.IGNORECASE)
    if match:
        type_letter = match.group(1).upper()
        number = match.group(2).zfill(4)
        suffix = f"{type_letter}-{number}"
        # Use OPDIR year to enhance to full format
        if opdir_year:
            full = f"{opdir_year}-{type_letter}-{number}"
            return {'full': full, 'suffix': suffix, 'year': opdir_year, 'type': type_letter}
        else:
            return {'full': suffix, 'suffix': suffix, 'year': None, 'type': type_letter}

    # Try parsing just letters and numbers without hyphen: B0201
    compact_pattern = r'^([ABT])(\d+)$'
    match = re.match(compact_pattern, iavab_str, re.IGNORECASE)
    if match:
        type_letter = match.group(1).upper()
        number = match.group(2).zfill(4)
        suffix = f"{type_letter}-{number}"
        if opdir_year:
            full = f"{opdir_year}-{type_letter}-{number}"
            return {'full': full, 'suffix': suffix, 'year': opdir_year, 'type': type_letter}
        else:
            return {'full': suffix, 'suffix': suffix, 'year': None, 'type': type_letter}

    # Return as-is if doesn't match any pattern
    return {'full': iavab_str, 'suffix': iavab_str, 'year': opdir_year, 'type': ''}


def normalize_iavx_from_scan(iavx_string: str) -> List[Dict[str, Any]]:
    """
    Extract and normalize IAVX references from scan data (finding's iavx field).

    Scan data format examples:
    - IAVB:2025-B-0146
    - IAVA:2024-A-0073
    - IAVA:A-0073 (no year - needs lookup by suffix)

    Args:
        iavx_string: String containing IAVx references (newline-separated)

    Returns:
        List of dicts with 'full', 'suffix', 'year', 'type' keys
    """
    if not iavx_string or pd.isna(iavx_string):
        return []

    results = []

    # Pattern for full format with year: IAVX:YYYY-X-NNNN
    full_pattern = r'(IAVA|IAVB|IATM)[:\s]*(\d{4})-([ABT])-(\d+)'

    # Pattern for suffix-only: IAVX:X-NNNN
    suffix_pattern = r'(IAVA|IAVB|IATM)[:\s]*([ABT])-(\d+)'

    for line in str(iavx_string).split('\n'):
        line = line.strip()
        if not line:
            continue

        # Try full pattern first
        for match in re.finditer(full_pattern, line, re.IGNORECASE):
            year = int(match.group(2))
            type_letter = match.group(3).upper()
            number = match.group(4).zfill(4)
            suffix = f"{type_letter}-{number}"
            full = f"{year}-{type_letter}-{number}"

            results.append({
                'full': full,
                'suffix': suffix,
                'year': year,
                'type': type_letter,
                'iav_type': match.group(1).upper()
            })

        # Also try suffix pattern (only add if not already found via full pattern)
        for match in re.finditer(suffix_pattern, line, re.IGNORECASE):
            type_letter = match.group(2).upper()
            number = match.group(3).zfill(4)
            suffix = f"{type_letter}-{number}"

            # Check if already found with year
            if not any(r['suffix'] == suffix for r in results):
                results.append({
                    'full': suffix,  # No year known
                    'suffix': suffix,
                    'year': None,
                    'type': type_letter,
                    'iav_type': match.group(1).upper()
                })

    return results


def is_legend_or_empty_row(row: pd.Series) -> bool:
    """
    Check if a row is part of the legend or is effectively empty.

    Args:
        row: DataFrame row

    Returns:
        True if row should be skipped (legend or empty)
    """
    # Count non-null, non-empty values
    non_empty = 0
    for val in row:
        if pd.notna(val) and str(val).strip() != '':
            non_empty += 1

    # Skip if mostly empty (less than 2 meaningful values)
    if non_empty < 2:
        return True

    # Check for legend keywords in any cell
    legend_keywords = ['legend', 'note:', 'notes:', '*', '**']
    for val in row:
        if pd.notna(val):
            val_str = str(val).strip().lower()
            if any(kw in val_str for kw in legend_keywords):
                return True

    return False


def clean_opdir_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Clean OPDIR DataFrame by removing blank columns and legend rows.

    Args:
        df: Raw OPDIR DataFrame

    Returns:
        Cleaned DataFrame
    """
    if df.empty:
        return df

    # Remove completely empty columns
    df = df.dropna(axis=1, how='all')

    # Remove columns that are mostly empty (>90% null)
    threshold = len(df) * 0.9
    df = df.dropna(axis=1, thresh=int(len(df) - threshold))

    # Remove columns with 'Unnamed' in header (blank header columns)
    df = df.loc[:, ~df.columns.str.contains('unnamed', case=False, na=False)]

    # Remove legend/empty rows
    mask = ~df.apply(is_legend_or_empty_row, axis=1)
    df = df[mask].reset_index(drop=True)

    return df


def load_opdir_mapping(opdir_file: str) -> pd.DataFrame:
    """
    Load OPDIR mapping from Excel or CSV file with year extraction.

    Expected columns:
    - OPDIR NUMBER: Format XXXX-YY (e.g., 0001-24 for 2024)
    - IAVA/B: Can be full (2024-B-0201) or suffix-only (B-0201)
    - POA&M DUE DATE: Intermediate deadline
    - FINAL DUE DATE: Final compliance deadline

    Blank columns and legend rows at the end are automatically ignored.

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

        # Clean: remove blank columns and legend rows
        opdir_df = clean_opdir_dataframe(opdir_df)

        if opdir_df.empty:
            print("OPDIR file is empty after cleaning")
            return pd.DataFrame()

        # Standardize column names
        column_mappings = {
            'opdir number': 'opdir_number',
            'opdir_number': 'opdir_number',
            'opdir': 'opdir_number',
            'iava/b': 'iavab',
            'iava_b': 'iavab',
            'iavab': 'iavab',
            'iava': 'iavab',
            'iavb': 'iavab',
            'poa&m due date': 'poam_due_date',
            'poam due date': 'poam_due_date',
            'poam_due_date': 'poam_due_date',
            'final due date': 'final_due_date',
            'final_due_date': 'final_due_date',
            'due date': 'final_due_date',
            'due_date': 'final_due_date',
            'subject': 'subject',
            'title': 'subject',
            'release date': 'release_date',
            'release_date': 'release_date',
            'released': 'release_date',
        }

        opdir_df.columns = opdir_df.columns.str.lower().str.strip()
        opdir_df = opdir_df.rename(columns=column_mappings)

        # Parse dates
        for date_col in ['poam_due_date', 'final_due_date', 'release_date']:
            if date_col in opdir_df.columns:
                opdir_df[date_col] = pd.to_datetime(opdir_df[date_col], errors='coerce')

        # Parse OPDIR NUMBER to extract year
        if 'opdir_number' in opdir_df.columns:
            parsed = opdir_df['opdir_number'].apply(parse_opdir_number)
            opdir_df['opdir_number_raw'] = parsed.apply(lambda x: x[0])
            opdir_df['opdir_year'] = parsed.apply(lambda x: x[1])
        else:
            opdir_df['opdir_number_raw'] = ''
            opdir_df['opdir_year'] = None

        # Parse IAVA/B column - enhance suffix-only with year from OPDIR NUMBER
        if 'iavab' in opdir_df.columns:
            def parse_row_iavab(row):
                return parse_iavab_reference(row.get('iavab'), row.get('opdir_year'))

            parsed_iavab = opdir_df.apply(parse_row_iavab, axis=1)
            opdir_df['iavab_full'] = parsed_iavab.apply(lambda x: x['full'])
            opdir_df['iavab_suffix'] = parsed_iavab.apply(lambda x: x['suffix'])
            opdir_df['iavab_year'] = parsed_iavab.apply(lambda x: x['year'])
            opdir_df['iavab_type'] = parsed_iavab.apply(lambda x: x['type'])
        else:
            opdir_df['iavab_full'] = ''
            opdir_df['iavab_suffix'] = ''
            opdir_df['iavab_year'] = None
            opdir_df['iavab_type'] = ''

        print(f"Loaded {len(opdir_df)} OPDIR entries")
        if 'opdir_year' in opdir_df.columns:
            years = opdir_df['opdir_year'].dropna().unique()
            if len(years) > 0:
                print(f"Years covered: {sorted([int(y) for y in years if pd.notna(y)])}")

        # Debug: Check date columns
        for date_col in ['poam_due_date', 'final_due_date']:
            if date_col in opdir_df.columns:
                valid = opdir_df[date_col].notna()
                print(f"  Date column '{date_col}': {valid.sum()} valid out of {len(opdir_df)}")
                if valid.any():
                    print(f"    Sample dates: {opdir_df[date_col].dropna().head(3).tolist()}")
            else:
                print(f"  Date column '{date_col}': NOT FOUND")

        # Debug: show sample of parsed data
        if len(opdir_df) > 0:
            sample = opdir_df[['opdir_number_raw', 'opdir_year', 'iavab_full', 'iavab_suffix']].head(3)
            print(f"Sample parsed data:\n{sample.to_string()}")

        return opdir_df

    except Exception as e:
        print(f"Error loading OPDIR mapping: {e}")
        import traceback
        traceback.print_exc()
        return pd.DataFrame()


def create_opdir_lookup(opdir_df: pd.DataFrame) -> Dict[str, Any]:
    """
    Create optimized lookup dictionaries for OPDIR matching.

    Two-strategy lookup:
    1. by_full: Full match 'YYYY-X-NNNN' -> OPDIR data
    2. by_suffix: Suffix match 'X-NNNN' -> list of OPDIR data (may have multiple years)

    Handles both new format (from file) and legacy format (from existing database).

    Args:
        opdir_df: OPDIR mapping DataFrame

    Returns:
        Dictionary with 'by_full' and 'by_suffix' lookups
    """
    lookup = {
        'by_full': {},      # '2024-B-0201' -> row
        'by_suffix': {},    # 'B-0201' -> [row1, row2] (possibly multiple years)
    }

    if opdir_df.empty:
        return lookup

    # Clean: drop unnamed columns (blank columns from Excel import)
    unnamed_cols = [col for col in opdir_df.columns if 'unnamed' in str(col).lower()]
    if unnamed_cols:
        print(f"Dropping {len(unnamed_cols)} unnamed columns: {unnamed_cols}")
        opdir_df = opdir_df.drop(columns=unnamed_cols)

    # Check if we need to parse legacy format (database loaded without iavab columns)
    needs_parsing = 'iavab_full' not in opdir_df.columns and 'iavab_suffix' not in opdir_df.columns

    # Debug: print available columns
    print(f"OPDIR columns: {list(opdir_df.columns)}")

    # Debug: Check what values are in potential IAVA/B columns
    candidate_cols = ['iavab', 'iava_b', 'iava/b', 'iava', 'iavb', 'opdir_number_normalized']
    for col in candidate_cols:
        if col in opdir_df.columns:
            non_empty = opdir_df[col].notna() & (opdir_df[col].astype(str).str.strip() != '') & (opdir_df[col].astype(str).str.lower() != 'nan')
            print(f"  Column '{col}': {non_empty.sum()} non-empty values out of {len(opdir_df)}")

    rows_processed = 0
    rows_skipped = 0

    for _, row in opdir_df.iterrows():
        if needs_parsing:
            # Legacy format - try to get IAVA/B from various possible columns
            iavab_raw = None
            for col in candidate_cols:
                if col in row.index and pd.notna(row.get(col)) and row.get(col):
                    val = str(row.get(col)).strip()
                    if val and val.lower() != 'nan':
                        iavab_raw = val
                        break

            if not iavab_raw:
                # No IAVA/B found in legacy columns - skip this row
                rows_skipped += 1
                continue
            rows_processed += 1

            # Parse the IAVA/B reference
            opdir_year = row.get('opdir_year')
            if pd.isna(opdir_year):
                opdir_year = None
            parsed = parse_iavab_reference(iavab_raw, opdir_year)
            iavab_full = parsed['full']
            iavab_suffix = parsed['suffix']
        else:
            # New format - columns already exist
            iavab_full = row.get('iavab_full', '')
            iavab_suffix = row.get('iavab_suffix', '')

        if not iavab_suffix:
            continue

        row_dict = row.to_dict()
        # Add parsed values for consistency
        row_dict['iavab_full'] = iavab_full
        row_dict['iavab_suffix'] = iavab_suffix

        # Full lookup (year-specific)
        if iavab_full and iavab_full != iavab_suffix:  # Has year component
            key_full = iavab_full.upper()
            lookup['by_full'][key_full] = row_dict

        # Suffix lookup (for fallback matching)
        key_suffix = iavab_suffix.upper()
        if key_suffix not in lookup['by_suffix']:
            lookup['by_suffix'][key_suffix] = []
        lookup['by_suffix'][key_suffix].append(row_dict)

    if needs_parsing:
        print(f"OPDIR parsing: {rows_processed} rows processed, {rows_skipped} rows skipped (no IAVA/B data)")

    print(f"Created lookup: {len(lookup['by_full'])} full entries, {len(lookup['by_suffix'])} suffix entries")

    return lookup


def match_finding_to_opdir(iavx_refs: List[Dict], lookup: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Match finding's IAVX references to OPDIR using two-strategy lookup.

    Strategy:
    1. Try full match (YYYY-X-NNNN) first - most precise
    2. Fall back to suffix match (X-NNNN) if no full match
    3. For suffix matches with multiple years, prefer most recent

    Args:
        iavx_refs: List of parsed IAVX references from normalize_iavx_from_scan
        lookup: Lookup dict from create_opdir_lookup

    Returns:
        Matching OPDIR row dict or None
    """
    if not iavx_refs:
        return None

    # Try each reference
    for ref in iavx_refs:
        # Strategy 1: Full match (with year)
        if ref.get('year'):
            full_key = ref['full'].upper()
            if full_key in lookup['by_full']:
                return lookup['by_full'][full_key]

        # Strategy 2: Suffix fallback
        suffix_key = ref['suffix'].upper()
        if suffix_key in lookup['by_suffix']:
            entries = lookup['by_suffix'][suffix_key]

            if len(entries) == 1:
                return entries[0]

            # Multiple entries - prefer year match if available
            if ref.get('year'):
                for entry in entries:
                    if entry.get('iavab_year') == ref['year']:
                        return entry

            # Otherwise return most recent year
            entries_with_year = [e for e in entries if pd.notna(e.get('opdir_year'))]
            if entries_with_year:
                entries_with_year.sort(key=lambda e: e.get('opdir_year', 0), reverse=True)
                return entries_with_year[0]

            # Last resort: first entry
            return entries[0]

    return None


def enrich_with_opdir(lifecycle_df: pd.DataFrame, opdir_df: pd.DataFrame) -> pd.DataFrame:
    """
    Enrich finding lifecycle data with OPDIR information using two-strategy matching.

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
        'opdir_title': '',
        'opdir_poam_due_date': pd.NaT,
        'opdir_due_date': pd.NaT,
        'opdir_status': '',
        'opdir_days_until_due': np.nan,
        'iavx_matched': '',
    }

    for col, default in opdir_columns.items():
        lifecycle_df[col] = default

    if opdir_df.empty:
        print("No OPDIR data to enrich with")
        return lifecycle_df

    # Create lookup
    lookup = create_opdir_lookup(opdir_df)

    match_count = 0
    no_iavx_count = 0
    no_match_count = 0

    # Debug: Check if iavx column exists and has data
    if 'iavx' in lifecycle_df.columns:
        iavx_non_empty = lifecycle_df['iavx'].notna() & (lifecycle_df['iavx'] != '')
        print(f"Lifecycle has iavx column: {iavx_non_empty.sum()} findings with IAVX data out of {len(lifecycle_df)}")
    else:
        print("WARNING: Lifecycle data does not have 'iavx' column!")
        print(f"Available columns: {list(lifecycle_df.columns)}")

    # Process each finding
    for idx, row in lifecycle_df.iterrows():
        iavx = row.get('iavx')
        if not pd.notna(iavx) or not iavx:
            no_iavx_count += 1
            continue

        # Extract IAVX references from scan data
        iavx_refs = normalize_iavx_from_scan(iavx)

        if not iavx_refs:
            no_iavx_count += 1
            continue

        # Store extracted references for debugging
        lifecycle_df.at[idx, 'iavx_matched'] = ', '.join([r['full'] for r in iavx_refs])

        # Match against OPDIR
        matched = match_finding_to_opdir(iavx_refs, lookup)

        if matched:
            match_count += 1
            lifecycle_df.at[idx, 'opdir_number'] = matched.get('opdir_number_raw', '')
            lifecycle_df.at[idx, 'opdir_year'] = matched.get('opdir_year')
            lifecycle_df.at[idx, 'opdir_title'] = matched.get('subject', '')
            lifecycle_df.at[idx, 'opdir_poam_due_date'] = matched.get('poam_due_date')
            lifecycle_df.at[idx, 'opdir_due_date'] = matched.get('final_due_date')
        else:
            no_match_count += 1
            # Store the IAVX reference even without OPDIR match
            if iavx_refs:
                lifecycle_df.at[idx, 'opdir_number'] = iavx_refs[0].get('full', '')

    print(f"OPDIR enrichment: {match_count} matched, {no_match_count} unmatched, {no_iavx_count} no IAVX")

    # Debug: Check how many matched entries have valid due dates
    has_due_date = lifecycle_df['opdir_due_date'].notna()
    has_opdir_num = lifecycle_df['opdir_number'].notna() & (lifecycle_df['opdir_number'] != '')
    print(f"  Debug: {has_opdir_num.sum()} findings with opdir_number, {has_due_date.sum()} with due dates")

    # Calculate compliance status
    lifecycle_df = calculate_opdir_compliance_status(lifecycle_df)

    # Debug: Check status distribution
    if 'opdir_status' in lifecycle_df.columns:
        status_counts = lifecycle_df['opdir_status'].value_counts()
        print(f"  Status distribution: {status_counts.to_dict()}")

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
        due_date = row.get('opdir_due_date')

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


# Legacy function aliases for backward compatibility
def normalize_opdir_number(opdir_str: str, reference_year: int = None) -> Tuple[str, Optional[int]]:
    """Legacy alias for parse_opdir_number."""
    return parse_opdir_number(opdir_str)


def extract_opdir_from_iavx(iavx_string: str, reference_year: int = None) -> List[Dict[str, Any]]:
    """Legacy alias for normalize_iavx_from_scan with format conversion."""
    refs = normalize_iavx_from_scan(iavx_string)
    # Convert to legacy format
    return [{'number': r['suffix'].lower(), 'year': r['year'], 'full': r['full']} for r in refs]


def match_opdir(opdir_info: Dict[str, Any], lookup: Dict[str, Any],
                reference_year: int = None) -> Optional[Dict[str, Any]]:
    """Legacy alias for match_finding_to_opdir with format conversion."""
    # Convert old format to new format
    refs = [{
        'full': opdir_info.get('full', ''),
        'suffix': opdir_info.get('number', '').upper(),
        'year': opdir_info.get('year') or reference_year,
        'type': ''
    }]
    return match_finding_to_opdir(refs, lookup)
