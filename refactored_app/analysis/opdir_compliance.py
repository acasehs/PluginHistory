"""
OPDIR Compliance Analysis Module
Handles OPDIR mapping and compliance status tracking.
"""

import pandas as pd
import numpy as np
import re
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any


def load_opdir_mapping(opdir_file: str) -> pd.DataFrame:
    """
    Load OPDIR mapping from Excel or CSV file.

    Expected columns (case-insensitive):
    - OPDIR Number (e.g., 'B-0146')
    - Subject
    - Release Date
    - Final Due Date
    - Days to Remediate

    Args:
        opdir_file: Path to OPDIR mapping file (xlsx, xls, or csv)

    Returns:
        DataFrame with OPDIR mapping data
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
        }

        opdir_df.columns = opdir_df.columns.str.lower().str.strip()
        opdir_df = opdir_df.rename(columns=column_mappings)

        # Parse dates
        for date_col in ['opdir_release_date', 'opdir_final_due_date']:
            if date_col in opdir_df.columns:
                opdir_df[date_col] = pd.to_datetime(opdir_df[date_col], errors='coerce')

        # Normalize OPDIR numbers (convert to lowercase for matching)
        if 'opdir_number' in opdir_df.columns:
            opdir_df['opdir_number_normalized'] = opdir_df['opdir_number'].str.lower().str.strip()

        print(f"Loaded {len(opdir_df)} OPDIR entries")
        return opdir_df

    except Exception as e:
        print(f"Error loading OPDIR mapping: {e}")
        return pd.DataFrame()


def extract_opdir_from_iavx(iavx_string: str) -> List[str]:
    """
    Extract OPDIR numbers from IAVx references.

    Converts formats like:
    - IAVB:2025-B-0146 -> b-0146
    - IAVA:2024-A-0073 -> a-0073
    - IATM:2023-T-0001 -> t-0001

    Args:
        iavx_string: String containing IAVx references (newline-separated)

    Returns:
        List of normalized OPDIR numbers
    """
    if not iavx_string or pd.isna(iavx_string):
        return []

    opdir_numbers = []

    # Pattern to match IAV references
    patterns = [
        r'IAVB:?\s*\d{4}-?B-?(\d+)',
        r'IAVA:?\s*\d{4}-?A-?(\d+)',
        r'IATM:?\s*\d{4}-?T-?(\d+)',
    ]

    for line in str(iavx_string).split('\n'):
        line = line.strip()

        for i, pattern in enumerate(patterns):
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                num = match.group(1).zfill(4)
                prefix = ['b', 'a', 't'][i]
                opdir_numbers.append(f"{prefix}-{num}")

    return opdir_numbers


def enrich_with_opdir(lifecycle_df: pd.DataFrame, opdir_df: pd.DataFrame) -> pd.DataFrame:
    """
    Enrich finding lifecycle data with OPDIR information.

    Args:
        lifecycle_df: DataFrame from analyze_finding_lifecycle
        opdir_df: DataFrame from load_opdir_mapping

    Returns:
        DataFrame with OPDIR enrichment
    """
    if lifecycle_df.empty:
        return lifecycle_df

    if opdir_df.empty:
        # Add empty OPDIR columns
        lifecycle_df = lifecycle_df.copy()
        lifecycle_df['opdir_number'] = ''
        lifecycle_df['opdir_subject'] = ''
        lifecycle_df['opdir_release_date'] = pd.NaT
        lifecycle_df['opdir_final_due_date'] = pd.NaT
        lifecycle_df['opdir_status'] = ''
        lifecycle_df['opdir_days_until_due'] = np.nan
        return lifecycle_df

    lifecycle_df = lifecycle_df.copy()

    # Initialize OPDIR columns
    lifecycle_df['opdir_number'] = ''
    lifecycle_df['opdir_subject'] = ''
    lifecycle_df['opdir_release_date'] = pd.NaT
    lifecycle_df['opdir_final_due_date'] = pd.NaT
    lifecycle_df['opdir_days_to_remediate'] = np.nan
    lifecycle_df['opdir_status'] = ''
    lifecycle_df['opdir_days_until_due'] = np.nan
    lifecycle_df['iavx_mapped'] = ''

    # Create OPDIR lookup
    opdir_lookup = {}
    if 'opdir_number_normalized' in opdir_df.columns:
        for _, row in opdir_df.iterrows():
            key = row['opdir_number_normalized']
            opdir_lookup[key] = row

    # Map IAVx to OPDIR
    for idx, row in lifecycle_df.iterrows():
        if pd.notna(row.get('iavx')) and row['iavx']:
            opdirs = extract_opdir_from_iavx(row['iavx'])

            if opdirs:
                lifecycle_df.at[idx, 'iavx_mapped'] = ', '.join(opdirs)

                # Use first matching OPDIR
                for opdir in opdirs:
                    if opdir in opdir_lookup:
                        opdir_data = opdir_lookup[opdir]
                        lifecycle_df.at[idx, 'opdir_number'] = opdir_data.get('opdir_number', opdir)
                        lifecycle_df.at[idx, 'opdir_subject'] = opdir_data.get('opdir_subject', '')
                        lifecycle_df.at[idx, 'opdir_release_date'] = opdir_data.get('opdir_release_date')
                        lifecycle_df.at[idx, 'opdir_final_due_date'] = opdir_data.get('opdir_final_due_date')
                        lifecycle_df.at[idx, 'opdir_days_to_remediate'] = opdir_data.get('opdir_days_to_remediate')
                        break

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
            'on_track_count': 0
        }

    total = len(lifecycle_df)
    with_opdir = len(lifecycle_df[lifecycle_df['opdir_number'] != ''])
    without_opdir = total - with_opdir
    coverage = (with_opdir / total * 100) if total > 0 else 0.0

    status_counts = lifecycle_df[lifecycle_df['opdir_status'] != '']['opdir_status'].value_counts().to_dict()

    return {
        'total_findings': total,
        'with_opdir': with_opdir,
        'without_opdir': without_opdir,
        'coverage_percentage': round(coverage, 1),
        'status_breakdown': status_counts,
        'overdue_count': status_counts.get('Overdue', 0),
        'due_soon_count': status_counts.get('Due Soon', 0),
        'on_track_count': status_counts.get('On Track', 0)
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
