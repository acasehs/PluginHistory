"""
Host Presence Analysis Module
Tracks host presence across multiple scans.
"""

import pandas as pd
import numpy as np
from datetime import datetime
from typing import Dict, List, Tuple, Optional


def create_host_presence_analysis(historical_df: pd.DataFrame) -> pd.DataFrame:
    """
    Analyze host presence across scans.

    Args:
        historical_df: DataFrame with historical findings. Must have columns:
                       hostname, ip_address, scan_date

    Returns:
        DataFrame with host presence analysis
    """
    if historical_df.empty:
        return pd.DataFrame()

    historical_df = historical_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(historical_df['scan_date']):
        historical_df['scan_date'] = pd.to_datetime(historical_df['scan_date'])

    scan_dates = sorted(historical_df['scan_date'].unique())
    total_scans = len(scan_dates)
    latest_scan = max(scan_dates)

    # Get unique hosts
    all_hosts = historical_df.groupby(['hostname', 'ip_address']).size().reset_index(name='count')
    presence_records = []

    for _, host_row in all_hosts.iterrows():
        hostname = host_row['hostname']
        ip_address = host_row['ip_address']

        # Get scan dates for this host
        host_scans = historical_df[
            (historical_df['hostname'] == hostname) &
            (historical_df['ip_address'] == ip_address)
        ]['scan_date'].unique()

        first_seen = min(host_scans)
        last_seen = max(host_scans)
        present_scans = len(host_scans)
        missing_scans = total_scans - present_scans
        presence_percentage = (present_scans / total_scans) * 100 if total_scans > 0 else 0

        # Determine status
        status = 'Active' if last_seen == latest_scan else 'Missing'

        # Find missing scan dates
        missing_dates = sorted(set(scan_dates) - set(host_scans))
        missing_dates_str = ', '.join([d.strftime('%Y-%m-%d') for d in missing_dates]) if missing_dates else ''

        presence_records.append({
            'hostname': hostname,
            'ip_address': ip_address,
            'first_seen': first_seen,
            'last_seen': last_seen,
            'total_scans_available': total_scans,
            'scans_present': present_scans,
            'scans_missing': missing_scans,
            'presence_percentage': round(presence_percentage, 1),
            'status': status,
            'missing_scan_dates': missing_dates_str
        })

    presence_df = pd.DataFrame(presence_records)

    # Sort by status and presence percentage
    presence_df = presence_df.sort_values(
        ['status', 'presence_percentage'],
        ascending=[True, False]
    )

    return presence_df


def identify_missing_hosts(presence_df: pd.DataFrame, threshold_days: int = 30) -> pd.DataFrame:
    """
    Identify hosts that have been missing from recent scans.

    Args:
        presence_df: DataFrame from create_host_presence_analysis
        threshold_days: Number of days since last seen to consider "missing"

    Returns:
        DataFrame with missing hosts
    """
    if presence_df.empty:
        return pd.DataFrame()

    presence_df = presence_df.copy()

    # Calculate days since last seen
    now = datetime.now()
    presence_df['days_since_seen'] = (now - pd.to_datetime(presence_df['last_seen'])).dt.days

    missing = presence_df[presence_df['days_since_seen'] > threshold_days]

    return missing.sort_values('days_since_seen', ascending=False)


def identify_unreliable_hosts(presence_df: pd.DataFrame, threshold_percentage: float = 75.0) -> pd.DataFrame:
    """
    Identify hosts with unreliable scan coverage.

    Args:
        presence_df: DataFrame from create_host_presence_analysis
        threshold_percentage: Minimum presence percentage for reliability

    Returns:
        DataFrame with unreliable hosts
    """
    if presence_df.empty:
        return pd.DataFrame()

    unreliable = presence_df[presence_df['presence_percentage'] < threshold_percentage]

    return unreliable.sort_values('presence_percentage', ascending=True)


def calculate_scan_coverage(presence_df: pd.DataFrame) -> Dict[str, float]:
    """
    Calculate overall scan coverage statistics.

    Args:
        presence_df: DataFrame from create_host_presence_analysis

    Returns:
        Dictionary with coverage statistics
    """
    if presence_df.empty:
        return {
            'total_hosts': 0,
            'active_hosts': 0,
            'missing_hosts': 0,
            'avg_presence_percentage': 0.0,
            'reliable_hosts': 0,
            'unreliable_hosts': 0
        }

    total = len(presence_df)
    active = len(presence_df[presence_df['status'] == 'Active'])
    missing = len(presence_df[presence_df['status'] == 'Missing'])
    avg_presence = presence_df['presence_percentage'].mean()
    reliable = len(presence_df[presence_df['presence_percentage'] >= 75.0])
    unreliable = len(presence_df[presence_df['presence_percentage'] < 75.0])

    return {
        'total_hosts': total,
        'active_hosts': active,
        'missing_hosts': missing,
        'avg_presence_percentage': round(avg_presence, 1),
        'reliable_hosts': reliable,
        'unreliable_hosts': unreliable,
        'active_percentage': round((active / total) * 100, 1) if total > 0 else 0.0
    }


def get_host_counts_by_scan(historical_df: pd.DataFrame) -> pd.DataFrame:
    """
    Get host counts per scan date.

    Args:
        historical_df: DataFrame with historical findings

    Returns:
        DataFrame with host counts per scan date
    """
    if historical_df.empty:
        return pd.DataFrame()

    historical_df = historical_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(historical_df['scan_date']):
        historical_df['scan_date'] = pd.to_datetime(historical_df['scan_date'])

    host_counts = historical_df.groupby('scan_date')['hostname'].nunique().reset_index()
    host_counts.columns = ['scan_date', 'host_count']

    return host_counts.sort_values('scan_date')


def identify_new_hosts(historical_df: pd.DataFrame) -> pd.DataFrame:
    """
    Identify hosts that first appeared in the most recent scan.

    Args:
        historical_df: DataFrame with historical findings

    Returns:
        DataFrame with new hosts
    """
    if historical_df.empty:
        return pd.DataFrame()

    historical_df = historical_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(historical_df['scan_date']):
        historical_df['scan_date'] = pd.to_datetime(historical_df['scan_date'])

    latest_scan = historical_df['scan_date'].max()

    # Get first seen date for each host
    first_seen = historical_df.groupby('hostname')['scan_date'].min().reset_index()
    first_seen.columns = ['hostname', 'first_seen']

    # Filter to hosts first seen in latest scan
    new_hosts = first_seen[first_seen['first_seen'] == latest_scan]

    return new_hosts
