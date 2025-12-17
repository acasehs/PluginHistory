"""
Data Processing and Enrichment Module
Handles CVSS scoring, severity mapping, finding enrichment, and data transformations.
"""

import pandas as pd
import numpy as np
from typing import Dict, List, Tuple, Any, Optional
import json

from ..config import CVSS_THRESHOLDS, SEVERITY_ORDER


# Nessus severity value to text mapping
NESSUS_SEVERITY_MAP = {
    '0': ('Info', 0),
    '1': ('Low', 1),
    '2': ('Medium', 2),
    '3': ('High', 3),
    '4': ('Critical', 4),
    0: ('Info', 0),
    1: ('Low', 1),
    2: ('Medium', 2),
    3: ('High', 3),
    4: ('Critical', 4),
}


def calculate_severity_from_cvss(cvss3_score: Optional[float], cvss2_score: Optional[float] = None,
                                  nessus_severity: Optional[str] = None) -> Tuple[str, int]:
    """
    Calculate severity text and numeric value from CVSS scores.
    Falls back to original Nessus severity if no CVSS scores available.

    Args:
        cvss3_score: CVSS v3 base score (preferred)
        cvss2_score: CVSS v2 base score (fallback)
        nessus_severity: Original Nessus severity value (0-4) as final fallback

    Returns:
        Tuple of (severity_text, severity_value)
    """
    score = cvss3_score if cvss3_score is not None else cvss2_score

    if score is None:
        # Fall back to Nessus severity if no CVSS score
        if nessus_severity is not None:
            return NESSUS_SEVERITY_MAP.get(nessus_severity, ('Info', 0))
        return "Info", 0

    try:
        score = float(score)

        if 9.0 <= score <= 10.0:
            return "Critical", 4
        elif 7.0 <= score < 9.0:
            return "High", 3
        elif 4.0 <= score < 7.0:
            return "Medium", 2
        elif 0.1 <= score < 4.0:
            return "Low", 1
        else:
            # Even with score of 0, fall back to Nessus severity
            if nessus_severity is not None:
                return NESSUS_SEVERITY_MAP.get(nessus_severity, ('Info', 0))
            return "Info", 0
    except (ValueError, TypeError):
        # Fall back to Nessus severity on error
        if nessus_severity is not None:
            return NESSUS_SEVERITY_MAP.get(nessus_severity, ('Info', 0))
        return "Info", 0


def enrich_findings_with_severity(df: pd.DataFrame, severity_overrides: Optional[Dict[str, str]] = None) -> pd.DataFrame:
    """
    Add severity calculations to findings DataFrame.

    Priority order:
    1. Plugin severity overrides (user-defined remapping)
    2. CVSS v3 score
    3. CVSS v2 score
    4. Original Nessus severity

    Args:
        df: Findings DataFrame
        severity_overrides: Optional dict mapping plugin_id to severity_text

    Returns:
        DataFrame with added severity columns
    """
    if df.empty:
        return df

    df = df.copy()

    # Convert CVSS scores to numeric
    df['cvss3_base_score_numeric'] = pd.to_numeric(df.get('cvss3_base_score'), errors='coerce')
    df['cvss2_base_score_numeric'] = pd.to_numeric(df.get('cvss2_base_score'), errors='coerce')

    # Get original Nessus severity column if present
    has_nessus_severity = 'severity' in df.columns

    # Calculate severity with fallback to Nessus severity
    def get_severity(row):
        nessus_sev = row.get('severity') if has_nessus_severity else None
        return calculate_severity_from_cvss(
            row['cvss3_base_score_numeric'],
            row['cvss2_base_score_numeric'],
            nessus_sev
        )

    severity_results = df.apply(get_severity, axis=1)

    df['severity_text'] = [result[0] for result in severity_results]
    df['severity_value'] = [result[1] for result in severity_results]

    # Apply plugin severity overrides (highest priority)
    if severity_overrides and 'plugin_id' in df.columns:
        severity_text_map = {
            'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Info': 0
        }
        for plugin_id, override_severity in severity_overrides.items():
            mask = df['plugin_id'].astype(str) == str(plugin_id)
            if mask.any():
                df.loc[mask, 'severity_text'] = override_severity
                df.loc[mask, 'severity_value'] = severity_text_map.get(override_severity, 0)

    return df


def create_severity_summary(df: pd.DataFrame, group_by: str = 'hostname') -> pd.DataFrame:
    """
    Create severity summary grouped by specified column.

    Args:
        df: Findings DataFrame with severity information
        group_by: Column to group by (default: 'hostname')

    Returns:
        DataFrame with severity counts by group
    """
    if df.empty:
        return pd.DataFrame()

    severity_summary = pd.crosstab(
        df[group_by],
        df['severity_text'],
        margins=True,
        margins_name='Total'
    )

    # Reorder columns by severity
    available_columns = [col for col in SEVERITY_ORDER + ['Total'] if col in severity_summary.columns]

    if available_columns:
        severity_summary = severity_summary[available_columns]

    return severity_summary


def create_age_distribution(df: pd.DataFrame, group_by: str = 'hostname') -> pd.DataFrame:
    """
    Create age distribution summary.

    Args:
        df: Findings DataFrame with age_bucket information
        group_by: Column to group by

    Returns:
        DataFrame with age distribution by group
    """
    if df.empty or 'age_bucket' not in df.columns:
        return pd.DataFrame()

    age_summary = pd.crosstab(
        df[group_by],
        df['age_bucket'],
        margins=True,
        margins_name='Total'
    )

    age_order = ['0-30', '31-60', '61-90', '91-120', '121+', 'Total']
    available_columns = [col for col in age_order if col in age_summary.columns]

    if available_columns:
        age_summary = age_summary[available_columns]

    return age_summary


def create_cve_summary(df: pd.DataFrame) -> pd.DataFrame:
    """
    Create summary of CVEs with host and plugin information.

    Args:
        df: Findings DataFrame

    Returns:
        DataFrame with CVE summary information
    """
    if df.empty:
        return pd.DataFrame()

    cve_findings = df[df['cves'].notna() & (df['cves'] != '')]

    if cve_findings.empty:
        return pd.DataFrame()

    cve_records = []

    for _, finding in cve_findings.iterrows():
        if finding['cves']:
            for cve in finding['cves'].split('\n'):
                cve = cve.strip()
                if cve:
                    cve_records.append({
                        'cve': cve,
                        'severity_text': finding.get('severity_text', 'Info'),
                        'severity_value': finding.get('severity_value', 0),
                        'cvss3_base_score': finding.get('cvss3_base_score'),
                        'hostname': finding.get('hostname', ''),
                        'plugin_id': finding.get('plugin_id', ''),
                        'plugin_name': finding.get('name', '')
                    })

    if not cve_records:
        return pd.DataFrame()

    cve_df = pd.DataFrame(cve_records)

    cve_summary = cve_df.groupby('cve').agg({
        'severity_value': 'max',
        'cvss3_base_score': 'first',
        'hostname': lambda x: list(set(x)),
        'plugin_id': lambda x: list(set(x)),
    }).reset_index()

    cve_summary['host_count'] = cve_summary['hostname'].apply(len)
    cve_summary['affected_hosts'] = cve_summary['hostname'].apply(lambda x: '\n'.join(sorted(x)))

    return cve_summary


def create_iavx_summary(df: pd.DataFrame) -> pd.DataFrame:
    """
    Create summary of IAVx references with host and plugin information.

    Args:
        df: Findings DataFrame

    Returns:
        DataFrame with IAVx summary information
    """
    if df.empty:
        return pd.DataFrame()

    iavx_findings = df[df['iavx'].notna() & (df['iavx'] != '')]

    if iavx_findings.empty:
        return pd.DataFrame()

    iavx_records = []

    for _, finding in iavx_findings.iterrows():
        if finding['iavx']:
            for iavx in finding['iavx'].split('\n'):
                iavx = iavx.strip()
                if iavx:
                    iavx_records.append({
                        'iavx': iavx,
                        'severity_text': finding.get('severity_text', 'Info'),
                        'severity_value': finding.get('severity_value', 0),
                        'hostname': finding.get('hostname', ''),
                        'plugin_id': finding.get('plugin_id', ''),
                    })

    if not iavx_records:
        return pd.DataFrame()

    iavx_df = pd.DataFrame(iavx_records)

    iavx_summary = iavx_df.groupby('iavx').agg({
        'severity_value': 'max',
        'hostname': lambda x: list(set(x)),
        'plugin_id': lambda x: list(set(x)),
    }).reset_index()

    iavx_summary['host_count'] = iavx_summary['hostname'].apply(len)
    iavx_summary['affected_hosts'] = iavx_summary['hostname'].apply(lambda x: '\n'.join(sorted(x)))

    return iavx_summary


def filter_by_severity(df: pd.DataFrame, include_info: bool = True) -> pd.DataFrame:
    """
    Filter DataFrame by severity level.

    Args:
        df: Input DataFrame with severity information
        include_info: Whether to include informational findings

    Returns:
        Filtered DataFrame
    """
    if df.empty or 'severity_text' not in df.columns:
        return df

    if include_info:
        return df
    else:
        return df[df['severity_text'] != 'Info']


def create_executive_summary(findings_df: pd.DataFrame, host_summary_df: pd.DataFrame) -> Dict[str, Any]:
    """
    Create executive summary statistics.

    Args:
        findings_df: Findings DataFrame
        host_summary_df: Host summary DataFrame

    Returns:
        Dictionary with summary statistics
    """
    summary = {
        'total_hosts': len(host_summary_df),
        'total_findings': len(findings_df),
        'credentialed_hosts': 0,
        'non_credentialed_hosts': 0,
        'severity_breakdown': {},
        'top_plugins': [],
        'top_cves': [],
    }

    if not host_summary_df.empty and 'proper_scan' in host_summary_df.columns:
        summary['credentialed_hosts'] = len(host_summary_df[host_summary_df['proper_scan'] == 'Yes'])
        summary['non_credentialed_hosts'] = len(host_summary_df[host_summary_df['proper_scan'] == 'No'])

    if not findings_df.empty and 'severity_text' in findings_df.columns:
        summary['severity_breakdown'] = findings_df['severity_text'].value_counts().to_dict()

        if 'plugin_id' in findings_df.columns and 'name' in findings_df.columns:
            top_plugins = findings_df.groupby(['plugin_id', 'name']).size().reset_index(name='count')
            top_plugins = top_plugins.sort_values('count', ascending=False).head(10)
            summary['top_plugins'] = top_plugins.to_dict('records')

    return summary
