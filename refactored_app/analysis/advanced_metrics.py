"""
Advanced Vulnerability Management Metrics
Industry best-practice metrics for vulnerability lifecycle management.
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple


def calculate_reopen_rate(lifecycle_df: pd.DataFrame) -> Dict[str, Any]:
    """
    Calculate vulnerability reopen/recurrence rate.

    Tracks how often fixed vulnerabilities reappear - indicates patch quality issues.

    Args:
        lifecycle_df: DataFrame from analyze_finding_lifecycle with 'reappearances' column

    Returns:
        Dictionary with reopen metrics
    """
    if lifecycle_df.empty or 'reappearances' not in lifecycle_df.columns:
        return {
            'total_findings': 0,
            'findings_with_reappearances': 0,
            'reopen_rate_pct': 0.0,
            'total_reappearances': 0,
            'avg_reappearances': 0.0,
            'by_severity': {}
        }

    total = len(lifecycle_df)
    with_reappearances = len(lifecycle_df[lifecycle_df['reappearances'] > 0])
    total_reappearances = lifecycle_df['reappearances'].sum()

    # By severity breakdown
    by_severity = {}
    if 'severity_text' in lifecycle_df.columns:
        for sev in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            sev_df = lifecycle_df[lifecycle_df['severity_text'] == sev]
            if len(sev_df) > 0:
                reopen_count = len(sev_df[sev_df['reappearances'] > 0])
                by_severity[sev] = {
                    'total': len(sev_df),
                    'reopened': reopen_count,
                    'rate_pct': round(reopen_count / len(sev_df) * 100, 1) if len(sev_df) > 0 else 0
                }

    return {
        'total_findings': total,
        'findings_with_reappearances': with_reappearances,
        'reopen_rate_pct': round(with_reappearances / total * 100, 1) if total > 0 else 0.0,
        'total_reappearances': int(total_reappearances),
        'avg_reappearances': round(total_reappearances / total, 2) if total > 0 else 0.0,
        'by_severity': by_severity
    }


def calculate_coverage_metrics(historical_df: pd.DataFrame,
                                expected_hosts: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Calculate scan coverage metrics.

    Measures % of assets scanned and scan frequency per asset.

    Args:
        historical_df: Historical findings DataFrame with scan_date and hostname
        expected_hosts: Optional list of expected hostnames for coverage calculation

    Returns:
        Dictionary with coverage metrics
    """
    if historical_df.empty:
        return {
            'total_scans': 0,
            'unique_hosts_scanned': 0,
            'coverage_pct': 0.0,
            'avg_scans_per_host': 0.0,
            'scan_frequency': {},
            'hosts_by_scan_count': {}
        }

    # Ensure scan_date is datetime
    df = historical_df.copy()
    if 'scan_date' in df.columns:
        df['scan_date'] = pd.to_datetime(df['scan_date'])

    total_scans = df['scan_date'].nunique() if 'scan_date' in df.columns else 0
    unique_hosts = df['hostname'].nunique() if 'hostname' in df.columns else 0

    # Calculate coverage if expected hosts provided
    coverage_pct = 100.0
    if expected_hosts:
        scanned_hosts = set(df['hostname'].unique())
        expected_set = set(expected_hosts)
        covered = len(scanned_hosts.intersection(expected_set))
        coverage_pct = round(covered / len(expected_set) * 100, 1) if expected_set else 100.0

    # Scan frequency per host
    scan_frequency = {}
    if 'hostname' in df.columns and 'scan_date' in df.columns:
        host_scans = df.groupby('hostname')['scan_date'].nunique()
        scan_frequency = {
            'min': int(host_scans.min()),
            'max': int(host_scans.max()),
            'avg': round(host_scans.mean(), 1),
            'median': round(host_scans.median(), 1)
        }

    # Hosts by scan count buckets
    hosts_by_scan_count = {}
    if 'hostname' in df.columns and 'scan_date' in df.columns:
        host_scans = df.groupby('hostname')['scan_date'].nunique()
        buckets = [(1, 1, '1 scan'), (2, 5, '2-5 scans'), (6, 10, '6-10 scans'), (11, float('inf'), '11+ scans')]
        for low, high, label in buckets:
            count = len(host_scans[(host_scans >= low) & (host_scans <= high)])
            hosts_by_scan_count[label] = count

    return {
        'total_scans': total_scans,
        'unique_hosts_scanned': unique_hosts,
        'coverage_pct': coverage_pct,
        'avg_scans_per_host': round(total_scans / unique_hosts, 1) if unique_hosts > 0 else 0.0,
        'scan_frequency': scan_frequency,
        'hosts_by_scan_count': hosts_by_scan_count
    }


def calculate_mttd(historical_df: pd.DataFrame, lifecycle_df: pd.DataFrame) -> Dict[str, Any]:
    """
    Calculate Mean Time to Detect (MTTD) / Exposure Window.

    Estimates how long vulnerabilities exist before detection.
    Uses vuln_publication_date vs first_seen as proxy.

    Args:
        historical_df: Historical findings with vuln_publication_date
        lifecycle_df: Lifecycle DataFrame with first_seen dates

    Returns:
        Dictionary with MTTD metrics
    """
    if lifecycle_df.empty:
        return {
            'avg_mttd_days': None,
            'median_mttd_days': None,
            'findings_with_pub_date': 0,
            'by_severity': {}
        }

    # Try to join vuln_publication_date from historical data
    df = lifecycle_df.copy()

    # If we have vuln_publication_date, calculate actual MTTD
    if 'vuln_publication_date' in historical_df.columns:
        pub_dates = historical_df.groupby(['hostname', 'plugin_id'])['vuln_publication_date'].first().reset_index()
        df = df.merge(pub_dates, on=['hostname', 'plugin_id'], how='left')

        df['first_seen'] = pd.to_datetime(df['first_seen'])
        df['vuln_publication_date'] = pd.to_datetime(df['vuln_publication_date'], errors='coerce')

        df['mttd_days'] = (df['first_seen'] - df['vuln_publication_date']).dt.days
        valid_mttd = df[df['mttd_days'].notna() & (df['mttd_days'] >= 0)]

        if len(valid_mttd) > 0:
            by_severity = {}
            if 'severity_text' in valid_mttd.columns:
                for sev in ['Critical', 'High', 'Medium', 'Low']:
                    sev_df = valid_mttd[valid_mttd['severity_text'] == sev]
                    if len(sev_df) > 0:
                        by_severity[sev] = {
                            'avg_days': round(sev_df['mttd_days'].mean(), 1),
                            'median_days': round(sev_df['mttd_days'].median(), 1),
                            'count': len(sev_df)
                        }

            return {
                'avg_mttd_days': round(valid_mttd['mttd_days'].mean(), 1),
                'median_mttd_days': round(valid_mttd['mttd_days'].median(), 1),
                'findings_with_pub_date': len(valid_mttd),
                'by_severity': by_severity
            }

    return {
        'avg_mttd_days': None,
        'median_mttd_days': None,
        'findings_with_pub_date': 0,
        'by_severity': {},
        'note': 'No vuln_publication_date data available'
    }


def calculate_risk_reduction_trend(historical_df: pd.DataFrame) -> pd.DataFrame:
    """
    Calculate risk reduction trend over time.

    Shows overall risk score trend (not just counts).

    Args:
        historical_df: Historical findings with scan_date and severity_value

    Returns:
        DataFrame with risk score trend by scan date
    """
    if historical_df.empty or 'scan_date' not in historical_df.columns:
        return pd.DataFrame()

    df = historical_df.copy()
    df['scan_date'] = pd.to_datetime(df['scan_date'])

    # Ensure severity_value exists
    if 'severity_value' not in df.columns:
        severity_map = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Info': 0}
        if 'severity_text' in df.columns:
            df['severity_value'] = df['severity_text'].map(severity_map).fillna(0)
        else:
            df['severity_value'] = 0

    # Calculate risk metrics per scan
    risk_trend = df.groupby('scan_date').agg({
        'severity_value': ['sum', 'mean', 'count'],
        'hostname': 'nunique'
    }).reset_index()

    risk_trend.columns = ['scan_date', 'total_risk_score', 'avg_severity', 'finding_count', 'host_count']

    # Add normalized risk (per host)
    risk_trend['risk_per_host'] = risk_trend['total_risk_score'] / risk_trend['host_count']
    risk_trend['risk_per_host'] = risk_trend['risk_per_host'].round(2)

    # Calculate trend direction
    if len(risk_trend) > 1:
        risk_trend['risk_change'] = risk_trend['total_risk_score'].diff()
        risk_trend['risk_change_pct'] = risk_trend['total_risk_score'].pct_change() * 100

    return risk_trend.sort_values('scan_date')


def calculate_remediation_rate(lifecycle_df: pd.DataFrame,
                                historical_df: pd.DataFrame) -> Dict[str, Any]:
    """
    Calculate remediation rate / velocity.

    Formula: (Fixed vulns / Discovered vulns) × 100
    Indicates if you're gaining or losing ground.

    Args:
        lifecycle_df: Lifecycle DataFrame with status
        historical_df: Historical findings with scan dates

    Returns:
        Dictionary with remediation rate metrics
    """
    if lifecycle_df.empty:
        return {
            'total_discovered': 0,
            'total_remediated': 0,
            'remediation_rate_pct': 0.0,
            'net_position': 'neutral',
            'by_severity': {}
        }

    total_discovered = len(lifecycle_df)
    total_remediated = len(lifecycle_df[lifecycle_df['status'] == 'Resolved'])
    active = len(lifecycle_df[lifecycle_df['status'] == 'Active'])

    rate = round(total_remediated / total_discovered * 100, 1) if total_discovered > 0 else 0.0

    # Determine net position
    if rate >= 80:
        net_position = 'gaining_ground'
    elif rate >= 50:
        net_position = 'holding_steady'
    else:
        net_position = 'losing_ground'

    # By severity
    by_severity = {}
    if 'severity_text' in lifecycle_df.columns:
        for sev in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            sev_df = lifecycle_df[lifecycle_df['severity_text'] == sev]
            if len(sev_df) > 0:
                resolved = len(sev_df[sev_df['status'] == 'Resolved'])
                by_severity[sev] = {
                    'discovered': len(sev_df),
                    'remediated': resolved,
                    'active': len(sev_df) - resolved,
                    'rate_pct': round(resolved / len(sev_df) * 100, 1)
                }

    return {
        'total_discovered': total_discovered,
        'total_remediated': total_remediated,
        'total_active': active,
        'remediation_rate_pct': rate,
        'net_position': net_position,
        'by_severity': by_severity
    }


def calculate_sla_breach_tracking(lifecycle_df: pd.DataFrame,
                                   sla_targets: Dict[str, int]) -> Dict[str, Any]:
    """
    Calculate SLA breach and escalation tracking.

    Not just compliance %, but trend of breaches and escalation patterns.

    Args:
        lifecycle_df: Lifecycle DataFrame with days_open and severity_text
        sla_targets: SLA targets by severity in days

    Returns:
        Dictionary with SLA breach metrics
    """
    if lifecycle_df.empty:
        return {
            'total_findings': 0,
            'with_sla': 0,
            'breached': 0,
            'breach_rate_pct': 0.0,
            'by_severity': {},
            'breach_severity_distribution': {}
        }

    df = lifecycle_df.copy()

    # Calculate SLA status for each finding
    def get_sla_status(row):
        severity = row.get('severity_text', 'Info')
        days_open = row.get('days_open', 0)
        target = sla_targets.get(severity)

        if target is None:
            return 'no_sla', 0, None

        days_remaining = target - days_open
        if days_remaining < 0:
            return 'breached', days_remaining, target
        elif days_remaining <= target * 0.25:  # Within 25% of SLA
            return 'at_risk', days_remaining, target
        else:
            return 'on_track', days_remaining, target

    df['sla_status'], df['days_remaining'], df['sla_target'] = zip(*df.apply(get_sla_status, axis=1))

    with_sla = df[df['sla_status'] != 'no_sla']
    breached = df[df['sla_status'] == 'breached']
    at_risk = df[df['sla_status'] == 'at_risk']

    # By severity breakdown
    by_severity = {}
    for sev in ['Critical', 'High', 'Medium', 'Low']:
        sev_df = with_sla[with_sla['severity_text'] == sev]
        if len(sev_df) > 0:
            breached_count = len(sev_df[sev_df['sla_status'] == 'breached'])
            at_risk_count = len(sev_df[sev_df['sla_status'] == 'at_risk'])
            by_severity[sev] = {
                'total': len(sev_df),
                'breached': breached_count,
                'at_risk': at_risk_count,
                'on_track': len(sev_df) - breached_count - at_risk_count,
                'breach_rate_pct': round(breached_count / len(sev_df) * 100, 1)
            }

    # Breach severity distribution (what severity are the breaches)
    breach_distribution = {}
    if len(breached) > 0 and 'severity_text' in breached.columns:
        breach_distribution = breached['severity_text'].value_counts().to_dict()

    return {
        'total_findings': len(df),
        'with_sla': len(with_sla),
        'breached': len(breached),
        'at_risk': len(at_risk),
        'on_track': len(with_sla) - len(breached) - len(at_risk),
        'breach_rate_pct': round(len(breached) / len(with_sla) * 100, 1) if len(with_sla) > 0 else 0.0,
        'by_severity': by_severity,
        'breach_severity_distribution': breach_distribution
    }


def calculate_normalized_metrics(historical_df: pd.DataFrame,
                                  lifecycle_df: pd.DataFrame) -> Dict[str, Any]:
    """
    Calculate normalized metrics (per asset).

    Ratios like vulns-per-host to account for environment growth.

    Args:
        historical_df: Historical findings DataFrame
        lifecycle_df: Lifecycle DataFrame

    Returns:
        Dictionary with normalized metrics
    """
    if historical_df.empty:
        return {
            'vulns_per_host': 0.0,
            'critical_per_host': 0.0,
            'high_per_host': 0.0,
            'active_per_host': 0.0,
            'risk_score_per_host': 0.0,
            'trend': []
        }

    df = historical_df.copy()
    df['scan_date'] = pd.to_datetime(df['scan_date'])

    # Latest scan metrics
    latest_scan = df['scan_date'].max()
    latest_data = df[df['scan_date'] == latest_scan]

    unique_hosts = latest_data['hostname'].nunique()
    total_findings = len(latest_data)

    # Severity breakdown
    critical_count = len(latest_data[latest_data['severity_text'] == 'Critical']) if 'severity_text' in latest_data.columns else 0
    high_count = len(latest_data[latest_data['severity_text'] == 'High']) if 'severity_text' in latest_data.columns else 0

    # Active findings per host (from lifecycle)
    active_count = 0
    if not lifecycle_df.empty and 'status' in lifecycle_df.columns:
        active_count = len(lifecycle_df[lifecycle_df['status'] == 'Active'])

    # Risk score
    risk_score = 0
    if 'severity_value' in latest_data.columns:
        risk_score = latest_data['severity_value'].sum()

    # Trend over time
    trend = []
    for scan_date in sorted(df['scan_date'].unique()):
        scan_data = df[df['scan_date'] == scan_date]
        hosts = scan_data['hostname'].nunique()
        findings = len(scan_data)
        trend.append({
            'scan_date': scan_date.strftime('%Y-%m-%d'),
            'hosts': hosts,
            'findings': findings,
            'vulns_per_host': round(findings / hosts, 2) if hosts > 0 else 0
        })

    return {
        'vulns_per_host': round(total_findings / unique_hosts, 2) if unique_hosts > 0 else 0.0,
        'critical_per_host': round(critical_count / unique_hosts, 2) if unique_hosts > 0 else 0.0,
        'high_per_host': round(high_count / unique_hosts, 2) if unique_hosts > 0 else 0.0,
        'active_per_host': round(active_count / unique_hosts, 2) if unique_hosts > 0 else 0.0,
        'risk_score_per_host': round(risk_score / unique_hosts, 2) if unique_hosts > 0 else 0.0,
        'unique_hosts': unique_hosts,
        'total_findings': total_findings,
        'trend': trend
    }


def get_all_advanced_metrics(historical_df: pd.DataFrame,
                              lifecycle_df: pd.DataFrame,
                              sla_targets: Dict[str, int] = None) -> Dict[str, Any]:
    """
    Calculate all advanced metrics in one call.

    Args:
        historical_df: Historical findings DataFrame
        lifecycle_df: Lifecycle DataFrame
        sla_targets: Optional SLA targets by severity

    Returns:
        Dictionary with all advanced metrics
    """
    if sla_targets is None:
        sla_targets = {
            'Critical': 15,
            'High': 30,
            'Medium': 60,
            'Low': 90
        }

    return {
        'reopen_rate': calculate_reopen_rate(lifecycle_df),
        'coverage': calculate_coverage_metrics(historical_df),
        'mttd': calculate_mttd(historical_df, lifecycle_df),
        'risk_trend': calculate_risk_reduction_trend(historical_df).to_dict('records') if not historical_df.empty else [],
        'remediation_rate': calculate_remediation_rate(lifecycle_df, historical_df),
        'sla_tracking': calculate_sla_breach_tracking(lifecycle_df, sla_targets),
        'normalized': calculate_normalized_metrics(historical_df, lifecycle_df)
    }
