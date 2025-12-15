"""
Package Version Impact Analysis Module

Analyzes package versions to identify the highest-impact remediation actions.
Consolidates versions by package name and calculates the impact of upgrading
to specific versions based on affected hosts and findings.
"""

import pandas as pd
import numpy as np
import re
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class PackageVersionInfo:
    """Information about a specific package version upgrade."""
    package_name: str
    current_versions: List[str]
    target_version: str
    affected_hosts: int
    affected_findings: int
    total_impact: int  # hosts × findings or unique finding instances
    plugin_ids: List[str]
    cves: List[str]
    severity_breakdown: Dict[str, int]
    hosts_list: List[str]
    cvss_scores: List[float] = field(default_factory=list)  # CVSS scores for each finding
    epss_scores: List[float] = field(default_factory=list)  # EPSS scores for each finding

    @property
    def impact_score(self) -> float:
        """Calculate severity-weighted impact score.

        Formula: (Critical×4 + High×3 + Medium×2 + Low×1) × affected_hosts
        This prioritizes packages with many high-severity findings across many hosts.
        """
        severity_weights = {
            'Critical': 4,
            'High': 3,
            'Medium': 2,
            'Low': 1,
            'Info': 0
        }
        weighted_score = sum(
            count * severity_weights.get(sev, 0)
            for sev, count in self.severity_breakdown.items()
        )
        return weighted_score * self.affected_hosts

    @property
    def cvss_impact_score(self) -> float:
        """Calculate CVSS-weighted impact score.

        Formula: sum(cvss_score for each finding) × affected_hosts
        This prioritizes packages with high-CVSS vulnerabilities across many hosts.
        CVSS scores range from 0-10, where 10 is most severe.
        """
        if not self.cvss_scores:
            return 0.0
        total_cvss = sum(self.cvss_scores)
        return total_cvss * self.affected_hosts

    @property
    def epss_impact_score(self) -> float:
        """Calculate EPSS-weighted impact score (exploit likelihood).

        Formula: sum(epss_score for each finding) × affected_hosts × 100
        This prioritizes packages with high exploit probability across many hosts.
        EPSS scores range from 0-1 (0%-100% probability of exploitation).
        Multiplied by 100 to make scores more readable.
        """
        if not self.epss_scores:
            return 0.0
        total_epss = sum(self.epss_scores)
        return total_epss * self.affected_hosts * 100

    @property
    def avg_cvss(self) -> float:
        """Get average CVSS score across all findings."""
        if not self.cvss_scores:
            return 0.0
        return sum(self.cvss_scores) / len(self.cvss_scores)

    @property
    def avg_epss(self) -> float:
        """Get average EPSS score across all findings."""
        if not self.epss_scores:
            return 0.0
        return sum(self.epss_scores) / len(self.epss_scores)

    @property
    def max_cvss(self) -> float:
        """Get maximum CVSS score (most severe vulnerability)."""
        if not self.cvss_scores:
            return 0.0
        return max(self.cvss_scores)

    @property
    def max_epss(self) -> float:
        """Get maximum EPSS score (highest exploit probability)."""
        if not self.epss_scores:
            return 0.0
        return max(self.epss_scores)


@dataclass
class RemediationPlan:
    """A prioritized remediation plan."""
    packages: List[PackageVersionInfo]
    total_findings_resolved: int
    total_hosts_affected: int
    total_unique_cves: int
    generated_at: datetime = field(default_factory=datetime.now)


def parse_version_string(version_str: str) -> Tuple[List[int], str]:
    """
    Parse a version string into comparable components.

    Args:
        version_str: Version string like "1.2.3" or "java-1.8.0_321"

    Returns:
        Tuple of (version_parts as integers, original string for comparison)
    """
    if not version_str:
        return ([], "")

    # Extract version numbers from the string
    version_match = re.findall(r'(\d+)', str(version_str))
    version_parts = [int(v) for v in version_match] if version_match else []

    return (version_parts, str(version_str))


def compare_versions(v1: str, v2: str) -> int:
    """
    Compare two version strings.

    Returns:
        -1 if v1 < v2, 0 if equal, 1 if v1 > v2
    """
    parts1, _ = parse_version_string(v1)
    parts2, _ = parse_version_string(v2)

    # Pad with zeros to make equal length
    max_len = max(len(parts1), len(parts2))
    parts1.extend([0] * (max_len - len(parts1)))
    parts2.extend([0] * (max_len - len(parts2)))

    for p1, p2 in zip(parts1, parts2):
        if p1 < p2:
            return -1
        elif p1 > p2:
            return 1
    return 0


def get_highest_version(versions: List[str]) -> str:
    """
    Get the highest version from a list of version strings.

    Args:
        versions: List of version strings

    Returns:
        The highest version string
    """
    if not versions:
        return ""

    valid_versions = [v for v in versions if v and str(v).strip()]
    if not valid_versions:
        return ""

    highest = valid_versions[0]
    for v in valid_versions[1:]:
        if compare_versions(v, highest) > 0:
            highest = v

    return highest


def extract_package_name(component_name: str, installed_version: str = None) -> str:
    """
    Extract a normalized package name from component name or installed version.

    Args:
        component_name: The component/package name field
        installed_version: The installed version string (may contain package name)

    Returns:
        Normalized package name
    """
    # First try component name
    if component_name and str(component_name).strip() and str(component_name).lower() != 'nan':
        return str(component_name).strip()

    # Try to extract from installed version (format: package-version)
    if installed_version and str(installed_version).strip():
        version_str = str(installed_version).strip()
        # Match patterns like "openssl-1.0.2k" -> "openssl"
        # Or "java-1.8.0_321-openjdk" -> "java-openjdk"
        match = re.match(r'^([a-zA-Z][a-zA-Z0-9_-]*?)[-_]?\d', version_str)
        if match:
            return match.group(1).rstrip('-_')

    return "Unknown"


def analyze_package_version_impact(
    version_df: pd.DataFrame,
    findings_df: pd.DataFrame = None,
    min_impact: int = 1
) -> RemediationPlan:
    """
    Analyze package versions to identify highest-impact remediation actions.

    This function consolidates version data by package name, identifies the
    highest version needed to resolve all findings, and calculates the impact.

    Args:
        version_df: DataFrame with extracted version information
            Required columns:
            - Component_Name or Package_Name: Package identifier
            - Installed_Version or Reported_Version: Current version
            - Should_Be_Version or Fixed_Version: Target version
            - Hostname or Host: Affected host
            - Plugin_ID: Associated plugin
            Optional:
            - IP_Address: Host IP
            - Severity or severity_text: Finding severity
            - CVEs or cves: Associated CVEs

        findings_df: Optional DataFrame with full findings data for severity lookup
        min_impact: Minimum impact score to include in results

    Returns:
        RemediationPlan with prioritized package upgrades
    """
    if version_df is None or version_df.empty:
        return RemediationPlan(
            packages=[],
            total_findings_resolved=0,
            total_hosts_affected=0,
            total_unique_cves=0
        )

    # Normalize column names
    df = version_df.copy()
    column_mapping = {
        'Component_Name': 'package_name',
        'Package_Name': 'package_name',
        'component_name': 'package_name',
        'package_name': 'package_name',
        'Installed_Version': 'installed_version',
        'installed_version': 'installed_version',
        'Reported_Version': 'reported_version',
        'reported_version': 'reported_version',
        'Should_Be_Version': 'target_version',
        'should_be_version': 'target_version',
        'Fixed_Version': 'target_version',
        'fixed_version': 'target_version',
        'Hostname': 'hostname',
        'hostname': 'hostname',
        'Host': 'hostname',
        'DNS Name': 'hostname',
        'Plugin_ID': 'plugin_id',
        'plugin_id': 'plugin_id',
        'IP_Address': 'ip_address',
        'ip_address': 'ip_address',
        'Severity': 'severity',
        'severity_text': 'severity',
        'CVEs': 'cves',
        'cves': 'cves',
        'cvss_base_score': 'cvss_score',
        'cvss_score': 'cvss_score',
        'CVSS_Base_Score': 'cvss_score',
        'cvss3_base_score': 'cvss_score',
        'epss_score': 'epss_score',
        'EPSS_Score': 'epss_score',
        'epss': 'epss_score'
    }

    # Apply column mapping
    for old_name, new_name in column_mapping.items():
        if old_name in df.columns and new_name not in df.columns:
            df = df.rename(columns={old_name: new_name})

    # Ensure required columns exist
    if 'package_name' not in df.columns:
        if 'installed_version' in df.columns:
            df['package_name'] = df['installed_version'].apply(
                lambda x: extract_package_name(None, x)
            )
        else:
            df['package_name'] = 'Unknown'

    # Extract package name from component or version if needed
    df['package_name'] = df.apply(
        lambda row: extract_package_name(
            row.get('package_name', ''),
            row.get('installed_version', row.get('reported_version', ''))
        ),
        axis=1
    )

    # Ensure we have target version
    if 'target_version' not in df.columns:
        if 'fixed_version' in df.columns:
            df['target_version'] = df['fixed_version']
        elif 'should_be_version' in df.columns:
            df['target_version'] = df['should_be_version']
        else:
            df['target_version'] = ''

    # Ensure hostname column
    if 'hostname' not in df.columns:
        df['hostname'] = 'Unknown'

    # Get current version
    if 'installed_version' not in df.columns:
        if 'reported_version' in df.columns:
            df['installed_version'] = df['reported_version']
        else:
            df['installed_version'] = ''

    # Ensure plugin_id column
    if 'plugin_id' not in df.columns:
        df['plugin_id'] = ''

    # Add severity from findings_df if available
    if 'severity' not in df.columns and findings_df is not None:
        severity_col = None
        for col in ['severity_text', 'severity', 'Severity']:
            if col in findings_df.columns:
                severity_col = col
                break

        if severity_col and 'plugin_id' in findings_df.columns:
            severity_map = findings_df.groupby('plugin_id')[severity_col].first().to_dict()
            df['severity'] = df['plugin_id'].map(severity_map).fillna('Unknown')

    if 'severity' not in df.columns:
        df['severity'] = 'Unknown'

    # Add CVSS score from findings_df if available
    if 'cvss_score' not in df.columns and findings_df is not None:
        cvss_col = None
        for col in ['cvss_base_score', 'cvss_score', 'CVSS_Base_Score', 'cvss3_base_score']:
            if col in findings_df.columns:
                cvss_col = col
                break

        if cvss_col and 'plugin_id' in findings_df.columns:
            cvss_map = findings_df.groupby('plugin_id')[cvss_col].first().to_dict()
            df['cvss_score'] = df['plugin_id'].map(cvss_map).fillna(0.0)

    if 'cvss_score' not in df.columns:
        df['cvss_score'] = 0.0

    # Add EPSS score from findings_df if available
    if 'epss_score' not in df.columns and findings_df is not None:
        epss_col = None
        for col in ['epss_score', 'EPSS_Score', 'epss']:
            if col in findings_df.columns:
                epss_col = col
                break

        if epss_col and 'plugin_id' in findings_df.columns:
            epss_map = findings_df.groupby('plugin_id')[epss_col].first().to_dict()
            df['epss_score'] = df['plugin_id'].map(epss_map).fillna(0.0)

    if 'epss_score' not in df.columns:
        df['epss_score'] = 0.0

    # Extract CVEs if available
    if 'cves' not in df.columns:
        df['cves'] = ''

    # Group by package name
    package_analysis = {}

    for package_name, group in df.groupby('package_name'):
        if not package_name or package_name == 'Unknown':
            continue

        # Get all unique target versions
        target_versions = group['target_version'].dropna().unique().tolist()
        target_versions = [str(v).strip() for v in target_versions if str(v).strip()]

        # Get the highest target version
        highest_target = get_highest_version(target_versions)
        if not highest_target:
            continue

        # Get current versions
        current_versions = group['installed_version'].dropna().unique().tolist()
        current_versions = [str(v).strip() for v in current_versions if str(v).strip()]

        # Get unique hosts
        hosts = group['hostname'].dropna().unique().tolist()
        hosts = [str(h).strip() for h in hosts if str(h).strip() and str(h).lower() != 'unknown']

        # Get plugin IDs
        plugin_ids = group['plugin_id'].dropna().unique().tolist()
        plugin_ids = [str(p).strip() for p in plugin_ids if str(p).strip()]

        # Get CVEs
        all_cves = []
        for cve_str in group['cves'].dropna().unique():
            if cve_str:
                # Extract CVE IDs from string
                cve_matches = re.findall(r'CVE-\d{4}-\d+', str(cve_str), re.IGNORECASE)
                all_cves.extend(cve_matches)
        all_cves = list(set(all_cves))

        # Severity breakdown
        severity_breakdown = group['severity'].value_counts().to_dict()

        # Collect CVSS scores (filter out zeros and convert to float)
        cvss_scores = []
        if 'cvss_score' in group.columns:
            for score in group['cvss_score'].dropna():
                try:
                    score_val = float(score)
                    if score_val > 0:
                        cvss_scores.append(score_val)
                except (ValueError, TypeError):
                    pass

        # Collect EPSS scores (filter out zeros and convert to float)
        epss_scores = []
        if 'epss_score' in group.columns:
            for score in group['epss_score'].dropna():
                try:
                    score_val = float(score)
                    if score_val > 0:
                        epss_scores.append(score_val)
                except (ValueError, TypeError):
                    pass

        # Calculate impact: number of unique (host, plugin) combinations
        affected_findings = len(group.drop_duplicates(subset=['hostname', 'plugin_id']))
        affected_hosts = len(hosts) if hosts else group['hostname'].nunique()

        # Total impact is the actual number of finding instances that would be resolved
        total_impact = len(group)

        package_info = PackageVersionInfo(
            package_name=package_name,
            current_versions=current_versions,
            target_version=highest_target,
            affected_hosts=affected_hosts,
            affected_findings=affected_findings,
            total_impact=total_impact,
            plugin_ids=plugin_ids,
            cves=all_cves,
            severity_breakdown=severity_breakdown,
            hosts_list=hosts,
            cvss_scores=cvss_scores,
            epss_scores=epss_scores
        )

        if total_impact >= min_impact:
            package_analysis[package_name] = package_info

    # Sort by impact score (descending)
    sorted_packages = sorted(
        package_analysis.values(),
        key=lambda x: x.impact_score,
        reverse=True
    )

    # Calculate totals
    total_findings = sum(p.total_impact for p in sorted_packages)
    all_hosts = set()
    all_cves = set()
    for p in sorted_packages:
        all_hosts.update(p.hosts_list)
        all_cves.update(p.cves)

    return RemediationPlan(
        packages=sorted_packages,
        total_findings_resolved=total_findings,
        total_hosts_affected=len(all_hosts),
        total_unique_cves=len(all_cves)
    )


def create_remediation_summary_df(plan: RemediationPlan) -> pd.DataFrame:
    """
    Create a summary DataFrame from a remediation plan.

    Args:
        plan: RemediationPlan object

    Returns:
        DataFrame with remediation summary
    """
    if not plan.packages:
        return pd.DataFrame()

    data = []
    for pkg in plan.packages:
        data.append({
            'Package': pkg.package_name,
            'Target_Version': pkg.target_version,
            'Affected_Hosts': pkg.affected_hosts,
            'Findings_Resolved': pkg.total_impact,
            'Severity_Impact': pkg.impact_score,
            'CVSS_Impact': pkg.cvss_impact_score,
            'EPSS_Impact': pkg.epss_impact_score,
            'Max_CVSS': pkg.max_cvss,
            'Max_EPSS': round(pkg.max_epss * 100, 2),  # As percentage
            'Critical': pkg.severity_breakdown.get('Critical', 0),
            'High': pkg.severity_breakdown.get('High', 0),
            'Medium': pkg.severity_breakdown.get('Medium', 0),
            'Low': pkg.severity_breakdown.get('Low', 0),
            'CVE_Count': len(pkg.cves),
            'Plugin_Count': len(pkg.plugin_ids),
            'Current_Versions': ', '.join(pkg.current_versions[:5]) + ('...' if len(pkg.current_versions) > 5 else ''),
            'CVEs': ', '.join(pkg.cves[:5]) + ('...' if len(pkg.cves) > 5 else ''),
            'Plugin_IDs': ', '.join(pkg.plugin_ids[:5]) + ('...' if len(pkg.plugin_ids) > 5 else '')
        })

    df = pd.DataFrame(data)
    return df.sort_values('Severity_Impact', ascending=False)


def get_package_details(
    plan: RemediationPlan,
    package_name: str
) -> Optional[Dict[str, Any]]:
    """
    Get detailed information for a specific package.

    Args:
        plan: RemediationPlan object
        package_name: Name of the package to get details for

    Returns:
        Dictionary with detailed package information
    """
    for pkg in plan.packages:
        if pkg.package_name == package_name:
            return {
                'package_name': pkg.package_name,
                'target_version': pkg.target_version,
                'current_versions': pkg.current_versions,
                'affected_hosts': pkg.affected_hosts,
                'hosts_list': pkg.hosts_list,
                'findings_resolved': pkg.total_impact,
                'severity_impact_score': pkg.impact_score,
                'cvss_impact_score': pkg.cvss_impact_score,
                'epss_impact_score': pkg.epss_impact_score,
                'max_cvss': pkg.max_cvss,
                'avg_cvss': pkg.avg_cvss,
                'max_epss': pkg.max_epss,
                'avg_epss': pkg.avg_epss,
                'severity_breakdown': pkg.severity_breakdown,
                'cves': pkg.cves,
                'plugin_ids': pkg.plugin_ids
            }
    return None


def calculate_cumulative_impact(plan: RemediationPlan) -> pd.DataFrame:
    """
    Calculate cumulative impact when remediating packages in priority order.

    Args:
        plan: RemediationPlan object

    Returns:
        DataFrame showing cumulative impact
    """
    if not plan.packages:
        return pd.DataFrame()

    data = []
    cumulative_findings = 0
    cumulative_hosts = set()
    cumulative_cves = set()

    for i, pkg in enumerate(plan.packages):
        cumulative_findings += pkg.total_impact
        cumulative_hosts.update(pkg.hosts_list)
        cumulative_cves.update(pkg.cves)

        data.append({
            'Priority': i + 1,
            'Package': pkg.package_name,
            'Findings_Resolved': pkg.total_impact,
            'Cumulative_Findings': cumulative_findings,
            'Cumulative_Findings_Pct': round(cumulative_findings / plan.total_findings_resolved * 100, 1) if plan.total_findings_resolved > 0 else 0,
            'Cumulative_Hosts': len(cumulative_hosts),
            'Cumulative_CVEs': len(cumulative_cves)
        })

    return pd.DataFrame(data)


def group_by_severity_impact(plan: RemediationPlan) -> Dict[str, List[PackageVersionInfo]]:
    """
    Group packages by their primary severity impact.

    Args:
        plan: RemediationPlan object

    Returns:
        Dictionary mapping severity to list of packages
    """
    severity_groups = {
        'Critical': [],
        'High': [],
        'Medium': [],
        'Low': [],
        'Info': []
    }

    for pkg in plan.packages:
        # Determine primary severity
        primary_severity = 'Info'
        max_weighted = 0
        weights = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Info': 0}

        for sev, count in pkg.severity_breakdown.items():
            weighted = count * weights.get(sev, 0)
            if weighted > max_weighted:
                max_weighted = weighted
                primary_severity = sev

        if primary_severity in severity_groups:
            severity_groups[primary_severity].append(pkg)

    return severity_groups


def estimate_remediation_effort(plan: RemediationPlan) -> Dict[str, Any]:
    """
    Estimate remediation effort based on package count and hosts affected.

    Args:
        plan: RemediationPlan object

    Returns:
        Dictionary with effort estimates
    """
    total_packages = len(plan.packages)

    # Categorize effort
    if total_packages <= 5:
        effort_level = 'Low'
    elif total_packages <= 15:
        effort_level = 'Medium'
    elif total_packages <= 30:
        effort_level = 'High'
    else:
        effort_level = 'Very High'

    # Calculate distribution
    severity_groups = group_by_severity_impact(plan)

    return {
        'total_packages': total_packages,
        'total_hosts': plan.total_hosts_affected,
        'total_findings': plan.total_findings_resolved,
        'total_cves': plan.total_unique_cves,
        'effort_level': effort_level,
        'critical_packages': len(severity_groups.get('Critical', [])),
        'high_packages': len(severity_groups.get('High', [])),
        'medium_packages': len(severity_groups.get('Medium', [])),
        'low_packages': len(severity_groups.get('Low', [])),
        'recommendations': _generate_recommendations(plan, severity_groups)
    }


def _generate_recommendations(
    plan: RemediationPlan,
    severity_groups: Dict[str, List[PackageVersionInfo]]
) -> List[str]:
    """Generate remediation recommendations."""
    recommendations = []

    critical_pkgs = severity_groups.get('Critical', [])
    high_pkgs = severity_groups.get('High', [])

    if critical_pkgs:
        top_critical = critical_pkgs[:3]
        pkg_names = ', '.join(p.package_name for p in top_critical)
        recommendations.append(
            f"URGENT: Prioritize {len(critical_pkgs)} critical package(s). "
            f"Start with: {pkg_names}"
        )

    if high_pkgs:
        top_high = high_pkgs[:3]
        pkg_names = ', '.join(p.package_name for p in top_high)
        recommendations.append(
            f"HIGH PRIORITY: {len(high_pkgs)} high-severity package(s) need attention. "
            f"Top candidates: {pkg_names}"
        )

    # Quick wins (high impact, few hosts)
    quick_wins = [p for p in plan.packages if p.affected_hosts <= 5 and p.total_impact >= 10]
    if quick_wins:
        top_quick = quick_wins[:3]
        pkg_names = ', '.join(p.package_name for p in top_quick)
        recommendations.append(
            f"QUICK WINS: {len(quick_wins)} package(s) affect few hosts but resolve many findings: {pkg_names}"
        )

    # Consolidation opportunities (many versions of same package family)
    if plan.packages:
        top_by_versions = sorted(
            plan.packages,
            key=lambda x: len(x.current_versions),
            reverse=True
        )[:3]
        for pkg in top_by_versions:
            if len(pkg.current_versions) > 3:
                recommendations.append(
                    f"CONSOLIDATION: {pkg.package_name} has {len(pkg.current_versions)} different versions. "
                    f"Standardizing to {pkg.target_version} would simplify maintenance."
                )

    return recommendations


def export_remediation_plan(
    plan: RemediationPlan,
    output_path: str,
    format: str = 'xlsx'
) -> bool:
    """
    Export remediation plan to file.

    Args:
        plan: RemediationPlan object
        output_path: Path for output file
        format: Output format ('xlsx', 'csv', 'json')

    Returns:
        True if successful
    """
    try:
        summary_df = create_remediation_summary_df(plan)
        cumulative_df = calculate_cumulative_impact(plan)
        effort = estimate_remediation_effort(plan)

        if format == 'xlsx':
            with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
                # Summary sheet
                summary_df.to_excel(writer, sheet_name='Package_Priority', index=False)

                # Cumulative impact sheet
                cumulative_df.to_excel(writer, sheet_name='Cumulative_Impact', index=False)

                # Effort estimate sheet
                effort_df = pd.DataFrame([{
                    'Metric': k,
                    'Value': v if not isinstance(v, list) else '\n'.join(v)
                } for k, v in effort.items()])
                effort_df.to_excel(writer, sheet_name='Effort_Estimate', index=False)

                # Detailed host list per package
                host_data = []
                for pkg in plan.packages:
                    for host in pkg.hosts_list:
                        host_data.append({
                            'Package': pkg.package_name,
                            'Target_Version': pkg.target_version,
                            'Hostname': host
                        })
                if host_data:
                    host_df = pd.DataFrame(host_data)
                    host_df.to_excel(writer, sheet_name='Host_Details', index=False)

            return True

        elif format == 'csv':
            summary_df.to_csv(output_path, index=False)
            return True

        elif format == 'json':
            import json
            output = {
                'summary': summary_df.to_dict('records'),
                'cumulative_impact': cumulative_df.to_dict('records'),
                'effort_estimate': effort,
                'generated_at': plan.generated_at.isoformat()
            }
            with open(output_path, 'w') as f:
                json.dump(output, f, indent=2)
            return True

    except Exception as e:
        logger.error(f"Error exporting remediation plan: {e}")
        return False


# Integration with existing version extractor
def process_version_extractor_output(
    version_file_path: str,
    findings_df: pd.DataFrame = None
) -> RemediationPlan:
    """
    Process output from the Tenable Version Extractor script.

    Args:
        version_file_path: Path to the extracted versions Excel file
        findings_df: Optional findings DataFrame for severity enrichment

    Returns:
        RemediationPlan with analysis results
    """
    try:
        # Read the version extractor output
        if version_file_path.endswith('.xlsx'):
            version_df = pd.read_excel(version_file_path)
        elif version_file_path.endswith('.csv'):
            version_df = pd.read_csv(version_file_path)
        else:
            logger.error(f"Unsupported file format: {version_file_path}")
            return RemediationPlan([], 0, 0, 0)

        return analyze_package_version_impact(version_df, findings_df)

    except Exception as e:
        logger.error(f"Error processing version extractor output: {e}")
        return RemediationPlan([], 0, 0, 0)
