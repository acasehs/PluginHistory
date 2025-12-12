"""
Data Processing and Enrichment Module
Handles CVSS scoring, severity mapping, finding enrichment, and data transformations.
"""

import pandas as pd  # pip install pandas
import numpy as np  # pip install numpy
from typing import Dict, List, Tuple, Any, Optional
import json


def calculate_severity_from_cvss(cvss3_score: Optional[float], cvss2_score: Optional[float] = None) -> Tuple[str, int]:
    """
    Calculate severity text and numeric value from CVSS scores.
    
    Args:
        cvss3_score: CVSS v3 base score (preferred)
        cvss2_score: CVSS v2 base score (fallback)
        
    Returns:
        Tuple of (severity_text, severity_value)
    """
    # Try CVSS v3 first, fall back to v2
    score = cvss3_score if cvss3_score is not None else cvss2_score
    
    if score is None:
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
            return "Info", 0
    except (ValueError, TypeError):
        return "Info", 0


def enrich_findings_with_severity(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add severity calculations to findings DataFrame.
    
    Args:
        df: Findings DataFrame
        
    Returns:
        DataFrame with added severity columns
    """
    if df.empty:
        return df
    
    df = df.copy()
    
    # Convert CVSS scores to numeric
    df['cvss3_base_score_numeric'] = pd.to_numeric(df['cvss3_base_score'], errors='coerce')
    df['cvss2_base_score_numeric'] = pd.to_numeric(df['cvss2_base_score'], errors='coerce')
    
    # Calculate severity
    severity_results = df.apply(
        lambda row: calculate_severity_from_cvss(
            row['cvss3_base_score_numeric'], 
            row['cvss2_base_score_numeric']
        ), 
        axis=1
    )
    
    df['severity_text'] = [result[0] for result in severity_results]
    df['severity_value'] = [result[1] for result in severity_results]
    
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
    
    # Create pivot table
    severity_summary = pd.crosstab(
        df[group_by], 
        df['severity_text'],
        margins=True,
        margins_name='Total'
    )
    
    # Reorder columns by severity
    severity_order = ['Critical', 'High', 'Medium', 'Low', 'Info', 'Total']
    available_columns = [col for col in severity_order if col in severity_summary.columns]
    
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
    
    # Reorder columns by age
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
    
    # Filter to findings with CVEs
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
                        'cvss2_base_score': finding.get('cvss2_base_score'),
                        'hostname': finding.get('hostname', ''),
                        'plugin_id': finding.get('plugin_id', ''),
                        'plugin_name': finding.get('name', ''),
                        'host_ip': finding.get('ip_address', '')
                    })
    
    if not cve_records:
        return pd.DataFrame()
    
    cve_df = pd.DataFrame(cve_records)
    
    # Aggregate by CVE
    cve_summary = cve_df.groupby('cve').agg({
        'severity_value': 'max',  # Highest severity for this CVE
        'severity_text': lambda x: x.loc[cve_df.loc[x.index, 'severity_value'].idxmax()],  # Corresponding severity text
        'cvss3_base_score': 'first',  # Take first non-null value
        'cvss2_base_score': 'first',
        'hostname': lambda x: list(set(x)),  # Unique hostnames
        'plugin_id': lambda x: list(set(x)),  # Unique plugin IDs
        'plugin_name': lambda x: list(set(x))  # Unique plugin names
    }).reset_index()
    
    # Add host count
    cve_summary['host_count'] = cve_summary['hostname'].apply(len)
    
    # Convert lists to strings for readability
    cve_summary['affected_hosts'] = cve_summary['hostname'].apply(lambda x: '\n'.join(sorted(x)))
    cve_summary['related_plugins'] = cve_summary.apply(
        lambda row: '\n'.join([f"{pid} - {pname}" for pid, pname in zip(row['plugin_id'], row['plugin_name'])]), 
        axis=1
    )
    
    # Sort by severity and CVE
    cve_summary = cve_summary.sort_values(['severity_value', 'cve'], ascending=[False, True])
    
    return cve_summary[['cve', 'severity_text', 'cvss3_base_score', 'cvss2_base_score', 
                       'host_count', 'affected_hosts', 'related_plugins']]


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
    
    # Filter to findings with IAVx
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
                        'cvss3_base_score': finding.get('cvss3_base_score'),
                        'cvss2_base_score': finding.get('cvss2_base_score'),
                        'hostname': finding.get('hostname', ''),
                        'plugin_id': finding.get('plugin_id', ''),
                        'plugin_name': finding.get('name', ''),
                        'host_ip': finding.get('ip_address', '')
                    })
    
    if not iavx_records:
        return pd.DataFrame()
    
    iavx_df = pd.DataFrame(iavx_records)
    
    # Aggregate by IAVx
    iavx_summary = iavx_df.groupby('iavx').agg({
        'severity_value': 'max',
        'severity_text': lambda x: x.loc[iavx_df.loc[x.index, 'severity_value'].idxmax()],
        'cvss3_base_score': 'first',
        'cvss2_base_score': 'first',
        'hostname': lambda x: list(set(x)),
        'plugin_id': lambda x: list(set(x)),
        'plugin_name': lambda x: list(set(x))
    }).reset_index()
    
    # Add host count
    iavx_summary['host_count'] = iavx_summary['hostname'].apply(len)
    
    # Convert lists to strings
    iavx_summary['affected_hosts'] = iavx_summary['hostname'].apply(lambda x: '\n'.join(sorted(x)))
    iavx_summary['related_plugins'] = iavx_summary.apply(
        lambda row: '\n'.join([f"{pid} - {pname}" for pid, pname in zip(row['plugin_id'], row['plugin_name'])]), 
        axis=1
    )
    
    # Sort by severity and IAVx
    iavx_summary = iavx_summary.sort_values(['severity_value', 'iavx'], ascending=[False, True])
    
    return iavx_summary[['iavx', 'severity_text', 'cvss3_base_score', 'cvss2_base_score',
                        'host_count', 'affected_hosts', 'related_plugins']]


def identify_unmapped_findings(df: pd.DataFrame) -> pd.DataFrame:
    """
    Identify findings that have no CVE or IAVx mappings.
    
    Args:
        df: Findings DataFrame
        
    Returns:
        DataFrame with unmapped findings
    """
    if df.empty:
        return pd.DataFrame()
    
    # Find findings with no CVE or IAVx
    unmapped_mask = (
        (df['cves'].isna() | (df['cves'] == '')) &
        (df['iavx'].isna() | (df['iavx'] == ''))
    )
    
    unmapped_df = df[unmapped_mask].copy()
    
    return unmapped_df


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


def export_to_formats(findings_df: pd.DataFrame, host_summary_df: pd.DataFrame, 
                     base_filename: str) -> Dict[str, str]:
    """
    Export DataFrames to multiple formats (JSON, Excel, CSV).
    
    Args:
        findings_df: Findings DataFrame
        host_summary_df: Host summary DataFrame  
        base_filename: Base filename without extension
        
    Returns:
        Dictionary mapping format names to file paths
    """
    exported_files = {}
    
    try:
        # Export to JSON
        json_file = f"{base_filename}.json"
        export_data = {
            'findings': findings_df.to_dict('records'),
            'host_summary': host_summary_df.to_dict('records'),
            'metadata': {
                'total_findings': len(findings_df),
                'total_hosts': len(host_summary_df),
                'export_timestamp': pd.Timestamp.now().isoformat()
            }
        }
        
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, default=str)
        exported_files['json'] = json_file
        
        # Export to Excel
        excel_file = f"{base_filename}.xlsx"
        with pd.ExcelWriter(excel_file, engine='openpyxl') as writer:
            findings_df.to_excel(writer, sheet_name='Findings', index=False)
            host_summary_df.to_excel(writer, sheet_name='Host_Summary', index=False)
            
            # Auto-fit columns
            for sheet_name in writer.sheets:
                worksheet = writer.sheets[sheet_name]
                for column in worksheet.columns:
                    max_length = 0
                    column = [cell for cell in column]
                    for cell in column:
                        try:
                            if len(str(cell.value)) > max_length:
                                max_length = len(str(cell.value))
                        except:
                            pass
                    adjusted_width = min(max_length + 2, 50)
                    worksheet.column_dimensions[column[0].column_letter].width = adjusted_width
        
        exported_files['excel'] = excel_file
        
        # Export to CSV (findings only)
        csv_file = f"{base_filename}_findings.csv"
        findings_df.to_csv(csv_file, index=False, encoding='utf-8')
        exported_files['csv'] = csv_file
        
        # Export host summary to CSV
        host_csv_file = f"{base_filename}_hosts.csv"
        host_summary_df.to_csv(host_csv_file, index=False, encoding='utf-8')
        exported_files['host_csv'] = host_csv_file
        
    except Exception as e:
        print(f"Error during export: {e}")
        import traceback
        traceback.print_exc()
    
    return exported_files


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
        'contradictory_hosts': 0,
        'severity_breakdown': {},
        'top_plugins': [],
        'top_cves': [],
        'top_iavx': []
    }
    
    if not host_summary_df.empty and 'proper_scan' in host_summary_df.columns:
        summary['credentialed_hosts'] = len(host_summary_df[host_summary_df['proper_scan'] == 'Yes'])
        summary['non_credentialed_hosts'] = len(host_summary_df[host_summary_df['proper_scan'] == 'No'])
        summary['contradictory_hosts'] = len(host_summary_df[host_summary_df['proper_scan'] == 'CONTRADICTORY'])
    
    if not findings_df.empty and 'severity_text' in findings_df.columns:
        summary['severity_breakdown'] = findings_df['severity_text'].value_counts().to_dict()
        
        # Top plugins by occurrence
        if 'plugin_id' in findings_df.columns and 'name' in findings_df.columns:
            top_plugins = findings_df.groupby(['plugin_id', 'name']).size().reset_index(name='count')
            top_plugins = top_plugins.sort_values('count', ascending=False).head(10)
            summary['top_plugins'] = top_plugins.to_dict('records')
        
        # Top CVEs
        if 'cves' in findings_df.columns:
            cve_list = []
            for cves in findings_df['cves'].dropna():
                if cves:
                    cve_list.extend([cve.strip() for cve in cves.split('\n') if cve.strip()])
            
            if cve_list:
                cve_counts = pd.Series(cve_list).value_counts().head(10)
                summary['top_cves'] = [{'cve': cve, 'count': count} for cve, count in cve_counts.items()]
        
        # Top IAVx
        if 'iavx' in findings_df.columns:
            iavx_list = []
            for iavx in findings_df['iavx'].dropna():
                if iavx:
                    iavx_list.extend([ref.strip() for ref in iavx.split('\n') if ref.strip()])
            
            if iavx_list:
                iavx_counts = pd.Series(iavx_list).value_counts().head(10)
                summary['top_iavx'] = [{'iavx': ref, 'count': count} for ref, count in iavx_counts.items()]
    
    return summary