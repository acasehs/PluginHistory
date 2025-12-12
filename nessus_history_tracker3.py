"""
Enhanced Nessus Historical Analysis and Visualization System
Tracks vulnerability findings and host presence across multiple scans over time.
Includes OPDIR integration and comprehensive visualization suite.
"""

import os
import json
import re
import sqlite3
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
from collections import defaultdict
import pandas as pd  # pip install pandas
import tkinter as tk  # pip install tk
from tkinter import filedialog, messagebox, ttk
import matplotlib.pyplot as plt  # pip install matplotlib
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.dates as mdates
import numpy as np  # pip install numpy

try:
    from archive_extraction import extract_nested_archives, find_files_by_extension, cleanup_temp_directory
    from nessus_parser import parse_multiple_nessus_files
    from plugin_database import load_plugins_database
    from data_processing import enrich_findings_with_severity
except ImportError:
    print("Warning: Could not import all modules. Ensure they are in the same directory.")


def load_and_process_opdir(opdir_file_path: str) -> pd.DataFrame:
    """
    Load and process OPDIR spreadsheet data.
    
    Args:
        opdir_file_path: Path to OPDIR Excel/CSV file
        
    Returns:
        DataFrame with processed OPDIR data
    """
    try:
        if opdir_file_path.lower().endswith('.xlsx') or opdir_file_path.lower().endswith('.xls'):
            opdir_df = pd.read_excel(opdir_file_path)
        else:
            opdir_df = pd.read_csv(opdir_file_path)
        
        print(f"Loaded OPDIR file with {len(opdir_df)} records")
        
        column_mapping = {}
        for col in opdir_df.columns:
            col_lower = col.lower().strip()
            if 'opdir' in col_lower and 'number' in col_lower:
                column_mapping[col] = 'opdir_number'
            elif 'iava' in col_lower or 'iav' in col_lower:
                column_mapping[col] = 'iavx_reference'
            elif 'subject' in col_lower:
                column_mapping[col] = 'subject'
            elif 'release' in col_lower and 'date' in col_lower:
                column_mapping[col] = 'release_date'
            elif 'acknowledge' in col_lower and 'date' in col_lower:
                column_mapping[col] = 'acknowledge_date'
            elif 'poa' in col_lower and 'due' in col_lower:
                column_mapping[col] = 'poam_due_date'
            elif 'final' in col_lower and 'due' in col_lower:
                column_mapping[col] = 'final_due_date'
        
        opdir_df = opdir_df.rename(columns=column_mapping)
        
        if 'opdir_number' in opdir_df.columns:
            opdir_df['opdir_year'] = opdir_df['opdir_number'].astype(str).str.extract(r'-(\d{2})')[0]
            opdir_df['opdir_sequence'] = opdir_df['opdir_number'].astype(str).str.extract(r'^(\d+)-')[0]
        
        if 'iavx_reference' in opdir_df.columns:
            opdir_df['iavx_normalized'] = opdir_df['iavx_reference'].astype(str).str.extract(r'([A-Z]-\d+)')[0]
            
            opdir_df['iavx_full'] = opdir_df.apply(lambda row: 
                f"IAV{row['iavx_reference'][0]}:20{row['opdir_year']}-{row['iavx_normalized']}" 
                if pd.notna(row.get('iavx_normalized')) and pd.notna(row.get('opdir_year')) 
                else None, axis=1)
        
        date_columns = ['release_date', 'acknowledge_date', 'poam_due_date', 'final_due_date']
        for col in date_columns:
            if col in opdir_df.columns:
                opdir_df[col] = pd.to_datetime(opdir_df[col], errors='coerce')
        
        print(f"Processed OPDIR data with {len(opdir_df)} valid records")
        return opdir_df
        
    except Exception as e:
        print(f"Error loading OPDIR file: {e}")
        return pd.DataFrame()


def enrich_findings_with_opdir(findings_df: pd.DataFrame, opdir_df: pd.DataFrame) -> pd.DataFrame:
    """
    Enrich findings with OPDIR data based on IAVx references.
    
    Args:
        findings_df: Historical findings DataFrame
        opdir_df: OPDIR DataFrame
        
    Returns:
        Enhanced findings DataFrame with OPDIR information
    """
    if opdir_df.empty or findings_df.empty:
        return findings_df
    
    enriched_df = findings_df.copy()
    
    enriched_df['opdir_number'] = None
    enriched_df['opdir_subject'] = None
    enriched_df['opdir_release_date'] = None
    enriched_df['opdir_poam_due_date'] = None
    enriched_df['opdir_final_due_date'] = None
    enriched_df['opdir_days_to_due'] = None
    
    for idx, finding in enriched_df.iterrows():
        if pd.notna(finding.get('iavx')) and finding['iavx']:
            iavx_list = finding['iavx'].split('\n')
            
            for iavx in iavx_list:
                iavx = iavx.strip()
                
                matching_opdir = opdir_df[
                    (opdir_df['iavx_full'].notna()) & 
                    (opdir_df['iavx_full'].str.contains(iavx.replace(':', ':'), regex=False, na=False))
                ]
                
                if not matching_opdir.empty:
                    opdir_record = matching_opdir.iloc[0]
                    enriched_df.at[idx, 'opdir_number'] = opdir_record.get('opdir_number')
                    enriched_df.at[idx, 'opdir_subject'] = opdir_record.get('subject')
                    enriched_df.at[idx, 'opdir_release_date'] = opdir_record.get('release_date')
                    enriched_df.at[idx, 'opdir_poam_due_date'] = opdir_record.get('poam_due_date')
                    enriched_df.at[idx, 'opdir_final_due_date'] = opdir_record.get('final_due_date')
                    
                    if pd.notna(opdir_record.get('final_due_date')):
                        days_to_due = (opdir_record['final_due_date'] - pd.Timestamp.now()).days
                        enriched_df.at[idx, 'opdir_days_to_due'] = days_to_due
                    
                    break
    
    print(f"Enriched {len(enriched_df[enriched_df['opdir_number'].notna()])} findings with OPDIR data")
    return enriched_df


def extract_scan_date_from_filename(filename: str) -> Optional[datetime]:
    """Extract scan date from filename using common patterns."""
    patterns = [
        r'(\d{4})[-_]?(\d{2})[-_]?(\d{2})',
        r'(\d{2})[-_]?(\d{2})[-_]?(\d{4})',
        r'(\d{8})'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, filename)
        if match:
            try:
                if len(match.groups()) == 1:
                    date_str = match.group(1)
                    return datetime.strptime(date_str, '%Y%m%d')
                elif len(match.groups()) == 3:
                    if len(match.group(1)) == 4:
                        return datetime(int(match.group(1)), int(match.group(2)), int(match.group(3)))
                    else:
                        return datetime(int(match.group(3)), int(match.group(1)), int(match.group(2)))
            except (ValueError, IndexError):
                continue
    
    return None


def extract_scan_date_from_nessus(nessus_file_path: str) -> Optional[datetime]:
    """Extract scan date from .nessus file."""
    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(nessus_file_path)
        root = tree.getroot()
        
        for report in root.findall('.//Report'):
            for host in report.findall('.//ReportHost'):
                for tag in host.findall('.//HostProperties/tag'):
                    if tag.get('name') == 'HOST_END':
                        timestamp = tag.text
                        return datetime.fromtimestamp(int(timestamp))
        
        policy = root.find('.//Policy/policyName')
        if policy is not None and policy.text:
            extracted_date = extract_scan_date_from_filename(policy.text)
            if extracted_date:
                return extracted_date
                
    except Exception as e:
        print(f"Error extracting date from nessus file: {e}")
    
    return None


def check_for_duplicates(new_df: pd.DataFrame, existing_df: pd.DataFrame) -> Tuple[pd.DataFrame, int]:
    """Check for duplicate scan data based on scan_date and scan_file."""
    if existing_df.empty:
        return new_df, 0
    
    new_df['composite_key'] = new_df['scan_date'].astype(str) + '|' + new_df['scan_file'].astype(str)
    existing_df['composite_key'] = existing_df['scan_date'].astype(str) + '|' + existing_df['scan_file'].astype(str)
    
    duplicate_keys = set(existing_df['composite_key'].unique())
    new_unique_mask = ~new_df['composite_key'].isin(duplicate_keys)
    
    filtered_new_df = new_df[new_unique_mask].copy()
    duplicate_count = len(new_df) - len(filtered_new_df)
    
    filtered_new_df = filtered_new_df.drop('composite_key', axis=1)
    
    return filtered_new_df, duplicate_count


def process_historical_scans(archive_paths: List[str], plugins_db_path: Optional[str] = None, 
                           existing_db_path: Optional[str] = None, include_info: bool = False) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Process multiple Nessus archives and track findings history with enhanced features."""
    import tempfile
    
    existing_historical_df = pd.DataFrame()
    if existing_db_path and os.path.exists(existing_db_path):
        print(f"Loading existing database from {existing_db_path}")
        existing_historical_df, _, _, _ = load_existing_database(existing_db_path)
    
    plugins_dict = None
    if plugins_db_path:
        plugins_dict = load_plugins_database(plugins_db_path)
    
    all_historical_findings = []
    
    for archive_path in archive_paths:
        print(f"\n{'='*60}")
        print(f"Processing: {os.path.basename(archive_path)}")
        print(f"{'='*60}")
        
        temp_dir = None
        nessus_files = []
        
        try:
            scan_date = extract_scan_date_from_filename(os.path.basename(archive_path))
            
            if archive_path.lower().endswith('.zip'):
                temp_dir = tempfile.mkdtemp()
                extract_nested_archives(archive_path, temp_dir)
                nessus_files = find_files_by_extension(temp_dir, '.nessus')
            elif archive_path.lower().endswith('.nessus'):
                nessus_files = [archive_path]
            else:
                print(f"Unsupported file format: {archive_path}")
                continue
            
            if not nessus_files:
                print(f"No .nessus files found in {archive_path}")
                continue
            
            if not scan_date and nessus_files:
                scan_date = extract_scan_date_from_nessus(nessus_files[0])
            
            if not scan_date:
                scan_date = datetime.fromtimestamp(os.path.getmtime(archive_path))
                print(f"Warning: Using file modification time for scan date: {scan_date.strftime('%Y-%m-%d')}")
            else:
                print(f"Scan date: {scan_date.strftime('%Y-%m-%d')}")
            
            findings_df, host_summary_df = parse_multiple_nessus_files(nessus_files, plugins_dict)
            
            if not findings_df.empty:
                findings_df['scan_date'] = scan_date
                findings_df['scan_file'] = os.path.basename(archive_path)
                
                findings_df = enrich_findings_with_severity(findings_df)
                
                all_historical_findings.append(findings_df)
                
                for _, host in host_summary_df.iterrows():
                    hostname = host.get('hostname', 'Unknown')
                    ip = host.get('host_name', 'Unknown')
                    print(f"  Processed: {hostname} ({ip})")
                print(f"Extracted {len(findings_df)} findings from {len(host_summary_df)} hosts")
            
        finally:
            if temp_dir:
                cleanup_temp_directory(temp_dir)
    
    if not all_historical_findings:
        print("No findings extracted from any archive")
        return pd.DataFrame(), pd.DataFrame(), pd.DataFrame(), pd.DataFrame()
    
    new_historical_df = pd.concat(all_historical_findings, ignore_index=True)
    
    duplicate_count = 0
    if not existing_historical_df.empty:
        print(f"\nChecking for duplicates against existing database...")
        new_historical_df, duplicate_count = check_for_duplicates(new_historical_df, existing_historical_df)
        
        if duplicate_count > 0:
            print(f"Found {duplicate_count} duplicate findings (already in database)")
        
        if not new_historical_df.empty:
            print(f"Adding {len(new_historical_df)} new findings to existing database")
            historical_df = pd.concat([existing_historical_df, new_historical_df], ignore_index=True)
        else:
            print("No new findings to add")
            historical_df = existing_historical_df
    else:
        historical_df = new_historical_df
    
    historical_df['scan_date'] = pd.to_datetime(historical_df['scan_date'])
    historical_df = historical_df.sort_values('scan_date')
    
    if not include_info:
        analysis_df = historical_df[historical_df['severity_text'] != 'Info'].copy()
        print(f"\nExcluding {len(historical_df) - len(analysis_df)} Info-level findings from analysis")
    else:
        analysis_df = historical_df.copy()
    
    print(f"\nGenerating lifecycle analysis...")
    lifecycle_df = generate_lifecycle_analysis(analysis_df)
    
    print(f"Tracking host presence...")
    host_presence_df = track_host_presence(historical_df)
    
    print(f"Analyzing scan-to-scan changes...")
    scan_changes_df = analyze_scan_changes(analysis_df)
    
    print(f"\n{'='*60}")
    print(f"PROCESSING COMPLETE")
    print(f"{'='*60}")
    print(f"Total findings in database: {len(historical_df)}")
    print(f"Findings in analysis (after filters): {len(analysis_df)}")
    print(f"Unique findings tracked: {len(lifecycle_df)}")
    print(f"Hosts tracked: {len(host_presence_df)}")
    print(f"Scan transitions analyzed: {len(scan_changes_df)}")
    
    return historical_df, lifecycle_df, host_presence_df, scan_changes_df


def generate_lifecycle_analysis(historical_df: pd.DataFrame) -> pd.DataFrame:
    """Generate lifecycle analysis for each unique finding."""
    if historical_df.empty:
        return pd.DataFrame()
    
    historical_df['finding_key'] = (
        historical_df['hostname'].astype(str) + '|' + 
        historical_df['plugin_id'].astype(str)
    )
    
    lifecycle_records = []
    
    for finding_key, group in historical_df.groupby('finding_key'):
        hostname, plugin_id = finding_key.split('|')
        
        group = group.sort_values('scan_date')
        
        scan_dates = group['scan_date'].tolist()
        scan_files = group['scan_file'].tolist()
        
        latest = group.iloc[-1]
        
        first_seen = scan_dates[0]
        last_seen = scan_dates[-1]
        total_observations = len(scan_dates)
        
        gaps = []
        reappearances = 0

        if len(scan_dates) > 1:
            for i in range(1, len(scan_dates)):
                days_gap = (scan_dates[i] - scan_dates[i-1]).days
                if days_gap > 45:
                    gaps.append({
                        'resolved_after': scan_dates[i-1].strftime('%Y-%m-%d'),
                        'reappeared_on': scan_dates[i].strftime('%Y-%m-%d'),
                        'days_resolved': days_gap
                    })
                    reappearances += 1
        
        if latest['scan_date'] == historical_df['scan_date'].max():
            status = 'Active'
        else:
            status = 'Resolved'
        
        lifecycle_records.append({
            'hostname': hostname,
            'ip_address': latest.get('ip_address', ''),
            'plugin_id': plugin_id,
            'plugin_name': latest['name'],
            'severity_text': latest.get('severity_text', ''),
            'severity_value': latest.get('severity_value', 0),
            'family': latest.get('family', ''),
            'first_seen': first_seen,
            'last_seen': last_seen,
            'days_open': (last_seen - first_seen).days,
            'total_observations': total_observations,
            'reappearances': reappearances,
            'status': status,
            'gap_details': json.dumps(gaps) if gaps else '',
            'scan_files': '\n'.join(scan_files),
            'cves': latest.get('cves', ''),
            'iavx': latest.get('iavx', ''),
            'cvss3_base_score': latest.get('cvss3_base_score', ''),
            'stig_severity': latest.get('stig_severity', ''),
            'exploit_available': latest.get('exploit_available', '')
        })
    
    lifecycle_df = pd.DataFrame(lifecycle_records)
    print(f"Generated lifecycle analysis for {len(lifecycle_df)} unique findings")
    
    return lifecycle_df


def track_host_presence(historical_df: pd.DataFrame) -> pd.DataFrame:
    """Track which hosts appear in which scans."""
    if historical_df.empty:
        return pd.DataFrame()
    
    all_scan_dates = sorted(historical_df['scan_date'].unique())
    total_scans = len(all_scan_dates)
    
    host_records = []
    
    for hostname in historical_df['hostname'].unique():
        host_data = historical_df[historical_df['hostname'] == hostname]
        
        scan_dates_present = sorted(host_data['scan_date'].unique())
        scans_present = len(scan_dates_present)
        
        ip_addresses = host_data['ip_address'].unique()
        ip_address = ip_addresses[0] if len(ip_addresses) > 0 else ''
        
        first_seen = scan_dates_present[0]
        last_seen = scan_dates_present[-1]
        
        gaps = []
        for i in range(len(all_scan_dates)):
            if all_scan_dates[i] not in scan_dates_present:
                if i > 0 and all_scan_dates[i-1] in scan_dates_present:
                    gap_start = all_scan_dates[i]
                    gap_end = None
                    for j in range(i+1, len(all_scan_dates)):
                        if all_scan_dates[j] in scan_dates_present:
                            gap_end = all_scan_dates[j-1] if j > i else gap_start
                            break
                    if gap_end is None:
                        gap_end = all_scan_dates[-1]
                    gaps.append({
                        'start': gap_start.strftime('%Y-%m-%d'),
                        'end': gap_end.strftime('%Y-%m-%d')
                    })
        
        if last_seen < all_scan_dates[-1]:
            status = 'Missing'
        else:
            status = 'Active'
        
        host_records.append({
            'hostname': hostname,
            'ip_address': ip_address,
            'first_seen': first_seen,
            'last_seen': last_seen,
            'total_scans_available': total_scans,
            'scans_present': scans_present,
            'presence_rate': (scans_present / total_scans) * 100,
            'status': status,
            'gaps': json.dumps(gaps) if gaps else ''
        })
    
    host_presence_df = pd.DataFrame(host_records)
    print(f"Tracked presence for {len(host_presence_df)} unique hosts")
    
    return host_presence_df


def analyze_scan_changes(historical_df: pd.DataFrame) -> pd.DataFrame:
    """Analyze changes between consecutive scans."""
    if historical_df.empty:
        return pd.DataFrame()
    
    scan_dates = sorted(historical_df['scan_date'].unique())
    
    if len(scan_dates) < 2:
        print("Not enough scans to analyze changes")
        return pd.DataFrame()
    
    change_records = []
    
    for i in range(1, len(scan_dates)):
        prev_date = scan_dates[i-1]
        curr_date = scan_dates[i]
        
        prev_scan = historical_df[historical_df['scan_date'] == prev_date]
        curr_scan = historical_df[historical_df['scan_date'] == curr_date]
        
        prev_keys = set(prev_scan['hostname'].astype(str) + '|' + prev_scan['plugin_id'].astype(str))
        curr_keys = set(curr_scan['hostname'].astype(str) + '|' + curr_scan['plugin_id'].astype(str))
        
        new_findings = curr_keys - prev_keys
        resolved_findings = prev_keys - curr_keys
        persistent_findings = prev_keys & curr_keys
        
        change_records.append({
            'previous_scan_date': prev_date,
            'current_scan_date': curr_date,
            'days_between': (curr_date - prev_date).days,
            'new_findings': len(new_findings),
            'resolved_findings': len(resolved_findings),
            'persistent_findings': len(persistent_findings),
            'total_previous': len(prev_keys),
            'total_current': len(curr_keys),
            'net_change': len(curr_keys) - len(prev_keys)
        })
    
    scan_changes_df = pd.DataFrame(change_records)
    print(f"Analyzed {len(scan_changes_df)} scan transitions")
    
    return scan_changes_df


def save_to_database(historical_df: pd.DataFrame, lifecycle_df: pd.DataFrame, 
                     host_presence_df: pd.DataFrame, scan_changes_df: pd.DataFrame, 
                     db_path: str):
    """Save all data to SQLite database."""
    try:
        conn = sqlite3.connect(db_path)
        
        historical_df.to_sql('historical_findings', conn, if_exists='replace', index=False)
        lifecycle_df.to_sql('lifecycle_analysis', conn, if_exists='replace', index=False)
        host_presence_df.to_sql('host_presence', conn, if_exists='replace', index=False)
        scan_changes_df.to_sql('scan_changes', conn, if_exists='replace', index=False)
        
        conn.close()
        print(f"\nDatabase saved to: {db_path}")
        
    except Exception as e:
        print(f"Error saving database: {e}")
        raise


def load_existing_database(db_path: str) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Load data from existing SQLite database."""
    try:
        conn = sqlite3.connect(db_path)
        
        historical_df = pd.read_sql('SELECT * FROM historical_findings', conn)
        lifecycle_df = pd.read_sql('SELECT * FROM lifecycle_analysis', conn)
        host_presence_df = pd.read_sql('SELECT * FROM host_presence', conn)
        scan_changes_df = pd.read_sql('SELECT * FROM scan_changes', conn)
        
        historical_df['scan_date'] = pd.to_datetime(historical_df['scan_date'])
        lifecycle_df['first_seen'] = pd.to_datetime(lifecycle_df['first_seen'])
        lifecycle_df['last_seen'] = pd.to_datetime(lifecycle_df['last_seen'])
        host_presence_df['first_seen'] = pd.to_datetime(host_presence_df['first_seen'])
        host_presence_df['last_seen'] = pd.to_datetime(host_presence_df['last_seen'])
        scan_changes_df['previous_scan_date'] = pd.to_datetime(scan_changes_df['previous_scan_date'])
        scan_changes_df['current_scan_date'] = pd.to_datetime(scan_changes_df['current_scan_date'])
        
        conn.close()
        print(f"Loaded existing database from: {db_path}")
        
        return historical_df, lifecycle_df, host_presence_df, scan_changes_df
        
    except Exception as e:
        print(f"Error loading database: {e}")
        return pd.DataFrame(), pd.DataFrame(), pd.DataFrame(), pd.DataFrame()


def export_to_excel(historical_df: pd.DataFrame, lifecycle_df: pd.DataFrame, 
                   host_presence_df: pd.DataFrame, scan_changes_df: pd.DataFrame, 
                   output_path: str, include_info: bool = False):
    """Export analysis to Excel with multiple sheets and formatting."""
    try:
        with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
            summary_data = {
                'Metric': [
                    'Total Scans Analyzed',
                    'Date Range',
                    'Total Findings in Database',
                    'Info Findings',
                    'Findings in Analysis',
                    'Unique Findings Tracked',
                    'Hosts Tracked',
                    'Active Findings',
                    'Resolved Findings',
                    'Recurring Findings'
                ],
                'Value': [
                    len(historical_df['scan_date'].unique()),
                    f"{historical_df['scan_date'].min().strftime('%Y-%m-%d')} to {historical_df['scan_date'].max().strftime('%Y-%m-%d')}",
                    len(historical_df),
                    len(historical_df[historical_df['severity_text'] == 'Info']),
                    len(historical_df[historical_df['severity_text'] != 'Info']) if not include_info else len(historical_df),
                    len(lifecycle_df),
                    len(host_presence_df),
                    len(lifecycle_df[lifecycle_df['status'] == 'Active']),
                    len(lifecycle_df[lifecycle_df['status'] == 'Resolved']),
                    len(lifecycle_df[lifecycle_df['reappearances'] > 0])
                ]
            }
            summary_df = pd.DataFrame(summary_data)
            summary_df.to_excel(writer, sheet_name='Summary', index=False)
            
            lifecycle_df.to_excel(writer, sheet_name='Lifecycle Analysis', index=False)
            host_presence_df.to_excel(writer, sheet_name='Host Presence', index=False)
            scan_changes_df.to_excel(writer, sheet_name='Scan Changes', index=False)
            historical_df.to_excel(writer, sheet_name='All Findings', index=False)
            
            for sheet_name in writer.sheets:
                worksheet = writer.sheets[sheet_name]
                
                for column in worksheet.columns:
                    max_length = 0
                    column_letter = column[0].column_letter
                    for cell in column:
                        try:
                            if len(str(cell.value)) > max_length:
                                max_length = len(str(cell.value))
                        except:
                            pass
                    adjusted_width = min(max_length + 2, 50)
                    worksheet.column_dimensions[column_letter].width = adjusted_width
                
                worksheet.auto_filter.ref = worksheet.dimensions
                
                for row in worksheet.iter_rows(min_row=2, max_row=worksheet.max_row):
                    for cell in row:
                        cell.style = 'Normal'
        
        print(f"Excel export complete: {output_path}")
        
    except PermissionError:
        raise PermissionError(f"Cannot write to {output_path}. Please close the file if it is open.")
    except Exception as e:
        print(f"Error exporting to Excel: {e}")
        raise


class EnhancedHistoricalAnalysisGUI:
    """GUI for enhanced Nessus historical analysis with comprehensive visualizations."""
    
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Enhanced Nessus Historical Analysis & Visualization")
        self.window.geometry("1400x900")
        self.window.configure(bg='#2b2b2b')
        
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TNotebook', background='#2b2b2b', foreground='white')
        self.style.configure('TNotebook.Tab', background='#404040', foreground='white', padding=[10, 5])
        self.style.map('TNotebook.Tab', background=[('selected', '#505050')])
        self.style.configure('TCheckbutton', background='#2b2b2b', foreground='white')
        self.style.configure('TLabel', background='#2b2b2b', foreground='white')
        self.style.configure('TFrame', background='#2b2b2b')
        self.style.configure('TLabelFrame', background='#2b2b2b', foreground='white')
        self.style.configure('TButton', background='#404040', foreground='white')
        self.style.map('TButton', background=[('active', '#505050')])
        
        self.archive_paths = []
        self.plugins_db_path = None
        self.existing_db_path = None
        self.opdir_file_path = None
        self.include_info = tk.BooleanVar(value=False)
        
        self.filter_start_date = tk.StringVar()
        self.filter_end_date = tk.StringVar()
        self.use_date_filter = tk.BooleanVar(value=False)
        
        self.historical_df = pd.DataFrame()
        self.lifecycle_df = pd.DataFrame()
        self.host_presence_df = pd.DataFrame()
        self.scan_changes_df = pd.DataFrame()
        self.opdir_df = pd.DataFrame()
        
        self.viz_frames = {}
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the user interface with dark theme"""
        main_frame = ttk.Frame(self.window, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.window.columnconfigure(0, weight=1)
        self.window.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(3, weight=1)
        
        file_frame = ttk.LabelFrame(main_frame, text="File Selection", padding="10")
        file_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)
        file_frame.columnconfigure(1, weight=1)
        
        ttk.Label(file_frame, text="Nessus Archives:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.archives_label = ttk.Label(file_frame, text="No files selected (optional if database loaded)", foreground="gray")
        self.archives_label.grid(row=0, column=1, sticky=tk.W, padx=5)
        ttk.Button(file_frame, text="Select Archives", command=self.select_archives).grid(row=0, column=2, padx=5)
        
        ttk.Label(file_frame, text="Plugins DB (optional):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.plugins_label = ttk.Label(file_frame, text="None selected", foreground="gray")
        self.plugins_label.grid(row=1, column=1, sticky=tk.W, padx=5)
        ttk.Button(file_frame, text="Select Plugins DB", command=self.select_plugins_db).grid(row=1, column=2, padx=5)
        
        ttk.Label(file_frame, text="Existing DB (optional):").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.existing_db_label = ttk.Label(file_frame, text="None selected", foreground="gray")
        self.existing_db_label.grid(row=2, column=1, sticky=tk.W, padx=5)
        ttk.Button(file_frame, text="Load Existing DB", command=self.select_existing_db).grid(row=2, column=2, padx=5)
        
        ttk.Label(file_frame, text="OPDIR File (optional):").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.opdir_label = ttk.Label(file_frame, text="None selected", foreground="gray")
        self.opdir_label.grid(row=3, column=1, sticky=tk.W, padx=5)
        ttk.Button(file_frame, text="Select OPDIR File", command=self.select_opdir_file).grid(row=3, column=2, padx=5)
        
        options_frame = ttk.LabelFrame(main_frame, text="Analysis Options", padding="10")
        options_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        options_frame.columnconfigure(1, weight=1)
        
        info_checkbox = ttk.Checkbutton(
            options_frame, 
            text="Include Info-level findings in analysis",
            variable=self.include_info
        )
        info_checkbox.grid(row=0, column=0, sticky=tk.W, pady=5)
        
        date_filter_checkbox = ttk.Checkbutton(
            options_frame,
            text="Enable date range filter for visualizations",
            variable=self.use_date_filter,
            command=self.toggle_date_filter
        )
        date_filter_checkbox.grid(row=1, column=0, sticky=tk.W, pady=5)
        
        date_frame = ttk.Frame(options_frame)
        date_frame.grid(row=2, column=0, sticky=tk.W, pady=5)
        
        ttk.Label(date_frame, text="Start Date (YYYY-MM-DD):").pack(side=tk.LEFT, padx=5)
        self.start_date_entry = ttk.Entry(date_frame, textvariable=self.filter_start_date, width=15, state='disabled')
        self.start_date_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(date_frame, text="End Date (YYYY-MM-DD):").pack(side=tk.LEFT, padx=5)
        self.end_date_entry = ttk.Entry(date_frame, textvariable=self.filter_end_date, width=15, state='disabled')
        self.end_date_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(date_frame, text="Apply Filter", command=self.apply_filter).pack(side=tk.LEFT, padx=10)
        
        control_frame = ttk.Frame(main_frame)
        control_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=10)
        
        ttk.Button(control_frame, text="Process Archives", command=self.process_archives).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Export to Excel", command=self.export_excel).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Save Database", command=self.save_database).pack(side=tk.LEFT, padx=5)
        
        output_frame = ttk.LabelFrame(main_frame, text="Output", padding="10")
        output_frame.grid(row=3, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(0, weight=1)
        
        self.notebook = ttk.Notebook(output_frame)
        self.notebook.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        log_frame = ttk.Frame(self.notebook)
        self.notebook.add(log_frame, text="Log")
        
        self.log_text = tk.Text(log_frame, height=10, bg='#1e1e1e', fg='white', insertbackground='white')
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.config(yscrollcommand=scrollbar.set)
    
    def log(self, message: str):
        """Add message to log"""
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.see(tk.END)
        self.window.update()
    
    def select_archives(self):
        """Select Nessus archives or files"""
        filetypes = (
            ('Nessus files', '*.nessus'),
            ('ZIP archives', '*.zip'),
            ('All files', '*.*')
        )
        
        paths = filedialog.askopenfilenames(
            title='Select Nessus Archives or .nessus Files',
            filetypes=filetypes
        )
        
        if paths:
            self.archive_paths = list(paths)
            self.archives_label.config(
                text=f"{len(paths)} file(s) selected",
                foreground="white"
            )
            self.log(f"Selected {len(paths)} archive(s)")
    
    def select_plugins_db(self):
        """Select plugins database"""
        path = filedialog.askopenfilename(
            title='Select Plugins Database',
            filetypes=[('JSON files', '*.json'), ('All files', '*.*')]
        )
        
        if path:
            self.plugins_db_path = path
            self.plugins_label.config(
                text=os.path.basename(path),
                foreground="white"
            )
            self.log(f"Selected plugins database: {os.path.basename(path)}")
    
    def select_existing_db(self):
        """Select existing database"""
        path = filedialog.askopenfilename(
            title='Select Existing Database',
            filetypes=[('SQLite DB', '*.db'), ('All files', '*.*')]
        )
        
        if path:
            self.existing_db_path = path
            self.existing_db_label.config(
                text=os.path.basename(path),
                foreground="white"
            )
            self.log(f"Selected existing database: {os.path.basename(path)}")
    
    def select_opdir_file(self):
        """Select OPDIR spreadsheet"""
        filetypes = (
            ('Excel files', '*.xlsx'),
            ('Excel files', '*.xls'),
            ('CSV files', '*.csv'),
            ('All files', '*.*')
        )
        
        path = filedialog.askopenfilename(
            title='Select OPDIR Spreadsheet',
            filetypes=filetypes
        )
        
        if path:
            self.opdir_file_path = path
            self.opdir_label.config(
                text=os.path.basename(path),
                foreground="white"
            )
            self.log(f"Selected OPDIR file: {os.path.basename(path)}")
            
            try:
                self.opdir_df = load_and_process_opdir(path)
                if not self.opdir_df.empty:
                    self.log(f"Loaded {len(self.opdir_df)} OPDIR records")
                else:
                    self.log("Warning: OPDIR file loaded but no valid records found")
            except Exception as e:
                self.log(f"Error processing OPDIR file: {e}")
                self.opdir_df = pd.DataFrame()
    
    def toggle_date_filter(self):
        """Enable/disable date filter controls"""
        state = 'normal' if self.use_date_filter.get() else 'disabled'
        self.start_date_entry.config(state=state)
        self.end_date_entry.config(state=state)
        
        if self.use_date_filter.get() and not self.historical_df.empty:
            if not self.filter_start_date.get():
                start_date = self.historical_df['scan_date'].min().strftime('%Y-%m-%d')
                self.filter_start_date.set(start_date)
            if not self.filter_end_date.get():
                end_date = self.historical_df['scan_date'].max().strftime('%Y-%m-%d')
                self.filter_end_date.set(end_date)
    
    def get_filtered_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """Apply date and info filtering to DataFrame"""
        filtered_df = df.copy()
        
        if not self.include_info.get():
            filtered_df = filtered_df[filtered_df['severity_text'] != 'Info']
        
        if self.use_date_filter.get() and not filtered_df.empty:
            try:
                start_date = pd.to_datetime(self.filter_start_date.get())
                end_date = pd.to_datetime(self.filter_end_date.get()) + pd.Timedelta(days=1) - pd.Timedelta(seconds=1)
                
                if 'scan_date' in filtered_df.columns:
                    filtered_df = filtered_df[
                        (filtered_df['scan_date'] >= start_date) & 
                        (filtered_df['scan_date'] <= end_date)
                    ]
            except Exception as e:
                self.log(f"Error applying date filter: {e}")
        
        return filtered_df
    
    def get_filter_status_text(self) -> str:
        """Get current filter status as text"""
        filters = []
        if not self.include_info.get():
            filters.append("Info excluded")
        if self.use_date_filter.get():
            filters.append(f"Date: {self.filter_start_date.get()} to {self.filter_end_date.get()}")
        return ", ".join(filters) if filters else "No filters applied"
    
    def apply_filter(self):
        """Apply filters and refresh visualizations"""
        if self.historical_df.empty:
            messagebox.showwarning("No Data", "Please process archives first")
            return
        
        self.log("Applying filters and refreshing visualizations...")
        self.create_visualizations()
        self.log("Visualizations updated")
    
    def get_severity_colors(self) -> Dict[str, str]:
        """Get color mapping for severity levels"""
        return {
            'Critical': '#dc3545',
            'High': '#fd7e14',
            'Medium': '#ffc107',
            'Low': '#28a745',
            'Info': '#17a2b8'
        }
    
    def process_archives(self):
        """Process selected archives"""
        if not self.archive_paths and not self.existing_db_path:
            messagebox.showerror("Error", "Please select archives or load an existing database")
            return
        
        if self.existing_db_path and not self.archive_paths:
            try:
                include_info_val = self.include_info.get()
                self.historical_df, self.lifecycle_df, self.host_presence_df, self.scan_changes_df = load_existing_database(self.existing_db_path)
                
                if not include_info_val:
                    analysis_df = self.historical_df[self.historical_df['severity_text'] != 'Info'].copy()
                    self.lifecycle_df = generate_lifecycle_analysis(analysis_df)
                    self.scan_changes_df = analyze_scan_changes(analysis_df)
                
                if not self.opdir_df.empty:
                    self.log("Enriching findings with OPDIR data...")
                    self.historical_df = enrich_findings_with_opdir(self.historical_df, self.opdir_df)
                    self.lifecycle_df = enrich_findings_with_opdir(self.lifecycle_df, self.opdir_df)
                
                if not self.filter_start_date.get():
                    start_date = self.historical_df['scan_date'].min().strftime('%Y-%m-%d')
                    self.filter_start_date.set(start_date)
                if not self.filter_end_date.get():
                    end_date = self.historical_df['scan_date'].max().strftime('%Y-%m-%d')
                    self.filter_end_date.set(end_date)
                
                self.log(f"Total findings in database: {len(self.historical_df)}")
                self.log(f"Date range: {self.historical_df['scan_date'].min()} to {self.historical_df['scan_date'].max()}")
                if not include_info_val:
                    info_count = len(self.historical_df[self.historical_df['severity_text'] == 'Info'])
                    self.log(f"Info findings in database (excluded from analysis): {info_count}")
                self.log(f"Findings in analysis: {len(self.lifecycle_df)}")
                self.log(f"Hosts tracked: {len(self.host_presence_df)}")
                self.log(f"Scan changes: {len(self.scan_changes_df)}")
                
                self.create_visualizations()
                
                messagebox.showinfo("Success", "Existing database loaded and analyzed successfully!")
                
            except Exception as e:
                self.log(f"ERROR: {str(e)}")
                messagebox.showerror("Error", f"Database analysis failed: {str(e)}")
                import traceback
                traceback.print_exc()
            
            return
        
        self.log("="*60)
        self.log("Starting enhanced archive processing...")
        self.log("="*60)
        
        try:
            include_info_val = self.include_info.get()
            self.log(f"Processing with Info findings {'included' if include_info_val else 'excluded'} from analysis")
            
            self.historical_df, self.lifecycle_df, self.host_presence_df, self.scan_changes_df = process_historical_scans(
                self.archive_paths,
                self.plugins_db_path,
                self.existing_db_path,
                include_info_val
            )
            
            if self.historical_df.empty:
                messagebox.showerror("Error", "No findings extracted from archives")
                return
            
            if not self.opdir_df.empty:
                self.log("Enriching findings with OPDIR data...")
                self.historical_df = enrich_findings_with_opdir(self.historical_df, self.opdir_df)
                self.lifecycle_df = enrich_findings_with_opdir(self.lifecycle_df, self.opdir_df)
            
            if not self.filter_start_date.get():
                start_date = self.historical_df['scan_date'].min().strftime('%Y-%m-%d')
                self.filter_start_date.set(start_date)
            if not self.filter_end_date.get():
                end_date = self.historical_df['scan_date'].max().strftime('%Y-%m-%d')
                self.filter_end_date.set(end_date)
            
            self.log(f"Analysis complete!")
            self.log(f"Total findings in database: {len(self.historical_df)}")
            if not include_info_val:
                info_count = len(self.historical_df[self.historical_df['severity_text'] == 'Info'])
                self.log(f"Info findings in database (excluded from analysis): {info_count}")
            self.log(f"Findings in analysis: {len(self.lifecycle_df)}")
            self.log(f"Hosts tracked: {len(self.host_presence_df)}")
            self.log(f"Scan changes: {len(self.scan_changes_df)}")
            
            self.create_visualizations()
            
            messagebox.showinfo("Success", "Archives processed successfully with enhanced features!")
            
        except Exception as e:
            self.log(f"ERROR: {str(e)}")
            messagebox.showerror("Error", f"Processing failed: {str(e)}")
            import traceback
            traceback.print_exc()
    
    def create_visualizations(self):
        """Create all visualization tabs"""
        for tab_name in list(self.viz_frames.keys()):
            self.notebook.forget(self.viz_frames[tab_name])
        self.viz_frames = {}
        
        self.create_timeline_viz()
        self.create_host_presence_viz()
        self.create_scan_changes_viz()
        self.create_severity_trend_viz()
        self.create_source_file_viz()
        self.create_cvss_analysis_viz()
        self.create_network_analysis_viz()
        self.create_threat_intelligence_viz()
        self.create_remediation_effectiveness_viz()
        self.create_risk_heatmap_viz()
        self.create_compliance_dashboard_viz()
        self.create_host_viz()
        self.create_plugin_viz()
        self.create_lifecycle_viz()
    
    def create_timeline_viz(self):
        """Create timeline visualization"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Timeline")
        self.viz_frames['timeline'] = frame
        
        control_frame = ttk.Frame(frame)
        control_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
        
        status_label = ttk.Label(control_frame, text=f"Filters: {self.get_filter_status_text()}", foreground="orange")
        status_label.pack(side=tk.LEFT)
        
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8))
        fig.patch.set_facecolor('#2b2b2b')
        
        filtered_df = self.get_filtered_data(self.lifecycle_df)
        
        if not filtered_df.empty:
            timeline_data = filtered_df.groupby('first_seen').size().reset_index(name='count')
            ax1.plot(timeline_data['first_seen'], timeline_data['count'], marker='o', linewidth=2, color='#007bff')
            ax1.set_title('New Findings Over Time', fontsize=14, fontweight='bold', color='white')
            ax1.set_xlabel('Date', color='white')
            ax1.set_ylabel('New Findings', color='white')
            ax1.grid(True, alpha=0.3)
            ax1.set_facecolor('#2b2b2b')
            ax1.tick_params(colors='white')
            ax1.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
            plt.setp(ax1.xaxis.get_majorticklabels(), rotation=45, ha='right')
            
            severity_timeline = filtered_df.groupby(['first_seen', 'severity_text']).size().unstack(fill_value=0)
            colors = self.get_severity_colors()
            
            for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
                if severity in severity_timeline.columns:
                    ax2.plot(severity_timeline.index, severity_timeline[severity], 
                           marker='o', label=severity, linewidth=2, color=colors.get(severity, '#6c757d'))
            
            ax2.set_title('New Findings by Severity Over Time', fontsize=14, fontweight='bold', color='white')
            ax2.set_xlabel('Date', color='white')
            ax2.set_ylabel('Count', color='white')
            ax2.legend()
            ax2.grid(True, alpha=0.3)
            ax2.set_facecolor('#2b2b2b')
            ax2.tick_params(colors='white')
            ax2.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
            plt.setp(ax2.xaxis.get_majorticklabels(), rotation=45, ha='right')
        
        plt.tight_layout()
        plt.style.use('dark_background')
        
        canvas = FigureCanvasTkAgg(fig, frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def create_host_presence_viz(self):
        """Create host presence visualization"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Host Tracking")
        self.viz_frames['host_presence'] = frame
        
        control_frame = ttk.Frame(frame)
        control_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
        
        status_label = ttk.Label(control_frame, text=f"Filters: {self.get_filter_status_text()}", foreground="orange")
        status_label.pack(side=tk.LEFT)
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(14, 10))
        fig.patch.set_facecolor('#2b2b2b')
        
        filtered_host_presence = self.host_presence_df.copy()
        if self.use_date_filter.get() and not filtered_host_presence.empty:
            try:
                start_date = pd.to_datetime(self.filter_start_date.get())
                end_date = pd.to_datetime(self.filter_end_date.get()) + pd.Timedelta(days=1) - pd.Timedelta(seconds=1)
                
                filtered_host_presence = filtered_host_presence[
                    (filtered_host_presence['last_seen'] >= start_date) | 
                    (filtered_host_presence['first_seen'] <= end_date)
                ]
            except:
                pass
        
        if not filtered_host_presence.empty:
            presence_dist = filtered_host_presence['presence_rate'].value_counts(bins=5, sort=False)
            bars = ax1.bar(range(len(presence_dist)), presence_dist.values, color='#007bff')
            ax1.set_xticks(range(len(presence_dist)))
            ax1.set_xticklabels([f'{int(i.left)}-{int(i.right)}%' for i in presence_dist.index], color='white')
            ax1.set_title('Host Presence Rate Distribution', fontsize=12, fontweight='bold', color='white')
            ax1.set_ylabel('Number of Hosts', color='white')
            ax1.set_facecolor('#2b2b2b')
            ax1.tick_params(colors='white')
            
            for bar in bars:
                height = bar.get_height()
                ax1.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                        f'{int(height)}', ha='center', va='bottom', color='white', fontweight='bold')
            
            status_counts = filtered_host_presence['status'].value_counts()
            colors_status = ['#28a745', '#dc3545']
            ax2.pie(status_counts.values, labels=status_counts.index, autopct='%1.1f%%',
                   colors=colors_status[:len(status_counts)], startangle=90)
            ax2.set_title('Host Status', fontsize=12, fontweight='bold', color='white')
            ax2.set_facecolor('#2b2b2b')
            
            top_hosts = filtered_host_presence.nlargest(15, 'scans_present')
            bars = ax3.barh(range(len(top_hosts)), top_hosts['scans_present'].values, color='#28a745')
            ax3.set_yticks(range(len(top_hosts)))
            ax3.set_yticklabels(top_hosts['hostname'].values, color='white')
            ax3.set_title('Top 15 Most Frequently Seen Hosts', fontsize=12, fontweight='bold', color='white')
            ax3.set_xlabel('Scans Present', color='white')
            ax3.set_facecolor('#2b2b2b')
            ax3.tick_params(colors='white')
            
            for bar in bars:
                width = bar.get_width()
                ax3.text(width + width*0.01, bar.get_y() + bar.get_height()/2.,
                        f'{int(width)}', ha='left', va='center', color='white', fontweight='bold')
            
            filtered_host_presence['days_tracked'] = (filtered_host_presence['last_seen'] - filtered_host_presence['first_seen']).dt.days
            tracking_dist = pd.cut(filtered_host_presence['days_tracked'], bins=[0, 30, 90, 180, 365, float('inf')], 
                                  labels=['<30d', '30-90d', '90-180d', '180-365d', '>365d']).value_counts()
            bars = ax4.bar(range(len(tracking_dist)), tracking_dist.values, color='#fd7e14')
            ax4.set_xticks(range(len(tracking_dist)))
            ax4.set_xticklabels(tracking_dist.index, color='white')
            ax4.set_title('Host Tracking Duration', fontsize=12, fontweight='bold', color='white')
            ax4.set_ylabel('Number of Hosts', color='white')
            ax4.set_facecolor('#2b2b2b')
            ax4.tick_params(colors='white')
            
            for bar in bars:
                height = bar.get_height()
                ax4.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                        f'{int(height)}', ha='center', va='bottom', color='white', fontweight='bold')
        
        plt.tight_layout()
        plt.style.use('dark_background')
        
        canvas = FigureCanvasTkAgg(fig, frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    """
Enhanced Nessus Historical Analysis - Part 2: All Visualization Methods
This continues from Part 1 and includes all visualization methods for the GUI class.
Add these methods to the EnhancedHistoricalAnalysisGUI class from Part 1.
"""

    def create_scan_changes_viz(self):
        """Create scan changes visualization"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Scan Changes")
        self.viz_frames['scan_changes'] = frame
        
        control_frame = ttk.Frame(frame)
        control_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
        
        status_label = ttk.Label(control_frame, text=f"Filters: {self.get_filter_status_text()}", foreground="orange")
        status_label.pack(side=tk.LEFT)
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(14, 10))
        fig.patch.set_facecolor('#2b2b2b')
        
        if not self.scan_changes_df.empty:
            ax1.plot(self.scan_changes_df['current_scan_date'], self.scan_changes_df['new_findings'], 
                    marker='o', linewidth=2, color='#dc3545', label='New')
            ax1.plot(self.scan_changes_df['current_scan_date'], self.scan_changes_df['resolved_findings'], 
                    marker='s', linewidth=2, color='#28a745', label='Resolved')
            ax1.set_title('New vs Resolved Findings', fontsize=12, fontweight='bold', color='white')
            ax1.set_xlabel('Scan Date', color='white')
            ax1.set_ylabel('Count', color='white')
            ax1.legend()
            ax1.grid(True, alpha=0.3)
            ax1.set_facecolor('#2b2b2b')
            ax1.tick_params(colors='white')
            ax1.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
            plt.setp(ax1.xaxis.get_majorticklabels(), rotation=45, ha='right')
            
            ax2.plot(self.scan_changes_df['current_scan_date'], self.scan_changes_df['net_change'], 
                    marker='o', linewidth=2, color='#007bff')
            ax2.axhline(y=0, color='white', linestyle='--', alpha=0.5)
            ax2.set_title('Net Change in Findings', fontsize=12, fontweight='bold', color='white')
            ax2.set_xlabel('Scan Date', color='white')
            ax2.set_ylabel('Net Change', color='white')
            ax2.grid(True, alpha=0.3)
            ax2.set_facecolor('#2b2b2b')
            ax2.tick_params(colors='white')
            ax2.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
            plt.setp(ax2.xaxis.get_majorticklabels(), rotation=45, ha='right')
            
            bars = ax3.bar(range(len(self.scan_changes_df)), self.scan_changes_df['days_between'].values, color='#ffc107')
            ax3.set_xticks(range(len(self.scan_changes_df)))
            ax3.set_xticklabels([d.strftime('%m/%d') for d in self.scan_changes_df['current_scan_date']], 
                               rotation=45, ha='right', color='white')
            ax3.set_title('Days Between Scans', fontsize=12, fontweight='bold', color='white')
            ax3.set_ylabel('Days', color='white')
            ax3.set_facecolor('#2b2b2b')
            ax3.tick_params(colors='white')
            
            for bar in bars:
                height = bar.get_height()
                ax3.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                        f'{int(height)}', ha='center', va='bottom', color='white', fontweight='bold')
            
            width = 0.35
            x = range(len(self.scan_changes_df))
            ax4.bar([i - width/2 for i in x], self.scan_changes_df['total_previous'].values, 
                   width, label='Previous', color='#6c757d')
            ax4.bar([i + width/2 for i in x], self.scan_changes_df['total_current'].values, 
                   width, label='Current', color='#007bff')
            ax4.set_xticks(x)
            ax4.set_xticklabels([d.strftime('%m/%d') for d in self.scan_changes_df['current_scan_date']], 
                               rotation=45, ha='right', color='white')
            ax4.set_title('Total Findings Comparison', fontsize=12, fontweight='bold', color='white')
            ax4.set_ylabel('Total Findings', color='white')
            ax4.legend()
            ax4.set_facecolor('#2b2b2b')
            ax4.tick_params(colors='white')
        
        plt.tight_layout()
        plt.style.use('dark_background')
        
        canvas = FigureCanvasTkAgg(fig, frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def create_severity_trend_viz(self):
        """Create severity trend visualization"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Severity Trends")
        self.viz_frames['severity_trend'] = frame
        
        control_frame = ttk.Frame(frame)
        control_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
        
        status_label = ttk.Label(control_frame, text=f"Filters: {self.get_filter_status_text()}", foreground="orange")
        status_label.pack(side=tk.LEFT)
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(14, 10))
        fig.patch.set_facecolor('#2b2b2b')
        
        filtered_df = self.get_filtered_data(self.lifecycle_df)
        
        if not filtered_df.empty:
            severity_counts = filtered_df['severity_text'].value_counts()
            colors = self.get_severity_colors()
            severity_colors = [colors.get(sev, '#6c757d') for sev in severity_counts.index]
            
            bars = ax1.bar(severity_counts.index, severity_counts.values, color=severity_colors)
            ax1.set_title('Findings by Severity', fontsize=12, fontweight='bold', color='white')
            ax1.set_ylabel('Count', color='white')
            ax1.set_facecolor('#2b2b2b')
            ax1.tick_params(colors='white')
            
            for bar in bars:
                height = bar.get_height()
                ax1.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                        f'{int(height)}', ha='center', va='bottom', color='white', fontweight='bold')
            
            status_by_severity = filtered_df.groupby(['severity_text', 'status']).size().unstack(fill_value=0)
            status_by_severity.plot(kind='bar', stacked=True, ax=ax2, color=['#28a745', '#dc3545'])
            ax2.set_title('Active vs Resolved by Severity', fontsize=12, fontweight='bold', color='white')
            ax2.set_ylabel('Count', color='white')
            ax2.set_xlabel('')
            ax2.legend(title='Status', loc='upper right')
            ax2.set_facecolor('#2b2b2b')
            ax2.tick_params(colors='white')
            plt.setp(ax2.xaxis.get_majorticklabels(), rotation=45, ha='right')
            
            recurring = len(filtered_df[filtered_df['reappearances'] > 0])
            one_time = len(filtered_df[filtered_df['reappearances'] == 0])
            
            bars = ax3.bar(['Recurring', 'One-time'], [recurring, one_time], color=['#dc3545', '#28a745'])
            ax3.set_title('Recurring vs One-time Findings', fontsize=12, fontweight='bold', color='white')
            ax3.set_ylabel('Number of Findings', color='white')
            ax3.set_facecolor('#2b2b2b')
            ax3.tick_params(colors='white')
            
            for bar in bars:
                height = bar.get_height()
                ax3.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                        f'{int(height)}', ha='center', va='bottom', color='white', fontweight='bold')
            
            if not self.opdir_df.empty and 'opdir_days_to_due' in filtered_df.columns:
                opdir_findings = filtered_df[filtered_df['opdir_days_to_due'].notna()]
                if not opdir_findings.empty:
                    overdue = len(opdir_findings[opdir_findings['opdir_days_to_due'] < 0])
                    due_soon = len(opdir_findings[(opdir_findings['opdir_days_to_due'] >= 0) & 
                                                 (opdir_findings['opdir_days_to_due'] <= 30)])
                    on_track = len(opdir_findings[opdir_findings['opdir_days_to_due'] > 30])
                    
                    bars = ax4.bar(['Overdue', 'Due Soon (<30d)', 'On Track (>30d)'], 
                                  [overdue, due_soon, on_track], 
                                  color=['#dc3545', '#ffc107', '#28a745'])
                    ax4.set_title('OPDIR Due Date Compliance', fontsize=12, fontweight='bold', color='white')
                    ax4.set_ylabel('Number of Findings', color='white')
                    ax4.set_facecolor('#2b2b2b')
                    ax4.tick_params(colors='white')
                    
                    for bar in bars:
                        height = bar.get_height()
                        if height > 0:
                            ax4.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                                    f'{int(height)}', ha='center', va='bottom', color='white', fontweight='bold')
                else:
                    ax4.text(0.5, 0.5, 'No OPDIR due date data', ha='center', va='center', 
                            transform=ax4.transAxes, color='white', fontsize=12)
                    ax4.set_facecolor('#2b2b2b')
            else:
                ax4.text(0.5, 0.5, 'OPDIR data not available', ha='center', va='center', 
                        transform=ax4.transAxes, color='white', fontsize=12)
                ax4.set_facecolor('#2b2b2b')
        
        plt.tight_layout()
        plt.style.use('dark_background')
        
        canvas = FigureCanvasTkAgg(fig, frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def create_source_file_viz(self):
        """Create source file analysis visualization"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Source Files")
        self.viz_frames['source_files'] = frame
        
        control_frame = ttk.Frame(frame)
        control_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
        
        status_label = ttk.Label(control_frame, text=f"Filters: {self.get_filter_status_text()}", foreground="orange")
        status_label.pack(side=tk.LEFT)
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(14, 10))
        fig.patch.set_facecolor('#2b2b2b')
        
        filtered_df = self.get_filtered_data(self.historical_df)
        
        if not filtered_df.empty:
            source_counts = filtered_df['scan_file'].value_counts().head(15)
            bars = ax1.barh(range(len(source_counts)), source_counts.values, color='#007bff')
            ax1.set_yticks(range(len(source_counts)))
            ax1.set_yticklabels([f[:30] + '...' if len(f) > 30 else f for f in source_counts.index], color='white')
            ax1.set_title('Findings per Source File (Top 15)', fontsize=12, fontweight='bold', color='white')
            ax1.set_xlabel('Number of Findings', color='white')
            ax1.set_facecolor('#2b2b2b')
            ax1.tick_params(colors='white')
            
            for bar in bars:
                width = bar.get_width()
                ax1.text(width + width*0.01, bar.get_y() + bar.get_height()/2.,
                        f'{int(width)}', ha='left', va='center', color='white', fontweight='bold')
            
            scan_timeline = filtered_df.groupby(['scan_date', 'scan_file']).size().reset_index(name='findings')
            unique_scans = scan_timeline.groupby('scan_date')['scan_file'].nunique().reset_index(name='file_count')
            
            ax2.plot(unique_scans['scan_date'], unique_scans['file_count'], marker='o', linewidth=2, color='#28a745')
            ax2.set_title('Source Files per Scan Date', fontsize=12, fontweight='bold', color='white')
            ax2.set_xlabel('Scan Date', color='white')
            ax2.set_ylabel('Number of Source Files', color='white')
            ax2.set_facecolor('#2b2b2b')
            ax2.tick_params(colors='white')
            ax2.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
            plt.setp(ax2.xaxis.get_majorticklabels(), rotation=45, ha='right')
            
            if 'severity_text' in filtered_df.columns:
                source_severity = filtered_df.groupby(['scan_file', 'severity_text']).size().unstack(fill_value=0)
                top_sources = source_severity.sum(axis=1).nlargest(10)
                plot_data = source_severity.loc[top_sources.index]
                
                colors = self.get_severity_colors()
                bottom = None
                for severity in ['Critical', 'High', 'Medium', 'Low']:
                    if severity in plot_data.columns:
                        bars = ax3.bar(range(len(plot_data)), plot_data[severity], 
                                      bottom=bottom, label=severity, color=colors.get(severity))
                        
                        for i, bar in enumerate(bars):
                            height = bar.get_height()
                            if height > 0:
                                ax3.text(bar.get_x() + bar.get_width()/2., 
                                        bar.get_y() + height/2.,
                                        f'{int(height)}', ha='center', va='center', 
                                        color='white', fontweight='bold', fontsize=8)
                        
                        bottom = plot_data[severity] if bottom is None else bottom + plot_data[severity]
                
                ax3.set_xticks(range(len(plot_data)))
                ax3.set_xticklabels([f[:15] + '...' if len(f) > 15 else f for f in plot_data.index], 
                                   rotation=45, ha='right', color='white')
                ax3.set_title('Severity Distribution by Source (Top 10)', fontsize=12, fontweight='bold', color='white')
                ax3.set_ylabel('Number of Findings', color='white')
                ax3.legend(loc='upper right')
                ax3.set_facecolor('#2b2b2b')
                ax3.tick_params(colors='white')
            
            scan_dates = sorted(filtered_df['scan_date'].unique())
            if len(scan_dates) > 1:
                gaps = []
                gap_labels = []
                for i in range(1, len(scan_dates)):
                    gap_days = (scan_dates[i] - scan_dates[i-1]).days
                    gaps.append(gap_days)
                    gap_labels.append(f"{scan_dates[i-1].strftime('%m/%d')} to {scan_dates[i].strftime('%m/%d')}")
                
                bars = ax4.bar(range(len(gaps)), gaps, color='#fd7e14')
                ax4.set_xticks(range(len(gaps)))
                ax4.set_xticklabels(gap_labels, rotation=45, ha='right', color='white')
                ax4.set_title('Days Between Scans', fontsize=12, fontweight='bold', color='white')
                ax4.set_ylabel('Days', color='white')
                ax4.set_facecolor('#2b2b2b')
                ax4.tick_params(colors='white')
                
                for bar in bars:
                    height = bar.get_height()
                    ax4.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                            f'{int(height)}', ha='center', va='bottom', color='white', fontweight='bold')
        
        plt.tight_layout()
        plt.style.use('dark_background')
        
        canvas = FigureCanvasTkAgg(fig, frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def create_cvss_analysis_viz(self):
        """Create CVSS score analysis visualization"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="CVSS Analysis")
        self.viz_frames['cvss_analysis'] = frame
        
        control_frame = ttk.Frame(frame)
        control_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
        
        status_label = ttk.Label(control_frame, text=f"Filters: {self.get_filter_status_text()}", foreground="orange")
        status_label.pack(side=tk.LEFT)
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(14, 10))
        fig.patch.set_facecolor('#2b2b2b')
        
        filtered_df = self.get_filtered_data(self.historical_df)
        
        if not filtered_df.empty and 'cvss3_base_score' in filtered_df.columns:
            cvss3_data = pd.to_numeric(filtered_df['cvss3_base_score'], errors='coerce')
            cvss3_data = cvss3_data.dropna()
            
            if not cvss3_data.empty:
                ax1.hist(cvss3_data, bins=20, color='#007bff', edgecolor='white', alpha=0.7)
                ax1.set_title('CVSS v3 Score Distribution', fontsize=12, fontweight='bold', color='white')
                ax1.set_xlabel('CVSS v3 Score', color='white')
                ax1.set_ylabel('Frequency', color='white')
                ax1.set_facecolor('#2b2b2b')
                ax1.tick_params(colors='white')
            
            cvss_timeline = filtered_df[filtered_df['cvss3_base_score'].notna()].copy()
            cvss_timeline['cvss3_numeric'] = pd.to_numeric(cvss_timeline['cvss3_base_score'], errors='coerce')
            cvss_by_date = cvss_timeline.groupby('scan_date')['cvss3_numeric'].mean()
            
            if not cvss_by_date.empty:
                ax2.plot(cvss_by_date.index, cvss_by_date.values, marker='o', linewidth=2, color='#dc3545')
                ax2.set_title('Average CVSS Score Over Time', fontsize=12, fontweight='bold', color='white')
                ax2.set_xlabel('Scan Date', color='white')
                ax2.set_ylabel('Average CVSS Score', color='white')
                ax2.set_facecolor('#2b2b2b')
                ax2.tick_params(colors='white')
                ax2.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
                plt.setp(ax2.xaxis.get_majorticklabels(), rotation=45, ha='right')
            
            if 'severity_text' in filtered_df.columns and not cvss3_data.empty:
                cvss_by_severity = filtered_df[filtered_df['cvss3_base_score'].notna()].copy()
                cvss_by_severity['cvss3_numeric'] = pd.to_numeric(cvss_by_severity['cvss3_base_score'], errors='coerce')
                
                severities = ['Critical', 'High', 'Medium', 'Low']
                colors = self.get_severity_colors()
                
                box_data = []
                box_labels = []
                box_colors = []
                for severity in severities:
                    severity_data = cvss_by_severity[cvss_by_severity['severity_text'] == severity]['cvss3_numeric']
                    if not severity_data.empty:
                        box_data.append(severity_data)
                        box_labels.append(severity)
                        box_colors.append(colors.get(severity))
                
                if box_data:
                    bp = ax3.boxplot(box_data, labels=box_labels, patch_artist=True)
                    for patch, color in zip(bp['boxes'], box_colors):
                        patch.set_facecolor(color)
                    
                    ax3.set_title('CVSS Score Ranges by Severity', fontsize=12, fontweight='bold', color='white')
                    ax3.set_ylabel('CVSS v3 Score', color='white')
                    ax3.set_facecolor('#2b2b2b')
                    ax3.tick_params(colors='white')
            
            has_cve = len(filtered_df[filtered_df['cves'].notna() & (filtered_df['cves'] != '')])
            no_cve = len(filtered_df) - has_cve
            
            bars = ax4.bar(['Has CVE', 'No CVE'], [has_cve, no_cve], color=['#dc3545', '#6c757d'])
            ax4.set_title('CVE Coverage', fontsize=12, fontweight='bold', color='white')
            ax4.set_ylabel('Number of Findings', color='white')
            ax4.set_facecolor('#2b2b2b')
            ax4.tick_params(colors='white')
            
            for bar in bars:
                height = bar.get_height()
                ax4.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                        f'{int(height)}', ha='center', va='bottom', color='white', fontweight='bold')
        
        plt.tight_layout()
        plt.style.use('dark_background')
        
        canvas = FigureCanvasTkAgg(fig, frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def create_network_analysis_viz(self):
        """Create network/port analysis visualization"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Network Analysis")
        self.viz_frames['network_analysis'] = frame
        
        control_frame = ttk.Frame(frame)
        control_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
        
        status_label = ttk.Label(control_frame, text=f"Filters: {self.get_filter_status_text()}", foreground="orange")
        status_label.pack(side=tk.LEFT)
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(14, 10))
        fig.patch.set_facecolor('#2b2b2b')
        
        filtered_df = self.get_filtered_data(self.historical_df)
        
        if not filtered_df.empty:
            if 'port' in filtered_df.columns:
                port_findings = filtered_df[filtered_df['port'].notna() & (filtered_df['port'] != 0)]
                if not port_findings.empty:
                    port_counts = port_findings['port'].value_counts().head(15)
                    bars = ax1.barh(range(len(port_counts)), port_counts.values, color='#007bff')
                    ax1.set_yticks(range(len(port_counts)))
                    ax1.set_yticklabels([f'Port {int(p)}' for p in port_counts.index], color='white')
                    ax1.set_title('Most Affected Ports (Top 15)', fontsize=12, fontweight='bold', color='white')
                    ax1.set_xlabel('Number of Findings', color='white')
                    ax1.set_facecolor('#2b2b2b')
                    ax1.tick_params(colors='white')
                    
                    for bar in bars:
                        width = bar.get_width()
                        ax1.text(width + width*0.01, bar.get_y() + bar.get_height()/2.,
                                f'{int(width)}', ha='left', va='center', color='white', fontweight='bold')
            
            if 'protocol' in filtered_df.columns:
                protocol_findings = filtered_df[filtered_df['protocol'].notna()]
                if not protocol_findings.empty:
                    protocol_counts = protocol_findings['protocol'].value_counts()
                    colors_proto = ['#28a745', '#007bff', '#ffc107']
                    ax2.pie(protocol_counts.values, labels=protocol_counts.index, autopct='%1.1f%%',
                           colors=colors_proto[:len(protocol_counts)], startangle=90)
                    ax2.set_title('Protocol Distribution', fontsize=12, fontweight='bold', color='white')
                    ax2.set_facecolor('#2b2b2b')
            
            host_finding_counts = filtered_df.groupby('hostname').size().reset_index(name='finding_count')
            top_hosts = host_finding_counts.nlargest(15, 'finding_count')
            
            bars = ax3.barh(range(len(top_hosts)), top_hosts['finding_count'].values, color='#dc3545')
            ax3.set_yticks(range(len(top_hosts)))
            ax3.set_yticklabels(top_hosts['hostname'].values, color='white')
            ax3.set_title('Hosts with Most Findings (Top 15)', fontsize=12, fontweight='bold', color='white')
            ax3.set_xlabel('Number of Findings', color='white')
            ax3.set_facecolor('#2b2b2b')
            ax3.tick_params(colors='white')
            
            for bar in bars:
                width = bar.get_width()
                ax3.text(width + width*0.01, bar.get_y() + bar.get_height()/2.,
                        f'{int(width)}', ha='left', va='center', color='white', fontweight='bold')
            
            ax4.text(0.5, 0.5, 'Port vs Severity heatmap\nwould appear here', ha='center', va='center', 
                    transform=ax4.transAxes, color='white', fontsize=12)
            ax4.set_facecolor('#2b2b2b')
        
        plt.tight_layout()
        plt.style.use('dark_background')
        
        canvas = FigureCanvasTkAgg(fig, frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def create_threat_intelligence_viz(self):
        """Create threat intelligence and CVE/IAVx analysis"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Threat Intel")
        self.viz_frames['threat_intel'] = frame
        
        control_frame = ttk.Frame(frame)
        control_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
        
        status_label = ttk.Label(control_frame, text=f"Filters: {self.get_filter_status_text()}", foreground="orange")
        status_label.pack(side=tk.LEFT)
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(14, 10))
        fig.patch.set_facecolor('#2b2b2b')
        
        filtered_df = self.get_filtered_data(self.historical_df)
        
        if not filtered_df.empty:
            cve_findings = filtered_df[filtered_df['cves'].notna() & (filtered_df['cves'] != '')]
            if not cve_findings.empty:
                all_cves = []
                for cves in cve_findings['cves']:
                    all_cves.extend([cve.strip() for cve in str(cves).split('\n') if cve.strip()])
                
                if all_cves:
                    cve_counts = pd.Series(all_cves).value_counts().head(15)
                    bars = ax1.barh(range(len(cve_counts)), cve_counts.values, color='#dc3545')
                    ax1.set_yticks(range(len(cve_counts)))
                    ax1.set_yticklabels(cve_counts.index, color='white')
                    ax1.set_title('Most Frequent CVEs (Top 15)', fontsize=12, fontweight='bold', color='white')
                    ax1.set_xlabel('Number of Affected Hosts', color='white')
                    ax1.set_facecolor('#2b2b2b')
                    ax1.tick_params(colors='white')
                    
                    for bar in bars:
                        width = bar.get_width()
                        ax1.text(width + width*0.01, bar.get_y() + bar.get_height()/2.,
                                f'{int(width)}', ha='left', va='center', color='white', fontweight='bold')
            
            iavx_findings = filtered_df[filtered_df['iavx'].notna() & (filtered_df['iavx'] != '')]
            if not iavx_findings.empty:
                all_iavx = []
                for iavx in iavx_findings['iavx']:
                    all_iavx.extend([ref.strip() for ref in str(iavx).split('\n') if ref.strip()])
                
                if all_iavx:
                    iavx_types = [ref.split(':')[0] if ':' in ref else ref[:4] for ref in all_iavx]
                    iavx_type_counts = pd.Series(iavx_types).value_counts()
                    
                    colors_iavx = ['#fd7e14', '#007bff', '#28a745']
                    ax2.pie(iavx_type_counts.values, labels=iavx_type_counts.index, autopct='%1.1f%%',
                           colors=colors_iavx[:len(iavx_type_counts)], startangle=90)
                    ax2.set_title('IAVx Type Distribution', fontsize=12, fontweight='bold', color='white')
                    ax2.set_facecolor('#2b2b2b')
            
            has_cve = len(filtered_df[filtered_df['cves'].notna() & (filtered_df['cves'] != '')])
            no_cve = len(filtered_df) - has_cve
            
            bars = ax3.bar(['Has CVE', 'No CVE'], [has_cve, no_cve], color=['#dc3545', '#6c757d'])
            ax3.set_title('CVE Coverage', fontsize=12, fontweight='bold', color='white')
            ax3.set_ylabel('Number of Findings', color='white')
            ax3.set_facecolor('#2b2b2b')
            ax3.tick_params(colors='white')
            
            for bar in bars:
                height = bar.get_height()
                ax3.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                        f'{int(height)}', ha='center', va='bottom', color='white', fontweight='bold')
            
            if not self.opdir_df.empty and 'opdir_number' in filtered_df.columns:
                has_opdir = len(filtered_df[filtered_df['opdir_number'].notna()])
                no_opdir = len(filtered_df) - has_opdir
                
                bars = ax4.bar(['Has OPDIR', 'No OPDIR'], [has_opdir, no_opdir], color=['#28a745', '#6c757d'])
                ax4.set_title('OPDIR Coverage', fontsize=12, fontweight='bold', color='white')
                ax4.set_ylabel('Number of Findings', color='white')
                ax4.set_facecolor('#2b2b2b')
                ax4.tick_params(colors='white')
                
                for bar in bars:
                    height = bar.get_height()
                    ax4.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                            f'{int(height)}', ha='center', va='bottom', color='white', fontweight='bold')
            else:
                ax4.text(0.5, 0.5, 'OPDIR data not available', ha='center', va='center', 
                        transform=ax4.transAxes, color='white', fontsize=12)
                ax4.set_facecolor('#2b2b2b')
        
        plt.tight_layout()
        plt.style.use('dark_background')
        
        canvas = FigureCanvasTkAgg(fig, frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def create_remediation_effectiveness_viz(self):
        """Create remediation effectiveness analysis"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Remediation")
        self.viz_frames['remediation'] = frame
        
        control_frame = ttk.Frame(frame)
        control_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
        
        status_label = ttk.Label(control_frame, text=f"Filters: {self.get_filter_status_text()}", foreground="orange")
        status_label.pack(side=tk.LEFT)
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(14, 10))
        fig.patch.set_facecolor('#2b2b2b')
        
        filtered_df = self.get_filtered_data(self.lifecycle_df)
        
        if not filtered_df.empty:
            resolved_findings = filtered_df[filtered_df['status'] == 'Resolved']
            
            if not resolved_findings.empty:
                resolved_findings['resolution_time'] = (resolved_findings['last_seen'] - resolved_findings['first_seen']).dt.days
                
                time_buckets = pd.cut(resolved_findings['resolution_time'], 
                                     bins=[0, 30, 90, 180, 365, float('inf')],
                                     labels=['<30d', '30-90d', '90-180d', '180-365d', '>365d'])
                time_dist = time_buckets.value_counts()
                
                bars = ax1.bar(range(len(time_dist)), time_dist.values, color='#28a745')
                ax1.set_xticks(range(len(time_dist)))
                ax1.set_xticklabels(time_dist.index, color='white')
                ax1.set_title('Time to Resolution Distribution', fontsize=12, fontweight='bold', color='white')
                ax1.set_ylabel('Number of Findings', color='white')
                ax1.set_facecolor('#2b2b2b')
                ax1.tick_params(colors='white')
                
                for bar in bars:
                    height = bar.get_height()
                    ax1.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                            f'{int(height)}', ha='center', va='bottom', color='white', fontweight='bold')
                
                if 'severity_text' in resolved_findings.columns:
                    severity_resolution = resolved_findings.groupby('severity_text')['resolution_time'].mean()
                    colors = self.get_severity_colors()
                    severity_colors = [colors.get(sev, '#6c757d') for sev in severity_resolution.index]
                    
                    bars = ax2.bar(severity_resolution.index, severity_resolution.values, color=severity_colors)
                    ax2.set_title('Average Resolution Time by Severity', fontsize=12, fontweight='bold', color='white')
                    ax2.set_ylabel('Average Days', color='white')
                    ax2.set_facecolor('#2b2b2b')
                    ax2.tick_params(colors='white')
                    
                    for bar in bars:
                        height = bar.get_height()
                        ax2.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                                f'{height:.1f}', ha='center', va='bottom', color='white', fontweight='bold')
            
            age_buckets = pd.cut(filtered_df['days_open'], 
                                bins=[0, 30, 90, 180, 365, float('inf')],
                                labels=['<30d', '30-90d', '90-180d', '180-365d', '>365d'])
            age_counts = age_buckets.value_counts()
            
            bars = ax3.bar(range(len(age_counts)), age_counts.values, color='#fd7e14')
            ax3.set_xticks(range(len(age_counts)))
            ax3.set_xticklabels(age_counts.index, rotation=45, ha='right', color='white')
            ax3.set_title('Finding Age Distribution', fontsize=12, fontweight='bold', color='white')
            ax3.set_ylabel('Number of Findings', color='white')
            ax3.set_facecolor('#2b2b2b')
            ax3.tick_params(colors='white')
            
            for bar in bars:
                height = bar.get_height()
                ax3.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                        f'{int(height)}', ha='center', va='bottom', color='white', fontweight='bold')
            
            if 'severity_text' in filtered_df.columns and not resolved_findings.empty:
                sla_targets = {'Critical': 30, 'High': 90, 'Medium': 180, 'Low': 365}
                compliance_data = []
                
                for severity, target_days in sla_targets.items():
                    severity_findings = resolved_findings[resolved_findings['severity_text'] == severity]
                    if not severity_findings.empty:
                        within_sla = len(severity_findings[severity_findings['resolution_time'] <= target_days])
                        total_severity = len(severity_findings)
                        compliance_rate = (within_sla / total_severity) * 100 if total_severity > 0 else 0
                        compliance_data.append({'severity': severity, 'compliance': compliance_rate})
                
                if compliance_data:
                    compliance_df = pd.DataFrame(compliance_data)
                    colors = self.get_severity_colors()
                    severity_colors = [colors.get(sev, '#6c757d') for sev in compliance_df['severity']]
                    
                    bars = ax4.bar(compliance_df['severity'], compliance_df['compliance'], color=severity_colors)
                    ax4.set_title('SLA Compliance by Severity', fontsize=12, fontweight='bold', color='white')
                    ax4.set_ylabel('Compliance Rate (%)', color='white')
                    ax4.set_ylim(0, 100)
                    ax4.axhline(y=80, color='#ffc107', linestyle='--', alpha=0.7, label='80% Target')
                    ax4.legend()
                    ax4.set_facecolor('#2b2b2b')
                    ax4.tick_params(colors='white')
                    
                    for bar in bars:
                        height = bar.get_height()
                        ax4.text(bar.get_x() + bar.get_width()/2., height + 2,
                                f'{height:.1f}%', ha='center', va='bottom', color='white', fontweight='bold')
                else:
                    ax4.text(0.5, 0.5, 'No SLA data available', ha='center', va='center', 
                            transform=ax4.transAxes, color='white', fontsize=12)
                    ax4.set_facecolor('#2b2b2b')
            else:
                ax4.text(0.5, 0.5, 'No resolution data available', ha='center', va='center', 
                        transform=ax4.transAxes, color='white', fontsize=12)
                ax4.set_facecolor('#2b2b2b')
        
        plt.tight_layout()
        plt.style.use('dark_background')
        
        canvas = FigureCanvasTkAgg(fig, frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def create_risk_heatmap_viz(self):
        """Create risk assessment heatmaps"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Risk Heatmaps")
        self.viz_frames['risk_heatmaps'] = frame
        
        control_frame = ttk.Frame(frame)
        control_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
        
        status_label = ttk.Label(control_frame, text=f"Filters: {self.get_filter_status_text()}", foreground="orange")
        status_label.pack(side=tk.LEFT)
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(14, 10))
        fig.patch.set_facecolor('#2b2b2b')
        
        filtered_df = self.get_filtered_data(self.historical_df)
        
        if not filtered_df.empty:
            host_risk = filtered_df.groupby('hostname').agg({
                'severity_value': 'max',
                'plugin_id': 'count'
            }).reset_index()
            host_risk.columns = ['hostname', 'max_severity', 'finding_count']
            
            severity_map = {4: 'Critical', 3: 'High', 2: 'Medium', 1: 'Low', 0: 'Info'}
            host_risk['severity_label'] = host_risk['max_severity'].map(severity_map)
            
            risk_matrix = host_risk.groupby('severity_label')['finding_count'].mean()
            
            colors = self.get_severity_colors()
            risk_colors = [colors.get(sev, '#6c757d') for sev in risk_matrix.index]
            
            bars = ax1.bar(risk_matrix.index, risk_matrix.values, color=risk_colors)
            ax1.set_title('Average Findings per Host by Risk Level', fontsize=12, fontweight='bold', color='white')
            ax1.set_ylabel('Average Finding Count', color='white')
            ax1.set_facecolor('#2b2b2b')
            ax1.tick_params(colors='white')
            
            for bar in bars:
                height = bar.get_height()
                ax1.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                        f'{height:.1f}', ha='center', va='bottom', color='white', fontweight='bold')
            
            if 'family' in filtered_df.columns:
                family_risk = filtered_df.groupby(['family', 'severity_text']).size().unstack(fill_value=0)
                top_families = family_risk.sum(axis=1).nlargest(10)
                plot_data = family_risk.loc[top_families.index]
                
                bars = ax2.barh(range(len(plot_data)), plot_data.sum(axis=1).values, color='#007bff')
                ax2.set_yticks(range(len(plot_data)))
                ax2.set_yticklabels([f[:20] + '...' if len(f) > 20 else f for f in plot_data.index], color='white')
                ax2.set_title('Plugin Families by Risk (Top 10)', fontsize=12, fontweight='bold', color='white')
                ax2.set_xlabel('Number of Findings', color='white')
                ax2.set_facecolor('#2b2b2b')
                ax2.tick_params(colors='white')
                
                for bar in bars:
                    width = bar.get_width()
                    ax2.text(width + width*0.01, bar.get_y() + bar.get_height()/2.,
                            f'{int(width)}', ha='left', va='center', color='white', fontweight='bold')
            
            risk_timeline = filtered_df.groupby(['scan_date', 'severity_text']).size().unstack(fill_value=0)
            if not risk_timeline.empty and 'Critical' in risk_timeline.columns:
                ax3.plot(risk_timeline.index, risk_timeline['Critical'], marker='o', 
                        linewidth=2, color='#dc3545', label='Critical')
                if 'High' in risk_timeline.columns:
                    ax3.plot(risk_timeline.index, risk_timeline['High'], marker='s', 
                            linewidth=2, color='#fd7e14', label='High')
                
                ax3.set_title('Critical/High Risk Trends', fontsize=12, fontweight='bold', color='white')
                ax3.set_xlabel('Scan Date', color='white')
                ax3.set_ylabel('Number of Findings', color='white')
                ax3.legend()
                ax3.set_facecolor('#2b2b2b')
                ax3.tick_params(colors='white')
                ax3.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
                plt.setp(ax3.xaxis.get_majorticklabels(), rotation=45, ha='right')
            
            if 'exploit_available' in filtered_df.columns and 'cvss3_base_score' in filtered_df.columns:
                exploit_data = filtered_df[filtered_df['cvss3_base_score'].notna()].copy()
                exploit_data['cvss_numeric'] = pd.to_numeric(exploit_data['cvss3_base_score'], errors='coerce')
                exploit_data = exploit_data[exploit_data['cvss_numeric'].notna()]
                
                if not exploit_data.empty:
                    exploitable = exploit_data[exploit_data['exploit_available'] == 'Yes']
                    not_exploitable = exploit_data[exploit_data['exploit_available'] == 'No']
                    
                    if not exploitable.empty:
                        ax4.scatter(exploitable['cvss_numeric'], [1]*len(exploitable), 
                                   alpha=0.6, color='#dc3545', label='Exploitable', s=50)
                    if not not_exploitable.empty:
                        ax4.scatter(not_exploitable['cvss_numeric'], [0]*len(not_exploitable), 
                                   alpha=0.6, color='#28a745', label='Not Exploitable', s=50)
                    
                    ax4.set_title('CVSS vs Exploitability', fontsize=12, fontweight='bold', color='white')
                    ax4.set_xlabel('CVSS v3 Score', color='white')
                    ax4.set_ylabel('Exploitable', color='white')
                    ax4.set_yticks([0, 1])
                    ax4.set_yticklabels(['No', 'Yes'], color='white')
                    ax4.legend()
                    ax4.set_facecolor('#2b2b2b')
                    ax4.tick_params(colors='white')
                else:
                    ax4.text(0.5, 0.5, 'No CVSS/exploit data', ha='center', va='center', 
                            transform=ax4.transAxes, color='white', fontsize=12)
                    ax4.set_facecolor('#2b2b2b')
            else:
                ax4.text(0.5, 0.5, 'Exploit data not available', ha='center', va='center', 
                        transform=ax4.transAxes, color='white', fontsize=12)
                ax4.set_facecolor('#2b2b2b')
        
        plt.tight_layout()
        plt.style.use('dark_background')
        
        canvas = FigureCanvasTkAgg(fig, frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def create_compliance_dashboard_viz(self):
        """Create compliance and executive dashboard"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Compliance")
        self.viz_frames['compliance'] = frame
        
        control_frame = ttk.Frame(frame)
        control_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
        
        status_label = ttk.Label(control_frame, text=f"Filters: {self.get_filter_status_text()}", foreground="orange")
        status_label.pack(side=tk.LEFT)
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(14, 10))
        fig.patch.set_facecolor('#2b2b2b')
        
        filtered_df = self.get_filtered_data(self.historical_df)
        
        if not filtered_df.empty:
            if 'stig_severity' in filtered_df.columns:
                stig_counts = filtered_df[filtered_df['stig_severity'].notna()]['stig_severity'].value_counts()
                if not stig_counts.empty:
                    stig_colors = {'CAT I': '#dc3545', 'CAT II': '#fd7e14', 'CAT III': '#ffc107'}
                    colors_list = [stig_colors.get(cat, '#6c757d') for cat in stig_counts.index]
                    
                    bars = ax1.bar(stig_counts.index, stig_counts.values, color=colors_list)
                    ax1.set_title('STIG Severity Distribution', fontsize=12, fontweight='bold', color='white')
                    ax1.set_ylabel('Count', color='white')
                    ax1.set_facecolor('#2b2b2b')
                    ax1.tick_params(colors='white')
                    
                    for bar in bars:
                        height = bar.get_height()
                        ax1.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                                f'{int(height)}', ha='center', va='bottom', color='white', fontweight='bold')
            
            severity_summary = filtered_df['severity_text'].value_counts()
            colors = self.get_severity_colors()
            severity_colors = [colors.get(sev, '#6c757d') for sev in severity_summary.index]
            
            ax2.pie(severity_summary.values, labels=severity_summary.index, autopct='%1.1f%%',
                   colors=severity_colors, startangle=90)
            ax2.set_title('Overall Risk Profile', fontsize=12, fontweight='bold', color='white')
            ax2.set_facecolor('#2b2b2b')
            
            has_cve = len(filtered_df[filtered_df['cves'].notna() & (filtered_df['cves'] != '')])
            has_iavx = len(filtered_df[filtered_df['iavx'].notna() & (filtered_df['iavx'] != '')])
            has_both = len(filtered_df[
                (filtered_df['cves'].notna() & (filtered_df['cves'] != '')) &
                (filtered_df['iavx'].notna() & (filtered_df['iavx'] != ''))
            ])
            has_neither = len(filtered_df) - has_cve - has_iavx + has_both
            
            categories = ['Has CVE', 'Has IAVx', 'Has Both', 'Neither']
            values = [has_cve - has_both, has_iavx - has_both, has_both, has_neither]
            
            bars = ax3.bar(categories, values, color=['#dc3545', '#fd7e14', '#ffc107', '#6c757d'])
            ax3.set_title('Vulnerability References Coverage', fontsize=12, fontweight='bold', color='white')
            ax3.set_ylabel('Number of Findings', color='white')
            ax3.set_facecolor('#2b2b2b')
            ax3.tick_params(colors='white')
            plt.setp(ax3.xaxis.get_majorticklabels(), rotation=45, ha='right')
            
            for bar in bars:
                height = bar.get_height()
                if height > 0:
                    ax3.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                            f'{int(height)}', ha='center', va='bottom', color='white', fontweight='bold')
            
            if not self.lifecycle_df.empty:
                lifecycle_filtered = self.get_filtered_data(self.lifecycle_df)
                active = len(lifecycle_filtered[lifecycle_filtered['status'] == 'Active'])
                resolved = len(lifecycle_filtered[lifecycle_filtered['status'] == 'Resolved'])
                
                bars = ax4.bar(['Active', 'Resolved'], [active, resolved], color=['#dc3545', '#28a745'])
                ax4.set_title('Remediation Status', fontsize=12, fontweight='bold', color='white')
                ax4.set_ylabel('Number of Findings', color='white')
                ax4.set_facecolor('#2b2b2b')
                ax4.tick_params(colors='white')
                
                for bar in bars:
                    height = bar.get_height()
                    ax4.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                            f'{int(height)}', ha='center', va='bottom', color='white', fontweight='bold')
            else:
                ax4.text(0.5, 0.5, 'No lifecycle data', ha='center', va='center', 
                        transform=ax4.transAxes, color='white', fontsize=12)
                ax4.set_facecolor('#2b2b2b')
        
        plt.tight_layout()
        plt.style.use('dark_background')
        
        canvas = FigureCanvasTkAgg(fig, frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def create_host_viz(self):
        """Create detailed host analysis visualization"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Host Analysis")
        self.viz_frames['host_analysis'] = frame
        
        control_frame = ttk.Frame(frame)
        control_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
        
        status_label = ttk.Label(control_frame, text=f"Filters: {self.get_filter_status_text()}", foreground="orange")
        status_label.pack(side=tk.LEFT)
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(14, 10))
        fig.patch.set_facecolor('#2b2b2b')
        
        filtered_df = self.get_filtered_data(self.historical_df)
        
        if not filtered_df.empty:
            host_counts = filtered_df.groupby('hostname').size().nlargest(15)
            bars = ax1.barh(range(len(host_counts)), host_counts.values, color='#007bff')
            ax1.set_yticks(range(len(host_counts)))
            ax1.set_yticklabels(host_counts.index, color='white')
            ax1.set_title('Hosts with Most Findings (Top 15)', fontsize=12, fontweight='bold', color='white')
            ax1.set_xlabel('Number of Findings', color='white')
            ax1.set_facecolor('#2b2b2b')
            ax1.tick_params(colors='white')
            
            for bar in bars:
                width = bar.get_width()
                ax1.text(width + width*0.01, bar.get_y() + bar.get_height()/2.,
                        f'{int(width)}', ha='left', va='center', color='white', fontweight='bold')
            
            host_severity = filtered_df.groupby(['hostname', 'severity_text']).size().unstack(fill_value=0)
            top_hosts = host_severity.sum(axis=1).nlargest(10)
            plot_data = host_severity.loc[top_hosts.index]
            
            colors = self.get_severity_colors()
            for severity in ['Critical', 'High']:
                if severity in plot_data.columns:
                    ax2.barh(range(len(plot_data)), plot_data[severity], 
                           label=severity, color=colors.get(severity))
            
            ax2.set_yticks(range(len(plot_data)))
            ax2.set_yticklabels(plot_data.index, color='white')
            ax2.set_title('Critical/High Findings by Host (Top 10)', fontsize=12, fontweight='bold', color='white')
            ax2.set_xlabel('Number of Findings', color='white')
            ax2.legend()
            ax2.set_facecolor('#2b2b2b')
            ax2.tick_params(colors='white')
            
            unique_hosts_per_scan = filtered_df.groupby('scan_date')['hostname'].nunique()
            ax3.plot(unique_hosts_per_scan.index, unique_hosts_per_scan.values, 
                    marker='o', linewidth=2, color='#28a745')
            ax3.set_title('Unique Hosts per Scan', fontsize=12, fontweight='bold', color='white')
            ax3.set_xlabel('Scan Date', color='white')
            ax3.set_ylabel('Number of Hosts', color='white')
            ax3.set_facecolor('#2b2b2b')
            ax3.tick_params(colors='white')
            ax3.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
            plt.setp(ax3.xaxis.get_majorticklabels(), rotation=45, ha='right')
            
            host_finding_dist = filtered_df.groupby('hostname').size()
            dist_buckets = pd.cut(host_finding_dist, bins=[0, 10, 25, 50, 100, float('inf')],
                                 labels=['1-10', '11-25', '26-50', '51-100', '>100'])
            bucket_counts = dist_buckets.value_counts()
            
            bars = ax4.bar(range(len(bucket_counts)), bucket_counts.values, color='#fd7e14')
            ax4.set_xticks(range(len(bucket_counts)))
            ax4.set_xticklabels(bucket_counts.index, color='white')
            ax4.set_title('Host Finding Count Distribution', fontsize=12, fontweight='bold', color='white')
            ax4.set_ylabel('Number of Hosts', color='white')
            ax4.set_xlabel('Findings per Host', color='white')
            ax4.set_facecolor('#2b2b2b')
            ax4.tick_params(colors='white')
            
            for bar in bars:
                height = bar.get_height()
                ax4.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                        f'{int(height)}', ha='center', va='bottom', color='white', fontweight='bold')
        
        plt.tight_layout()
        plt.style.use('dark_background')
        
        canvas = FigureCanvasTkAgg(fig, frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def create_plugin_viz(self):
        """Create plugin analysis visualization"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Plugin Analysis")
        self.viz_frames['plugin_analysis'] = frame
        
        control_frame = ttk.Frame(frame)
        control_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
        
        status_label = ttk.Label(control_frame, text=f"Filters: {self.get_filter_status_text()}", foreground="orange")
        status_label.pack(side=tk.LEFT)
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(14, 10))
        fig.patch.set_facecolor('#2b2b2b')
        
        filtered_df = self.get_filtered_data(self.lifecycle_df)
        
        if not filtered_df.empty:
            plugin_counts = filtered_df.groupby('plugin_name').size().nlargest(15)
            bars = ax1.barh(range(len(plugin_counts)), plugin_counts.values, color='#dc3545')
            ax1.set_yticks(range(len(plugin_counts)))
            ax1.set_yticklabels([name[:40] + '...' if len(name) > 40 else name for name in plugin_counts.index], color='white')
            ax1.set_title('Most Frequent Findings (Top 15)', fontsize=12, fontweight='bold', color='white')
            ax1.set_xlabel('Number of Affected Hosts', color='white')
            ax1.set_facecolor('#2b2b2b')
            ax1.tick_params(colors='white')
            
            for bar in bars:
                width = bar.get_width()
                ax1.text(width + width*0.01, bar.get_y() + bar.get_height()/2.,
                        f'{int(width)}', ha='left', va='center', color='white', fontweight='bold')
            
            if 'family' in filtered_df.columns:
                family_counts = filtered_df['family'].value_counts().head(10)
                bars = ax2.barh(range(len(family_counts)), family_counts.values, color='#007bff')
                ax2.set_yticks(range(len(family_counts)))
                ax2.set_yticklabels([f[:20] + '...' if len(f) > 20 else f for f in family_counts.index], color='white')
                ax2.set_title('Top 10 Plugin Families', fontsize=12, fontweight='bold', color='white')
                ax2.set_xlabel('Number of Findings', color='white')
                ax2.set_facecolor('#2b2b2b')
                ax2.tick_params(colors='white')
                
                for bar in bars:
                    width = bar.get_width()
                    ax2.text(width + width*0.01, bar.get_y() + bar.get_height()/2.,
                            f'{int(width)}', ha='left', va='center', color='white', fontweight='bold')
            
            risk_timeline = filtered_df.groupby(['first_seen', 'severity_text']).size().unstack(fill_value=0)
            if not risk_timeline.empty and 'Critical' in risk_timeline.columns:
                ax3.plot(risk_timeline.index, risk_timeline['Critical'], marker='o', 
                        linewidth=2, color='#dc3545', label='Critical')
                if 'High' in risk_timeline.columns:
                    ax3.plot(risk_timeline.index, risk_timeline['High'], marker='s', 
                            linewidth=2, color='#fd7e14', label='High')
                
                ax3.set_title('Critical/High Risk Trends', fontsize=12, fontweight='bold', color='white')
                ax3.set_xlabel('First Seen Date', color='white')
                ax3.set_ylabel('Number of Findings', color='white')
                ax3.legend()
                ax3.set_facecolor('#2b2b2b')
                ax3.tick_params(colors='white')
                ax3.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
                plt.setp(ax3.xaxis.get_majorticklabels(), rotation=45, ha='right')
            
            recurring_plugins = filtered_df[filtered_df['reappearances'] > 0].nlargest(10, 'reappearances')
            if not recurring_plugins.empty:
                bars = ax4.barh(range(len(recurring_plugins)), recurring_plugins['reappearances'].values, color='#ffc107')
                ax4.set_yticks(range(len(recurring_plugins)))
                ax4.set_yticklabels([name[:30] + '...' if len(name) > 30 else name for name in recurring_plugins['plugin_name']], color='white')
                ax4.set_title('Most Recurring Findings (Top 10)', fontsize=12, fontweight='bold', color='white')
                ax4.set_xlabel('Number of Reappearances', color='white')
                ax4.set_facecolor('#2b2b2b')
                ax4.tick_params(colors='white')
                
                for bar in bars:
                    width = bar.get_width()
                    ax4.text(width + width*0.01, bar.get_y() + bar.get_height()/2.,
                            f'{int(width)}', ha='left', va='center', color='white', fontweight='bold')
            else:
                ax4.text(0.5, 0.5, 'No recurring findings', ha='center', va='center', 
                        transform=ax4.transAxes, color='white', fontsize=12)
                ax4.set_facecolor('#2b2b2b')
        
        plt.tight_layout()
        plt.style.use('dark_background')
        
        canvas = FigureCanvasTkAgg(fig, frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def create_lifecycle_viz(self):
        """Create lifecycle analysis visualization"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Lifecycle")
        self.viz_frames['lifecycle'] = frame
        
        control_frame = ttk.Frame(frame)
        control_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
        
        status_label = ttk.Label(control_frame, text=f"Filters: {self.get_filter_status_text()}", foreground="orange")
        status_label.pack(side=tk.LEFT)
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(14, 10))
        fig.patch.set_facecolor('#2b2b2b')
        
        filtered_df = self.get_filtered_data(self.lifecycle_df)
        
        if not filtered_df.empty:
            age_buckets = pd.cut(filtered_df['days_open'], 
                                bins=[0, 30, 90, 180, 365, float('inf')],
                                labels=['<30d', '30-90d', '90-180d', '180-365d', '>365d'])
            age_counts = age_buckets.value_counts()
            
            bars = ax1.bar(range(len(age_counts)), age_counts.values, color='#007bff')
            ax1.set_xticks(range(len(age_counts)))
            ax1.set_xticklabels(age_counts.index, rotation=45, ha='right', color='white')
            ax1.set_title('Finding Age Distribution', fontsize=12, fontweight='bold', color='white')
            ax1.set_ylabel('Number of Findings', color='white')
            ax1.set_facecolor('#2b2b2b')
            ax1.tick_params(colors='white')
            
            for bar in bars:
                height = bar.get_height()
                ax1.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                        f'{int(height)}', ha='center', va='bottom', color='white', fontweight='bold')
            
            status_counts = filtered_df['status'].value_counts()
            colors_status = ['#28a745', '#dc3545']
            ax2.pie(status_counts.values, labels=status_counts.index, autopct='%1.1f%%',
                   colors=colors_status[:len(status_counts)], startangle=90)
            ax2.set_title('Active vs Resolved Findings', fontsize=12, fontweight='bold', color='white')
            ax2.set_facecolor('#2b2b2b')
            
            observation_dist = filtered_df['total_observations'].value_counts().sort_index()
            if len(observation_dist) > 10:
                observation_dist = observation_dist.head(10)
            
            bars = ax3.bar(range(len(observation_dist)), observation_dist.values, color='#28a745')
            ax3.set_xticks(range(len(observation_dist)))
            ax3.set_xticklabels([f'{int(idx)}' for idx in observation_dist.index], color='white')
            ax3.set_title('Finding Observation Frequency', fontsize=12, fontweight='bold', color='white')
            ax3.set_xlabel('Times Observed', color='white')
            ax3.set_ylabel('Number of Findings', color='white')
            ax3.set_facecolor('#2b2b2b')
            ax3.tick_params(colors='white')
            
            for bar in bars:
                height = bar.get_height()
                ax3.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                        f'{int(height)}', ha='center', va='bottom', color='white', fontweight='bold')
            
            if 'severity_text' in filtered_df.columns:
                severity_age = filtered_df.groupby('severity_text')['days_open'].mean()
                colors = self.get_severity_colors()
                severity_colors = [colors.get(sev, '#6c757d') for sev in severity_age.index]
                
                bars = ax4.bar(severity_age.index, severity_age.values, color=severity_colors)
                ax4.set_title('Average Age by Severity', fontsize=12, fontweight='bold', color='white')
                ax4.set_ylabel('Average Days Open', color='white')
                ax4.set_facecolor('#2b2b2b')
                ax4.tick_params(colors='white')
                
                for bar in bars:
                    height = bar.get_height()
                    ax4.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                            f'{height:.1f}', ha='center', va='bottom', color='white', fontweight='bold')
        
        plt.tight_layout()
        plt.style.use('dark_background')
        
        canvas = FigureCanvasTkAgg(fig, frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def export_excel(self):
        """Export to Excel"""
        if self.historical_df.empty:
            messagebox.showwarning("No Data", "Please process archives first")
            return
        
        filepath = filedialog.asksaveasfilename(
            defaultextension=".xlsx",
            filetypes=[("Excel files", "*.xlsx"), ("All files", "*.*")],
            title="Save Excel File"
        )
        
        if filepath:
            try:
                self.log(f"Exporting to Excel: {filepath}")
                export_to_excel(self.historical_df, self.lifecycle_df, 
                               self.host_presence_df, self.scan_changes_df, filepath, 
                               self.include_info.get())
                self.log("Excel export complete!")
                messagebox.showinfo("Success", f"Data exported to:\n{filepath}")
            except PermissionError:
                messagebox.showerror("Permission Error", 
                    f"Cannot write to file. Please close the file if it is open:\n{filepath}")
            except Exception as e:
                self.log(f"Export error: {e}")
                messagebox.showerror("Export Error", f"Failed to export: {str(e)}")
    
    def save_database(self):
        """Save to SQLite database"""
        if self.historical_df.empty:
            messagebox.showwarning("No Data", "Please process archives first")
            return
        
        filepath = filedialog.asksaveasfilename(
            defaultextension=".db",
            filetypes=[("SQLite DB", "*.db"), ("All files", "*.*")],
            title="Save Database File"
        )
        
        if filepath:
            try:
                self.log(f"Saving database: {filepath}")
                save_to_database(self.historical_df, self.lifecycle_df, 
                               self.host_presence_df, self.scan_changes_df, filepath)
                self.log("Database saved successfully!")
                messagebox.showinfo("Success", f"Database saved to:\n{filepath}")
            except PermissionError:
                messagebox.showerror("Permission Error", 
                    f"Cannot write to file. Please close the file if it is open:\n{filepath}")
            except Exception as e:
                self.log(f"Save error: {e}")
                messagebox.showerror("Save Error", f"Failed to save database: {str(e)}")
    
    def run(self):
        """Start the GUI application"""
        self.window.mainloop()


def main():
    """Main entry point for the application"""
    app = EnhancedHistoricalAnalysisGUI()
    app.run()


if __name__ == "__main__":
    main()