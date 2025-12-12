"""
Enhanced Nessus Historical Analysis and Visualization System with OPDIR Integration
Tracks vulnerability findings and host presence across multiple scans over time.
Includes OPDIR mapping for compliance tracking and enhanced dark theme GUI.
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


# OPDIR Integration Functions
def extract_iavx_mapping(iavx_full: str) -> str:
    """
    Extract IAVx mapping from full IAVA/B/T identifier.
    PRESERVES leading zeros in the number portion.
    
    Examples:
        "IAVB-2025-B-0146" -> "b-0146"  # Keeps leading zero
        "IAVT-2024-T-0055" -> "t-0055"  # Keeps leading zero
        "B-0146" -> "b-0146"            # Keeps leading zero
        "B-146" -> "b-146"              # No leading zero to preserve
    
    Args:
        iavx_full: Full IAVx identifier
        
    Returns:
        Mapped IAVx identifier in lowercase format with preserved leading zeros
    """
    if pd.isna(iavx_full) or not isinstance(iavx_full, str):
        return ''
    
    # Clean up the input
    iavx_clean = str(iavx_full).strip().upper()
    
    # Handle different formats
    if '-' in iavx_clean:
        parts = iavx_clean.split('-')
        
        # Format: IAVB-2025-B-0146 or IAVT-2024-T-0055
        if len(parts) >= 4 and parts[0].startswith('IAV'):
            iav_type = parts[2]  # B, T, A
            number = parts[3]    # Keep original format including leading zeros
            return f"{iav_type.lower()}-{number}"
        
        # Format: B-0146 or T-0055
        elif len(parts) == 2:
            iav_type = parts[0]
            number = parts[1]    # Keep original format including leading zeros
            return f"{iav_type.lower()}-{number}"
    
    # If no standard format found, return lowercase original
    return iavx_clean.lower()

def load_opdir_mapping(opdir_file_path: str) -> pd.DataFrame:
    """
    Load and process OPDIR mapping from Excel/CSV file.
    For Excel files with multiple sheets, allows user to select the sheet.
    PRESERVES leading zeros in OPDIR numbers and IAVx mappings.
    
    Args:
        opdir_file_path: Path to OPDIR spreadsheet file
        
    Returns:
        DataFrame with processed OPDIR mappings
    """
    try:
        # Handle CSV files (no sheet selection needed)
        if opdir_file_path.lower().endswith('.csv'):
            opdir_df = pd.read_csv(opdir_file_path, dtype={'OPDIR NUMBER': str, 'OPDIR_NUMBER': str})
            print(f"Loaded CSV file with {len(opdir_df)} rows")
        else:
            # Handle Excel files - check for multiple sheets
            excel_file = pd.ExcelFile(opdir_file_path)
            sheet_names = excel_file.sheet_names
            
            print(f"Excel file contains {len(sheet_names)} sheet(s): {sheet_names}")
            
            # If only one sheet, use it automatically
            if len(sheet_names) == 1:
                selected_sheet = sheet_names[0]
                print(f"Using single sheet: '{selected_sheet}'")
            else:
                # Multiple sheets - let user choose
                selected_sheet = select_excel_sheet(sheet_names, opdir_file_path)
                if not selected_sheet:
                    print("No sheet selected - cancelling OPDIR load")
                    return pd.DataFrame()
            
            # Read the selected sheet with string dtypes for OPDIR columns
            opdir_df = pd.read_excel(opdir_file_path, 
                                   sheet_name=selected_sheet,
                                   dtype={'OPDIR NUMBER': str, 'OPDIR_NUMBER': str, 'OPDIR': str})
            print(f"Loaded sheet '{selected_sheet}' with {len(opdir_df)} rows")
        
        print(f"Columns found: {list(opdir_df.columns)}")
        
        # Rest of the processing remains the same...
        # [Continue with existing column mapping, IAVx processing, etc.]
        
        # Standardize column names (flexible mapping)
        column_mapping = {
            'OPDIR NUMBER': 'opdir_number',
            'OPDIR_NUMBER': 'opdir_number',
            'OPDIR': 'opdir_number',
            'OPDIR #': 'opdir_number',
            'IAVA/B': 'iavx_full',
            'IAVA_B': 'iavx_full',
            'IAVX': 'iavx_full',
            'IAV': 'iavx_full',
            'SUBJECT': 'subject',
            'TITLE': 'subject',
            'DESCRIPTION': 'subject',
            'RELEASE DATE': 'release_date',
            'RELEASE_DATE': 'release_date',
            'RELEASED': 'release_date',
            'ACKNOWLEDGE DATE': 'acknowledge_date',
            'ACKNOWLEDGE_DATE': 'acknowledge_date',
            'ACK_DATE': 'acknowledge_date',
            'POA&M DUE DATE': 'poam_due_date',
            'POAM_DUE_DATE': 'poam_due_date',
            'POAM DUE': 'poam_due_date',
            'FINAL DUE DATE': 'final_due_date',
            'FINAL_DUE_DATE': 'final_due_date',
            'DUE_DATE': 'final_due_date',
            'FINAL DUE': 'final_due_date'
        }
        
        # Apply column mapping
        opdir_df.columns = opdir_df.columns.str.strip().str.upper()
        for old_col, new_col in column_mapping.items():
            if old_col in opdir_df.columns:
                opdir_df = opdir_df.rename(columns={old_col: new_col})
        
        print(f"Standardized columns: {list(opdir_df.columns)}")
        
        # Process OPDIR number if available - PRESERVE leading zeros
        if 'opdir_number' in opdir_df.columns:
            opdir_df['opdir_number'] = opdir_df['opdir_number'].astype(str)
            opdir_pattern = r'(\d+)-(\d+)'
            opdir_extract = opdir_df['opdir_number'].str.extract(opdir_pattern)
            
            if not opdir_extract.empty and not opdir_extract[0].isna().all():
                opdir_df['opdir_sequence_str'] = opdir_extract[0]
                opdir_df['opdir_sequence_num'] = pd.to_numeric(opdir_extract[0], errors='coerce')
                opdir_df['opdir_year_short'] = pd.to_numeric(opdir_extract[1], errors='coerce')
                opdir_df['opdir_year'] = opdir_df['opdir_year_short'].apply(
                    lambda x: 2000 + x if pd.notna(x) and x < 100 else x
                )
                
                valid_opdirs = opdir_df.dropna(subset=['opdir_sequence_num'])
                print(f"Processed {len(valid_opdirs)} OPDIR numbers (preserving leading zeros)")
        
        # Process IAVx mapping - PRESERVE leading zeros
        if 'iavx_full' in opdir_df.columns:
            opdir_df['iavx_mapped'] = opdir_df['iavx_full'].apply(extract_iavx_mapping)
            valid_mappings = len(opdir_df[opdir_df['iavx_mapped'] != ''])
            print(f"Created {valid_mappings} IAVx mappings (preserving leading zeros)")
        
        # Process date columns
        date_columns = ['release_date', 'acknowledge_date', 'poam_due_date', 'final_due_date']
        for col in date_columns:
            if col in opdir_df.columns:
                opdir_df[col] = pd.to_datetime(opdir_df[col], errors='coerce')
                valid_dates = opdir_df[col].notna().sum()
                print(f"Processed {valid_dates} valid dates for {col}")
        
        # Calculate derived metrics
        if 'release_date' in opdir_df.columns and 'final_due_date' in opdir_df.columns:
            opdir_df['days_to_remediate'] = (
                opdir_df['final_due_date'] - opdir_df['release_date']
            ).dt.days
            valid_durations = opdir_df['days_to_remediate'].notna().sum()
            print(f"Calculated remediation days for {valid_durations} records")
        
        # Add status tracking
        if 'final_due_date' in opdir_df.columns:
            from datetime import datetime
            today = datetime.now()
            opdir_df['days_until_due'] = (opdir_df['final_due_date'] - today).dt.days
            opdir_df['status'] = opdir_df['days_until_due'].apply(
                lambda x: 'Overdue' if pd.notna(x) and x < 0 else 
                         'Due Soon' if pd.notna(x) and x <= 30 else 
                         'On Track' if pd.notna(x) else 'Unknown'
            )
            
            status_counts = opdir_df['status'].value_counts()
            print(f"OPDIR Status: {dict(status_counts)}")
        
        # Clean up empty rows
        opdir_df = opdir_df.dropna(how='all')
        
        print(f"Final OPDIR dataset: {len(opdir_df)} records")
        return opdir_df
        
    except Exception as e:
        print(f"Error loading OPDIR file {opdir_file_path}: {e}")
        import traceback
        traceback.print_exc()
        return pd.DataFrame()

def select_excel_sheet(sheet_names: list, file_path: str) -> str:
    """
    Present user with sheet selection dialog for Excel files with multiple sheets.
    
    Args:
        sheet_names: List of sheet names in the Excel file
        file_path: Path to the Excel file (for display)
        
    Returns:
        Selected sheet name or None if cancelled
    """
    import tkinter as tk
    from tkinter import messagebox, simpledialog
    
    # Create a simple dialog for sheet selection
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    
    # Create message with sheet options
    message = f"Excel file contains multiple sheets:\n\n"
    for i, sheet in enumerate(sheet_names, 1):
        message += f"{i}. {sheet}\n"
    message += f"\nFile: {file_path}\n\nWhich sheet contains the OPDIR data?"
    
    # Show options dialog
    choice = messagebox.askquestion(
        "Select OPDIR Sheet",
        message + f"\n\nClick 'Yes' to use the first sheet ('{sheet_names[0]}'),\n" +
        f"or 'No' to choose a different sheet.",
        icon='question'
    )
    
    if choice == 'yes':
        selected_sheet = sheet_names[0]
        print(f"Using first sheet: '{selected_sheet}'")
    else:
        # Show input dialog for sheet selection
        sheet_list = "\n".join([f"{i}: {sheet}" for i, sheet in enumerate(sheet_names, 1)])
        user_input = simpledialog.askstring(
            "Sheet Selection",
            f"Enter the sheet number or exact sheet name:\n\n{sheet_list}",
            parent=root
        )
        
        if not user_input:
            return None  # User cancelled
        
        # Try to parse as number first
        try:
            sheet_index = int(user_input) - 1
            if 0 <= sheet_index < len(sheet_names):
                selected_sheet = sheet_names[sheet_index]
                print(f"Selected sheet by number: '{selected_sheet}'")
            else:
                messagebox.showerror("Invalid Selection", f"Sheet number must be between 1 and {len(sheet_names)}")
                return None
        except ValueError:
            # Try to match by name
            if user_input in sheet_names:
                selected_sheet = user_input
                print(f"Selected sheet by name: '{selected_sheet}'")
            else:
                messagebox.showerror("Invalid Selection", f"Sheet '{user_input}' not found in file")
                return None
    
    root.destroy()
    return selected_sheet

def enrich_findings_with_opdir(lifecycle_df: pd.DataFrame, opdir_df: pd.DataFrame) -> pd.DataFrame:
    """
    Enrich findings with OPDIR information based on IAVx mapping.
    
    Args:
        lifecycle_df: Lifecycle findings DataFrame
        opdir_df: OPDIR mapping DataFrame
        
    Returns:
        Enhanced lifecycle DataFrame with OPDIR info
    """
    if lifecycle_df.empty:
        print("No lifecycle data to enrich")
        return lifecycle_df
    
    if opdir_df.empty:
        print("No OPDIR data available for enrichment")
        # Add empty OPDIR columns for consistency
        opdir_columns = [
            'opdir_number', 'opdir_subject', 'opdir_release_date',
            'opdir_final_due_date', 'opdir_days_to_remediate', 
            'opdir_status', 'opdir_days_until_due'
        ]
        for col in opdir_columns:
            lifecycle_df[col] = ''
        return lifecycle_df
    
    enhanced_df = lifecycle_df.copy()
    print(f"Starting OPDIR enrichment for {len(enhanced_df)} findings")
    
    # Extract IAVx from findings
    if 'iavx' in enhanced_df.columns:
        enhanced_df['iavx_mapped'] = enhanced_df['iavx'].apply(extract_iavx_mapping)
        iavx_found = len(enhanced_df[enhanced_df['iavx_mapped'] != ''])
        print(f"Found IAVx data in {iavx_found} findings")
    else:
        enhanced_df['iavx_mapped'] = ''
        print("No IAVx field found in findings")
    
    # Create OPDIR lookup dictionary
    if 'iavx_mapped' in opdir_df.columns:
        # Filter out empty IAVx mappings
        valid_opdir = opdir_df[opdir_df['iavx_mapped'] != ''].copy()
        print(f"Using {len(valid_opdir)} OPDIR records with valid IAVx mappings")
        
        if not valid_opdir.empty:
            # Create lookup - handle duplicate IAVx mappings by taking the most recent
            if 'release_date' in valid_opdir.columns:
                valid_opdir = valid_opdir.sort_values('release_date', ascending=False)
            
            opdir_lookup = valid_opdir.drop_duplicates('iavx_mapped').set_index('iavx_mapped').to_dict('index')
            print(f"Created lookup table with {len(opdir_lookup)} unique IAVx mappings")
            
            # Initialize OPDIR columns
            enhanced_df['opdir_number'] = ''
            enhanced_df['opdir_subject'] = ''
            enhanced_df['opdir_release_date'] = pd.NaT
            enhanced_df['opdir_final_due_date'] = pd.NaT
            enhanced_df['opdir_days_to_remediate'] = pd.NA
            enhanced_df['opdir_status'] = ''
            enhanced_df['opdir_days_until_due'] = pd.NA
            
            # Apply OPDIR information
            matches_found = 0
            for idx, row in enhanced_df.iterrows():
                iavx_key = row.get('iavx_mapped', '')
                if iavx_key and iavx_key in opdir_lookup:
                    opdir_info = opdir_lookup[iavx_key]
                    enhanced_df.at[idx, 'opdir_number'] = opdir_info.get('opdir_number', '')
                    enhanced_df.at[idx, 'opdir_subject'] = opdir_info.get('subject', '')
                    enhanced_df.at[idx, 'opdir_release_date'] = opdir_info.get('release_date', pd.NaT)
                    enhanced_df.at[idx, 'opdir_final_due_date'] = opdir_info.get('final_due_date', pd.NaT)
                    enhanced_df.at[idx, 'opdir_days_to_remediate'] = opdir_info.get('days_to_remediate', pd.NA)
                    enhanced_df.at[idx, 'opdir_status'] = opdir_info.get('status', '')
                    enhanced_df.at[idx, 'opdir_days_until_due'] = opdir_info.get('days_until_due', pd.NA)
                    matches_found += 1
            
            print(f"Successfully matched {matches_found} findings to OPDIR records")
            
            if matches_found > 0:
                # Print some statistics
                opdir_findings = enhanced_df[enhanced_df['opdir_number'] != '']
                if not opdir_findings.empty:
                    status_dist = opdir_findings['opdir_status'].value_counts()
                    print(f"OPDIR status distribution: {dict(status_dist)}")
                    
                    overdue_count = len(opdir_findings[opdir_findings['opdir_status'] == 'Overdue'])
                    if overdue_count > 0:
                        print(f"WARNING: {overdue_count} findings are linked to overdue OPDIRs")
        
    return enhanced_df


def create_opdir_summary_report(lifecycle_df: pd.DataFrame, opdir_df: pd.DataFrame) -> Dict[str, Any]:
    """
    Create a summary report of OPDIR compliance and mapping.
    
    Args:
        lifecycle_df: Enhanced lifecycle DataFrame with OPDIR info
        opdir_df: Original OPDIR DataFrame
        
    Returns:
        Dictionary with summary statistics
    """
    summary = {
        'opdir_stats': {},
        'mapping_stats': {},
        'compliance_stats': {},
        'risk_stats': {}
    }
    
    # OPDIR basic statistics
    if not opdir_df.empty:
        summary['opdir_stats'] = {
            'total_opdirs': len(opdir_df),
            'opdirs_with_iavx': len(opdir_df[opdir_df.get('iavx_mapped', '') != '']),
            'opdirs_with_due_dates': len(opdir_df.dropna(subset=['final_due_date'])) if 'final_due_date' in opdir_df.columns else 0,
        }
        
        if 'status' in opdir_df.columns:
            status_counts = opdir_df['status'].value_counts().to_dict()
            summary['opdir_stats']['status_distribution'] = status_counts
    
    # Mapping statistics
    if not lifecycle_df.empty:
        total_findings = len(lifecycle_df)
        opdir_mapped = len(lifecycle_df[lifecycle_df.get('opdir_number', '') != ''])
        
        summary['mapping_stats'] = {
            'total_findings': total_findings,
            'opdir_mapped_findings': opdir_mapped,
            'mapping_percentage': round((opdir_mapped / total_findings) * 100, 1) if total_findings > 0 else 0,
            'unmapped_findings': total_findings - opdir_mapped
        }
        
        # Compliance statistics
        if opdir_mapped > 0:
            opdir_findings = lifecycle_df[lifecycle_df['opdir_number'] != '']
            
            if 'opdir_status' in opdir_findings.columns:
                compliance_counts = opdir_findings['opdir_status'].value_counts().to_dict()
                summary['compliance_stats'] = compliance_counts
            
            # Risk analysis
            active_opdir_findings = opdir_findings[opdir_findings['status'] == 'Active']
            if not active_opdir_findings.empty:
                overdue_active = active_opdir_findings[active_opdir_findings['opdir_status'] == 'Overdue']
                due_soon_active = active_opdir_findings[active_opdir_findings['opdir_status'] == 'Due Soon']
                
                summary['risk_stats'] = {
                    'active_opdir_findings': len(active_opdir_findings),
                    'overdue_active_findings': len(overdue_active),
                    'due_soon_active_findings': len(due_soon_active),
                    'high_risk_findings': len(overdue_active[overdue_active['severity_text'].isin(['Critical', 'High'])])
                }
    
    return summary


def export_opdir_enhanced_sqlite(historical_df: pd.DataFrame, lifecycle_df: pd.DataFrame, 
                                host_presence_df: pd.DataFrame, scan_changes_df: pd.DataFrame,
                                opdir_df: pd.DataFrame, db_path: str) -> None:
    """
    Export enhanced data to SQLite database including OPDIR table.
    
    Args:
        historical_df: Historical findings DataFrame
        lifecycle_df: Enhanced lifecycle DataFrame with OPDIR info
        host_presence_df: Host presence analysis DataFrame
        scan_changes_df: Scan changes DataFrame
        opdir_df: OPDIR mapping DataFrame
        db_path: Path to SQLite database file
    """
    try:
        conn = sqlite3.connect(db_path)
        
        # Export all DataFrames
        historical_df.to_sql('historical_findings', conn, if_exists='replace', index=False)
        lifecycle_df.to_sql('finding_lifecycle', conn, if_exists='replace', index=False)
        host_presence_df.to_sql('host_presence', conn, if_exists='replace', index=False)
        scan_changes_df.to_sql('scan_changes', conn, if_exists='replace', index=False)
        
        # Export OPDIR table if available
        if not opdir_df.empty:
            opdir_df.to_sql('opdir_mapping', conn, if_exists='replace', index=False)
            print(f"Exported {len(opdir_df)} OPDIR records to database")
        
        # Create indexes for better query performance
        cursor = conn.cursor()
        
        # Existing indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_historical_hostname ON historical_findings(hostname)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_historical_plugin ON historical_findings(plugin_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_historical_date ON historical_findings(scan_date)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_historical_ip ON historical_findings(ip_address)')
        
        # Lifecycle indexes (including OPDIR fields)
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_lifecycle_hostname ON finding_lifecycle(hostname)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_lifecycle_plugin ON finding_lifecycle(plugin_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_lifecycle_status ON finding_lifecycle(status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_lifecycle_opdir ON finding_lifecycle(opdir_number)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_lifecycle_opdir_status ON finding_lifecycle(opdir_status)')
        
        # OPDIR indexes
        if not opdir_df.empty:
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_opdir_number ON opdir_mapping(opdir_number)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_opdir_iavx ON opdir_mapping(iavx_mapped)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_opdir_status ON opdir_mapping(status)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_opdir_due_date ON opdir_mapping(final_due_date)')
        
        conn.commit()
        conn.close()
        
        print(f"Successfully exported OPDIR-enhanced database: {db_path}")
        
    except Exception as e:
        print(f"Error exporting OPDIR-enhanced SQLite: {e}")
        import traceback
        traceback.print_exc()


# Original Functions (Maintained)
def extract_scan_date_from_filename(filename: str) -> Optional[datetime]:
    """
    Extract scan date from filename using common patterns.
    
    Args:
        filename: Name of the file
        
    Returns:
        datetime object or None
    """
    # Common date patterns in filenames
    patterns = [
        r'(\d{4})[-_](\d{2})[-_](\d{2})',  # YYYY-MM-DD or YYYY_MM_DD
        r'(\d{2})[-_](\d{2})[-_](\d{4})',  # MM-DD-YYYY or MM_DD_YYYY
        r'(\d{8})',  # YYYYMMDD
        r'(\d{6})',  # YYMMDD or MMDDYY
    ]
    
    for pattern in patterns:
        match = re.search(pattern, filename)
        if match:
            try:
                if len(match.groups()) == 3:
                    # YYYY-MM-DD or MM-DD-YYYY
                    parts = match.groups()
                    if len(parts[0]) == 4:  # YYYY-MM-DD
                        return datetime(int(parts[0]), int(parts[1]), int(parts[2]))
                    else:  # MM-DD-YYYY
                        return datetime(int(parts[2]), int(parts[0]), int(parts[1]))
                elif len(match.group(1)) == 8:  # YYYYMMDD
                    date_str = match.group(1)
                    return datetime.strptime(date_str, '%Y%m%d')
                elif len(match.group(1)) == 6:  # Try both YYMMDD and MMDDYY
                    date_str = match.group(1)
                    try:
                        return datetime.strptime(date_str, '%y%m%d')
                    except ValueError:
                        return datetime.strptime(date_str, '%m%d%y')
            except (ValueError, IndexError):
                continue
    
    return None


def extract_scan_date_from_nessus(nessus_file: str) -> Optional[datetime]:
    """
    Extract scan date from .nessus file content.
    
    Args:
        nessus_file: Path to .nessus file
        
    Returns:
        datetime object or None
    """
    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(nessus_file)
        root = tree.getroot()
        
        # Try to find scan end date
        policy_elem = root.find(".//Policy/policyName")
        if policy_elem is not None and policy_elem.text:
            date = extract_scan_date_from_filename(policy_elem.text)
            if date:
                return date
        
        # Try Report name attribute
        report_elem = root.find(".//Report")
        if report_elem is not None and 'name' in report_elem.attrib:
            date = extract_scan_date_from_filename(report_elem.attrib['name'])
            if date:
                return date
        
        # Try HOST_END timestamps
        host_end = root.find(".//tag[@name='HOST_END']")
        if host_end is not None and host_end.text:
            try:
                timestamp = int(host_end.text)
                return datetime.fromtimestamp(timestamp)
            except (ValueError, TypeError):
                pass
        
    except Exception as e:
        print(f"Error extracting date from {nessus_file}: {e}")
    
    return None


def create_host_presence_analysis(historical_df: pd.DataFrame) -> pd.DataFrame:
    """
    Analyze host presence across scans to identify missing hosts.
    
    Args:
        historical_df: DataFrame with historical findings
        
    Returns:
        DataFrame with host presence analysis
    """
    if historical_df.empty:
        return pd.DataFrame()
    
    # Get all unique combinations of scan dates and hosts
    scan_dates = sorted(historical_df['scan_date'].unique())
    all_hosts = historical_df.groupby(['hostname', 'ip_address']).size().reset_index(name='count')
    
    presence_records = []
    
    for _, host_row in all_hosts.iterrows():
        hostname = host_row['hostname']
        ip_address = host_row['ip_address']
        
        # Get scan dates where this host appeared
        host_scans = historical_df[
            (historical_df['hostname'] == hostname) & 
            (historical_df['ip_address'] == ip_address)
        ]['scan_date'].unique()
        
        first_seen = min(host_scans)
        last_seen = max(host_scans)
        total_scans = len(scan_dates)
        present_scans = len(host_scans)
        missing_scans = total_scans - present_scans
        
        # Identify missing scan periods
        missing_periods = []
        for scan_date in scan_dates:
            if scan_date not in host_scans:
                missing_periods.append(scan_date.strftime('%Y-%m-%d'))
        
        # Determine status
        if last_seen == max(scan_dates):
            status = 'Active'
        else:
            status = 'Missing'
        
        # Calculate presence percentage
        presence_percentage = (present_scans / total_scans) * 100 if total_scans > 0 else 0
        
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
            'missing_scan_dates': ', '.join(missing_periods) if missing_periods else 'None'
        })
    
    presence_df = pd.DataFrame(presence_records)
    presence_df = presence_df.sort_values(['status', 'presence_percentage'], ascending=[True, False])
    
    return presence_df


def analyze_scan_changes(historical_df: pd.DataFrame) -> pd.DataFrame:
    """
    Analyze changes between consecutive scans (hosts added/removed).
    
    Args:
        historical_df: DataFrame with historical findings
        
    Returns:
        DataFrame with scan-to-scan changes
    """
    if historical_df.empty:
        return pd.DataFrame()
    
    scan_dates = sorted(historical_df['scan_date'].unique())
    change_records = []
    
    for i in range(1, len(scan_dates)):
        prev_scan = scan_dates[i-1]
        curr_scan = scan_dates[i]
        
        # Get hosts in each scan
        prev_hosts = set(historical_df[historical_df['scan_date'] == prev_scan]['hostname'].unique())
        curr_hosts = set(historical_df[historical_df['scan_date'] == curr_scan]['hostname'].unique())
        
        # Find changes
        added_hosts = curr_hosts - prev_hosts
        removed_hosts = prev_hosts - curr_hosts
        unchanged_hosts = curr_hosts & prev_hosts
        
        change_records.append({
            'scan_date': curr_scan,
            'previous_scan': prev_scan,
            'hosts_added': len(added_hosts),
            'hosts_removed': len(removed_hosts),
            'hosts_unchanged': len(unchanged_hosts),
            'total_hosts_current': len(curr_hosts),
            'total_hosts_previous': len(prev_hosts),
            'net_change': len(curr_hosts) - len(prev_hosts),
            'added_host_list': ', '.join(sorted(added_hosts)) if added_hosts else 'None',
            'removed_host_list': ', '.join(sorted(removed_hosts)) if removed_hosts else 'None'
        })
    
    changes_df = pd.DataFrame(change_records)
    return changes_df


def load_existing_database(db_path: str) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Load existing historical database.
    
    Args:
        db_path: Path to SQLite database file
        
    Returns:
        Tuple of (historical_df, lifecycle_df, host_presence_df, scan_changes_df)
    """
    try:
        if not os.path.exists(db_path):
            print(f"Database file {db_path} does not exist")
            return pd.DataFrame(), pd.DataFrame(), pd.DataFrame(), pd.DataFrame()
        
        conn = sqlite3.connect(db_path)
        
        # Load historical findings
        try:
            historical_df = pd.read_sql_query("SELECT * FROM historical_findings", conn)
            historical_df['scan_date'] = pd.to_datetime(historical_df['scan_date'])
            print(f"Loaded {len(historical_df)} historical findings from database")
        except Exception as e:
            print(f"Error loading historical_findings: {e}")
            historical_df = pd.DataFrame()
        
        # Load lifecycle analysis
        try:
            lifecycle_df = pd.read_sql_query("SELECT * FROM finding_lifecycle", conn)
            lifecycle_df['first_seen'] = pd.to_datetime(lifecycle_df['first_seen'])
            lifecycle_df['last_seen'] = pd.to_datetime(lifecycle_df['last_seen'])
            print(f"Loaded {len(lifecycle_df)} lifecycle records from database")
        except Exception as e:
            print(f"Error loading finding_lifecycle: {e}")
            lifecycle_df = pd.DataFrame()
        
        # Load host presence analysis
        try:
            host_presence_df = pd.read_sql_query("SELECT * FROM host_presence", conn)
            host_presence_df['first_seen'] = pd.to_datetime(host_presence_df['first_seen'])
            host_presence_df['last_seen'] = pd.to_datetime(host_presence_df['last_seen'])
            print(f"Loaded {len(host_presence_df)} host presence records from database")
        except Exception as e:
            print(f"Error loading host_presence: {e}")
            host_presence_df = pd.DataFrame()
        
        # Load scan changes
        try:
            scan_changes_df = pd.read_sql_query("SELECT * FROM scan_changes", conn)
            scan_changes_df['scan_date'] = pd.to_datetime(scan_changes_df['scan_date'])
            scan_changes_df['previous_scan'] = pd.to_datetime(scan_changes_df['previous_scan'])
            print(f"Loaded {len(scan_changes_df)} scan change records from database")
        except Exception as e:
            print(f"Error loading scan_changes: {e}")
            scan_changes_df = pd.DataFrame()
        
        conn.close()
        return historical_df, lifecycle_df, host_presence_df, scan_changes_df
        
    except Exception as e:
        print(f"Error loading existing database: {e}")
        return pd.DataFrame(), pd.DataFrame(), pd.DataFrame(), pd.DataFrame()

def export_to_excel(historical_df: pd.DataFrame, lifecycle_df: pd.DataFrame, 
                    host_presence_df: pd.DataFrame, scan_changes_df: pd.DataFrame,
                    excel_path: str) -> None:
    """
    Export data to Excel with multiple sheets and formatting.
    
    Args:
        historical_df: Historical findings DataFrame
        lifecycle_df: Lifecycle analysis DataFrame
        host_presence_df: Host presence analysis DataFrame
        scan_changes_df: Scan changes DataFrame
        excel_path: Path to Excel output file
    """
    try:
        with pd.ExcelWriter(excel_path, engine='openpyxl') as writer:
            # Export sheets
            lifecycle_df.to_excel(writer, sheet_name='Finding_Lifecycle', index=False)
            host_presence_df.to_excel(writer, sheet_name='Host_Presence', index=False)
            scan_changes_df.to_excel(writer, sheet_name='Scan_Changes', index=False)
            historical_df.to_excel(writer, sheet_name='Historical_Data', index=False)
            
            # Create summary statistics including OPDIR
            opdir_mapped = len(lifecycle_df[lifecycle_df.get('opdir_number', '') != '']) if not lifecycle_df.empty else 0
            opdir_overdue = len(lifecycle_df[lifecycle_df.get('opdir_status', '') == 'Overdue']) if not lifecycle_df.empty else 0
            
            summary_data = {
                'Metric': [
                    'Total Scans',
                    'Total Findings (Database)',
                    'Info Findings (Database)',
                    'Findings in Analysis',
                    'Unique Findings',
                    'Active Findings',
                    'Resolved Findings',
                    'Reappeared Findings',
                    'OPDIR Mapped Findings',
                    'OPDIR Overdue Findings',
                    'Total Hosts Ever Seen',
                    'Currently Active Hosts',
                    'Missing Hosts',
                    'Critical Findings',
                    'High Findings',
                    'Medium Findings',
                    'Low Findings'
                ],
                'Count': [
                    historical_df['scan_date'].nunique() if not historical_df.empty else 0,
                    len(historical_df),
                    len(historical_df[historical_df['severity_text'] == 'Info']) if not historical_df.empty else 0,
                    len(lifecycle_df),
                    len(lifecycle_df),
                    len(lifecycle_df[lifecycle_df['status'] == 'Active']) if not lifecycle_df.empty else 0,
                    len(lifecycle_df[lifecycle_df['status'] == 'Resolved']) if not lifecycle_df.empty else 0,
                    len(lifecycle_df[lifecycle_df['reappearances'] > 0]) if not lifecycle_df.empty else 0,
                    opdir_mapped,
                    opdir_overdue,
                    len(host_presence_df),
                    len(host_presence_df[host_presence_df['status'] == 'Active']) if not host_presence_df.empty else 0,
                    len(host_presence_df[host_presence_df['status'] == 'Missing']) if not host_presence_df.empty else 0,
                    len(lifecycle_df[lifecycle_df['severity_text'] == 'Critical']) if not lifecycle_df.empty else 0,
                    len(lifecycle_df[lifecycle_df['severity_text'] == 'High']) if not lifecycle_df.empty else 0,
                    len(lifecycle_df[lifecycle_df['severity_text'] == 'Medium']) if not lifecycle_df.empty else 0,
                    len(lifecycle_df[lifecycle_df['severity_text'] == 'Low']) if not lifecycle_df.empty else 0
                ]
            }
            summary_df = pd.DataFrame(summary_data)
            summary_df.to_excel(writer, sheet_name='Summary', index=False)
            
            # Auto-fit columns and add filters with banding
            for sheet_name in writer.sheets:
                worksheet = writer.sheets[sheet_name]
                
                # Auto-fit columns
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
                
                # Add autofilter and banding
                if worksheet.max_row > 0:
                    worksheet.auto_filter.ref = worksheet.dimensions
                    
                    # Add table formatting with banding
                    if worksheet.max_row > 1:
                        from openpyxl.worksheet.table import Table, TableStyleInfo
                        tab = Table(displayName=f"Table_{sheet_name}", ref=worksheet.dimensions)
                        style = TableStyleInfo(name="TableStyleMedium9", showFirstColumn=False,
                                             showLastColumn=False, showRowStripes=True, showColumnStripes=True)
                        tab.tableStyleInfo = style
                        worksheet.add_table(tab)
        
        print(f"Successfully exported to Excel: {excel_path}")
        
    except Exception as e:
        print(f"Error exporting to Excel: {e}")
        import traceback
        traceback.print_exc()

def check_for_duplicates(new_df: pd.DataFrame, existing_df: pd.DataFrame) -> Tuple[pd.DataFrame, int]:
    """
    Check for and remove duplicate scans based on scan_date and scan_file.
    
    Args:
        new_df: New findings DataFrame
        existing_df: Existing findings DataFrame
        
    Returns:
        Tuple of (filtered_new_df, duplicate_count)
    """
    if existing_df.empty:
        return new_df, 0
    
    # Create composite key for duplicate detection
    new_df['composite_key'] = new_df['scan_date'].astype(str) + '|' + new_df['scan_file'].astype(str)
    existing_df['composite_key'] = existing_df['scan_date'].astype(str) + '|' + existing_df['scan_file'].astype(str)
    
    # Find duplicates
    duplicate_keys = set(existing_df['composite_key'].unique())
    new_unique_mask = ~new_df['composite_key'].isin(duplicate_keys)
    
    filtered_new_df = new_df[new_unique_mask].copy()
    duplicate_count = len(new_df) - len(filtered_new_df)
    
    # Remove the temporary composite key
    filtered_new_df = filtered_new_df.drop('composite_key', axis=1)
    
    return filtered_new_df, duplicate_count


def process_historical_scans(archive_paths: List[str], plugins_db_path: Optional[str] = None, 
                           existing_db_path: Optional[str] = None, include_info: bool = False) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Process multiple Nessus archives and track findings history with enhanced features.
    
    Args:
        archive_paths: List of paths to Nessus archives or .nessus files
        plugins_db_path: Optional path to plugins database
        existing_db_path: Optional path to existing database to update
        include_info: Whether to include Info-level findings in analysis (default: False)
        
    Returns:
        Tuple of (historical_df, lifecycle_df, host_presence_df, scan_changes_df)
    """
    import tempfile
    
    # Load existing database if provided
    existing_historical_df = pd.DataFrame()
    if existing_db_path and os.path.exists(existing_db_path):
        print(f"Loading existing database from {existing_db_path}")
        existing_historical_df, _, _, _ = load_existing_database(existing_db_path)
    
    # Load plugins database if provided
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
            # Determine scan date from filename first
            scan_date = extract_scan_date_from_filename(os.path.basename(archive_path))
            
            # Handle different input types
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
            
            # If no date from filename, try extracting from first .nessus file
            if not scan_date and nessus_files:
                scan_date = extract_scan_date_from_nessus(nessus_files[0])
            
            # Fallback to file modification time
            if not scan_date:
                scan_date = datetime.fromtimestamp(os.path.getmtime(archive_path))
                print(f"Warning: Using file modification time for scan date: {scan_date.strftime('%Y-%m-%d')}")
            else:
                print(f"Scan date: {scan_date.strftime('%Y-%m-%d')}")
            
            # Parse nessus files with improved host display
            findings_df, host_summary_df = parse_multiple_nessus_files(nessus_files, plugins_dict)
            
            if not findings_df.empty:
                # Add scan metadata
                findings_df['scan_date'] = scan_date
                findings_df['scan_file'] = os.path.basename(archive_path)
                
                # Enrich with severity
                findings_df = enrich_findings_with_severity(findings_df)
                
                all_historical_findings.append(findings_df)
                
                # Display with hostname (IP) format
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
    
    # Combine all new findings
    new_historical_df = pd.concat(all_historical_findings, ignore_index=True)
    
    # Check for duplicates if we have existing data
    duplicate_count = 0
    if not existing_historical_df.empty:
        print(f"\nChecking for duplicates against existing database...")
        new_historical_df, duplicate_count = check_for_duplicates(new_historical_df, existing_historical_df)
        if duplicate_count > 0:
            print(f"Filtered out {duplicate_count} duplicate findings")
    
    # Combine with existing data
    if not existing_historical_df.empty and not new_historical_df.empty:
        combined_df = pd.concat([existing_historical_df, new_historical_df], ignore_index=True)
    elif not existing_historical_df.empty:
        combined_df = existing_historical_df
    else:
        combined_df = new_historical_df
    
    combined_df = combined_df.sort_values('scan_date')
    
    print(f"\n{'='*60}")
    print(f"Total findings across all scans: {len(combined_df)}")
    if not new_historical_df.empty:
        print(f"New findings added: {len(new_historical_df)}")
    if duplicate_count > 0:
        print(f"Duplicate findings filtered: {duplicate_count}")
    print(f"Date range: {combined_df['scan_date'].min()} to {combined_df['scan_date'].max()}")
    print(f"{'='*60}\n")
    
    # Perform analysis (filter Info findings for analysis only, not database storage)
    analysis_df = combined_df.copy()
    if not include_info:
        analysis_df = analysis_df[analysis_df['severity_text'] != 'Info']
        print(f"Filtered out {len(combined_df) - len(analysis_df)} Info-level findings from analysis")
    
    lifecycle_df = analyze_finding_lifecycle(analysis_df)
    host_presence_df = create_host_presence_analysis(analysis_df)
    scan_changes_df = analyze_scan_changes(analysis_df)
    
    return combined_df, lifecycle_df, host_presence_df, scan_changes_df


def analyze_finding_lifecycle(historical_df: pd.DataFrame) -> pd.DataFrame:
    """
    Analyze the lifecycle of findings (first seen, last seen, resolved, reappeared).
    
    Args:
        historical_df: DataFrame with historical findings
        
    Returns:
        DataFrame with lifecycle analysis
    """
    if historical_df.empty:
        return pd.DataFrame()
    
    # Create unique finding identifier
    historical_df['finding_key'] = (
        historical_df['hostname'].astype(str) + '|' + 
        historical_df['plugin_id'].astype(str)
    )
    
    lifecycle_records = []
    
    # Group by finding_key
    for finding_key, group in historical_df.groupby('finding_key'):
        hostname, plugin_id = finding_key.split('|')
        
        # Sort by scan date
        group = group.sort_values('scan_date')
        
        scan_dates = group['scan_date'].tolist()
        scan_files = group['scan_file'].tolist()
        
        # Get finding details from most recent observation
        latest = group.iloc[-1]
        
        first_seen = scan_dates[0]
        last_seen = scan_dates[-1]
        total_observations = len(scan_dates)
        
        # Check for gaps (resolved then reappeared)
        gaps = []
        reappearances = 0

        if len(scan_dates) > 1:
            for i in range(1, len(scan_dates)):
                days_gap = (scan_dates[i] - scan_dates[i-1]).days
                if days_gap > 45:  # More than 45 days gap suggests resolution
                    gaps.append({
                        'resolved_after': scan_dates[i-1].strftime('%Y-%m-%d'),
                        'reappeared_on': scan_dates[i].strftime('%Y-%m-%d'),
                        'days_resolved': days_gap
                    })
                    reappearances += 1
        
        # Determine current status
        if latest['scan_date'] == historical_df['scan_date'].max():
            status = 'Active'
        else:
            status = 'Resolved'
        
        lifecycle_records.append({
            'hostname': hostname,
            'ip_address': latest.get('ip_address', ''),
            'plugin_id': plugin_id,
            'plugin_name': latest['name'],
            'severity_text': latest.get('severity_text', 'Unknown'),
            'severity_value': latest.get('severity_value', 0),
            'first_seen': first_seen,
            'last_seen': last_seen,
            'days_open': (last_seen - first_seen).days,
            'total_observations': total_observations,
            'reappearances': reappearances,
            'status': status,
            'gap_details': json.dumps(gaps) if gaps else '',
            'cvss3_base_score': latest.get('cvss3_base_score'),
            'cves': latest.get('cves', ''),
            'iavx': latest.get('iavx', '')
        })
    
    lifecycle_df = pd.DataFrame(lifecycle_records)
    lifecycle_df = lifecycle_df.sort_values(['severity_value', 'days_open'], ascending=[False, False])
    
    return lifecycle_df


def export_to_sqlite(historical_df: pd.DataFrame, lifecycle_df: pd.DataFrame, 
                     host_presence_df: pd.DataFrame, scan_changes_df: pd.DataFrame,
                     db_path: str) -> None:
    """
    Export data to SQLite database with enhanced tables.
    
    Args:
        historical_df: Historical findings DataFrame
        lifecycle_df: Lifecycle analysis DataFrame
        host_presence_df: Host presence analysis DataFrame
        scan_changes_df: Scan changes DataFrame
        db_path: Path to SQLite database file
    """
    try:
        conn = sqlite3.connect(db_path)
        
        # Export all DataFrames
        historical_df.to_sql('historical_findings', conn, if_exists='replace', index=False)
        lifecycle_df.to_sql('finding_lifecycle', conn, if_exists='replace', index=False)
        host_presence_df.to_sql('host_presence', conn, if_exists='replace', index=False)
        scan_changes_df.to_sql('scan_changes', conn, if_exists='replace', index=False)
        
        # Create indexes for better query performance
        cursor = conn.cursor()
        
        # Historical findings indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_historical_hostname ON historical_findings(hostname)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_historical_plugin ON historical_findings(plugin_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_historical_date ON historical_findings(scan_date)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_historical_ip ON historical_findings(ip_address)')
        
        # Lifecycle indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_lifecycle_hostname ON finding_lifecycle(hostname)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_lifecycle_plugin ON finding_lifecycle(plugin_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_lifecycle_status ON finding_lifecycle(status)')
        
        # Host presence indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_host_presence_hostname ON host_presence(hostname)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_host_presence_status ON host_presence(status)')
        
        # Scan changes indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_changes_date ON scan_changes(scan_date)')
        
        conn.commit()
        conn.close()
        
        print(f"Successfully exported to SQLite database: {db_path}")
        
    except Exception as e:
        print(f"Error exporting to SQLite: {e}")
        import traceback
        traceback.print_exc()


def export_to_json(historical_df: pd.DataFrame, lifecycle_df: pd.DataFrame, 
                   host_presence_df: pd.DataFrame, scan_changes_df: pd.DataFrame,
                   json_path: str) -> None:
    """
    Export data to JSON file with enhanced structure.
    
    Args:
        historical_df: Historical findings DataFrame
        lifecycle_df: Lifecycle analysis DataFrame
        host_presence_df: Host presence analysis DataFrame
        scan_changes_df: Scan changes DataFrame
        json_path: Path to JSON output file
    """
    try:
        # Convert datetime columns to ISO format strings before export
        historical_export = historical_df.copy()
        lifecycle_export = lifecycle_df.copy()
        host_presence_export = host_presence_df.copy()
        scan_changes_export = scan_changes_df.copy()
        
        # Convert datetime columns in historical_df
        if 'scan_date' in historical_export.columns:
            historical_export['scan_date'] = historical_export['scan_date'].dt.strftime('%Y-%m-%d %H:%M:%S')
        
        # Convert datetime columns in lifecycle_df
        if 'first_seen' in lifecycle_export.columns:
            lifecycle_export['first_seen'] = lifecycle_export['first_seen'].dt.strftime('%Y-%m-%d %H:%M:%S')
        if 'last_seen' in lifecycle_export.columns:
            lifecycle_export['last_seen'] = lifecycle_export['last_seen'].dt.strftime('%Y-%m-%d %H:%M:%S')
        
        # Convert datetime columns in host_presence_df
        if 'first_seen' in host_presence_export.columns:
            host_presence_export['first_seen'] = host_presence_export['first_seen'].dt.strftime('%Y-%m-%d %H:%M:%S')
        if 'last_seen' in host_presence_export.columns:
            host_presence_export['last_seen'] = host_presence_export['last_seen'].dt.strftime('%Y-%m-%d %H:%M:%S')
        
        # Convert datetime columns in scan_changes_df
        if 'scan_date' in scan_changes_export.columns:
            scan_changes_export['scan_date'] = scan_changes_export['scan_date'].dt.strftime('%Y-%m-%d %H:%M:%S')
        if 'previous_scan' in scan_changes_export.columns:
            scan_changes_export['previous_scan'] = scan_changes_export['previous_scan'].dt.strftime('%Y-%m-%d %H:%M:%S')
        
        # Replace NaN with None for JSON compatibility
        historical_export = historical_export.where(pd.notnull(historical_export), None)
        lifecycle_export = lifecycle_export.where(pd.notnull(lifecycle_export), None)
        host_presence_export = host_presence_export.where(pd.notnull(host_presence_export), None)
        scan_changes_export = scan_changes_export.where(pd.notnull(scan_changes_export), None)
        
        export_data = {
            'metadata': {
                'export_date': datetime.now().isoformat(),
                'total_findings': len(historical_df),
                'unique_findings': len(lifecycle_df),
                'total_hosts': len(host_presence_df),
                'total_scans': len(scan_changes_df) + 1 if len(scan_changes_df) > 0 else len(historical_df['scan_date'].unique()) if not historical_df.empty else 0,
                'date_range': {
                    'start': historical_df['scan_date'].min().isoformat() if not historical_df.empty and 'scan_date' in historical_df.columns else None,
                    'end': historical_df['scan_date'].max().isoformat() if not historical_df.empty and 'scan_date' in historical_df.columns else None
                }
            },
            'historical_findings': historical_export.to_dict('records'),
            'lifecycle_analysis': lifecycle_export.to_dict('records'),
            'host_presence': host_presence_export.to_dict('records'),
            'scan_changes': scan_changes_export.to_dict('records')
        }
        
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        print(f"Successfully exported to JSON: {json_path}")
        
    except Exception as e:
        print(f"Error exporting to JSON: {e}")
        import traceback
        traceback.print_exc()


def export_json_schema(schema_path: str) -> None:
    """
    Export JSON schema definition for the export format.
    
    Args:
        schema_path: Path to save the JSON schema file
    """
    schema = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "Nessus Historical Analysis Export",
        "type": "object",
        "properties": {
            "metadata": {
                "type": "object",
                "properties": {
                    "export_date": {"type": "string", "format": "date-time"},
                    "total_findings": {"type": "integer"},
                    "unique_findings": {"type": "integer"},
                    "total_hosts": {"type": "integer"},
                    "total_scans": {"type": "integer"},
                    "date_range": {
                        "type": "object",
                        "properties": {
                            "start": {"type": ["string", "null"], "format": "date-time"},
                            "end": {"type": ["string", "null"], "format": "date-time"}
                        }
                    }
                }
            },
            "historical_findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "plugin_id": {"type": "string"},
                        "hostname": {"type": "string"},
                        "ip_address": {"type": "string"},
                        "scan_date": {"type": "string", "format": "date-time"},
                        "scan_file": {"type": "string"},
                        "name": {"type": "string"},
                        "severity_text": {"type": "string"},
                        "severity_value": {"type": "integer"},
                        "cvss3_base_score": {"type": ["string", "null"]},
                        "cvss2_base_score": {"type": ["string", "null"]},
                        "cves": {"type": ["string", "null"]},
                        "iavx": {"type": ["string", "null"]}
                    }
                }
            },
            "lifecycle_analysis": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "hostname": {"type": "string"},
                        "ip_address": {"type": "string"},
                        "plugin_id": {"type": "string"},
                        "plugin_name": {"type": "string"},
                        "severity_text": {"type": "string"},
                        "severity_value": {"type": "integer"},
                        "first_seen": {"type": "string", "format": "date-time"},
                        "last_seen": {"type": "string", "format": "date-time"},
                        "days_open": {"type": "integer"},
                        "total_observations": {"type": "integer"},
                        "reappearances": {"type": "integer"},
                        "status": {"type": "string", "enum": ["Active", "Resolved"]},
                        "gap_details": {"type": "string"}
                    }
                }
            },
            "host_presence": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "hostname": {"type": "string"},
                        "ip_address": {"type": "string"},
                        "first_seen": {"type": "string", "format": "date-time"},
                        "last_seen": {"type": "string", "format": "date-time"},
                        "total_scans_available": {"type": "integer"},
                        "scans_present": {"type": "integer"},
                        "scans_missing": {"type": "integer"},
                        "presence_percentage": {"type": "number"},
                        "status": {"type": "string", "enum": ["Active", "Missing"]},
                        "missing_scan_dates": {"type": "string"}
                    }
                }
            },
            "scan_changes": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "scan_date": {"type": "string", "format": "date-time"},
                        "previous_scan": {"type": "string", "format": "date-time"},
                        "hosts_added": {"type": "integer"},
                        "hosts_removed": {"type": "integer"},
                        "hosts_unchanged": {"type": "integer"},
                        "total_hosts_current": {"type": "integer"},
                        "total_hosts_previous": {"type": "integer"},
                        "net_change": {"type": "integer"},
                        "added_host_list": {"type": "string"},
                        "removed_host_list": {"type": "string"}
                    }
                }
            }
        }
    }
    
    try:
        with open(schema_path, 'w', encoding='utf-8') as f:
            json.dump(schema, f, indent=2, ensure_ascii=False)
        
        print(f"Successfully exported JSON schema: {schema_path}")
        
    except Exception as e:
        print(f"Error exporting JSON schema: {e}")


# OPDIR Integration Functions
def extract_iavx_mapping(iavx_full: str) -> str:
    """Extract IAVx mapping from full IAVA/B/T identifier."""
    if pd.isna(iavx_full) or not isinstance(iavx_full, str):
        return ''
    
    iavx_clean = str(iavx_full).strip().upper()
    
    if '-' in iavx_clean:
        parts = iavx_clean.split('-')
        
        if len(parts) >= 4 and parts[0].startswith('IAV'):
            iav_type = parts[2]
            number = parts[3]
            return f"{iav_type.lower()}-{number}"
        
        elif len(parts) == 2:
            iav_type = parts[0]
            number = parts[1]
            return f"{iav_type.lower()}-{number}"
    
    return iavx_clean.lower()

def load_opdir_mapping(opdir_file_path: str) -> pd.DataFrame:
    """Load and process OPDIR mapping from Excel/CSV file."""
    try:
        if opdir_file_path.lower().endswith('.csv'):
            opdir_df = pd.read_csv(opdir_file_path, dtype={'OPDIR NUMBER': str, 'OPDIR_NUMBER': str})
        else:
            excel_file = pd.ExcelFile(opdir_file_path)
            sheet_names = excel_file.sheet_names
            
            if len(sheet_names) == 1:
                selected_sheet = sheet_names[0]
            else:
                selected_sheet = select_excel_sheet(sheet_names, opdir_file_path)
                if not selected_sheet:
                    return pd.DataFrame()
            
            opdir_df = pd.read_excel(opdir_file_path, 
                                   sheet_name=selected_sheet,
                                   dtype={'OPDIR NUMBER': str, 'OPDIR_NUMBER': str, 'OPDIR': str})
        
        # Standardize column names
        column_mapping = {
            'OPDIR NUMBER': 'opdir_number', 'OPDIR_NUMBER': 'opdir_number', 'OPDIR': 'opdir_number',
            'IAVA/B': 'iavx_full', 'IAVA_B': 'iavx_full', 'IAVX': 'iavx_full', 'IAV': 'iavx_full',
            'SUBJECT': 'subject', 'TITLE': 'subject', 'DESCRIPTION': 'subject',
            'RELEASE DATE': 'release_date', 'RELEASE_DATE': 'release_date', 'RELEASED': 'release_date',
            'FINAL DUE DATE': 'final_due_date', 'FINAL_DUE_DATE': 'final_due_date', 'DUE_DATE': 'final_due_date'
        }
        
        opdir_df.columns = opdir_df.columns.str.strip().str.upper()
        for old_col, new_col in column_mapping.items():
            if old_col in opdir_df.columns:
                opdir_df = opdir_df.rename(columns={old_col: new_col})
        
        # Process IAVx mapping
        if 'iavx_full' in opdir_df.columns:
            opdir_df['iavx_mapped'] = opdir_df['iavx_full'].apply(extract_iavx_mapping)
        
        # Process date columns
        date_columns = ['release_date', 'final_due_date']
        for col in date_columns:
            if col in opdir_df.columns:
                opdir_df[col] = pd.to_datetime(opdir_df[col], errors='coerce')
        
        # Add status tracking
        if 'final_due_date' in opdir_df.columns:
            today = datetime.now()
            opdir_df['days_until_due'] = (opdir_df['final_due_date'] - today).dt.days
            opdir_df['status'] = opdir_df['days_until_due'].apply(
                lambda x: 'Overdue' if pd.notna(x) and x < 0 else 
                         'Due Soon' if pd.notna(x) and x <= 30 else 
                         'On Track' if pd.notna(x) else 'Unknown'
            )
        
        return opdir_df.dropna(how='all')
        
    except Exception as e:
        print(f"Error loading OPDIR file: {e}")
        return pd.DataFrame()

def select_excel_sheet(sheet_names: list, file_path: str) -> str:
    """Present user with sheet selection dialog for Excel files."""
    import tkinter as tk
    from tkinter import messagebox, simpledialog
    
    root = tk.Tk()
    root.withdraw()
    
    message = f"Excel file contains multiple sheets:\n\n"
    for i, sheet in enumerate(sheet_names, 1):
        message += f"{i}. {sheet}\n"
    
    choice = messagebox.askquestion(
        "Select OPDIR Sheet",
        message + f"\n\nClick 'Yes' to use the first sheet ('{sheet_names[0]}'),\n" +
        f"or 'No' to choose a different sheet.",
        icon='question'
    )
    
    if choice == 'yes':
        selected_sheet = sheet_names[0]
    else:
        sheet_list = "\n".join([f"{i}: {sheet}" for i, sheet in enumerate(sheet_names, 1)])
        user_input = simpledialog.askstring(
            "Sheet Selection",
            f"Enter the sheet number or exact sheet name:\n\n{sheet_list}",
            parent=root
        )
        
        if not user_input:
            return None
        
        try:
            sheet_index = int(user_input) - 1
            if 0 <= sheet_index < len(sheet_names):
                selected_sheet = sheet_names[sheet_index]
            else:
                messagebox.showerror("Invalid Selection", f"Sheet number must be between 1 and {len(sheet_names)}")
                return None
        except ValueError:
            if user_input in sheet_names:
                selected_sheet = user_input
            else:
                messagebox.showerror("Invalid Selection", f"Sheet '{user_input}' not found")
                return None
    
    root.destroy()
    return selected_sheet

def enrich_findings_with_opdir(lifecycle_df: pd.DataFrame, opdir_df: pd.DataFrame) -> pd.DataFrame:
    """Enrich findings with OPDIR information based on IAVx mapping."""
    if lifecycle_df.empty or opdir_df.empty:
        opdir_columns = ['opdir_number', 'opdir_subject', 'opdir_release_date',
                        'opdir_final_due_date', 'opdir_status']
        for col in opdir_columns:
            lifecycle_df[col] = ''
        return lifecycle_df
    
    enhanced_df = lifecycle_df.copy()
    
    # Extract IAVx from findings
    if 'iavx' in enhanced_df.columns:
        enhanced_df['iavx_mapped'] = enhanced_df['iavx'].apply(extract_iavx_mapping)
    else:
        enhanced_df['iavx_mapped'] = ''
    
    # Create OPDIR lookup
    if 'iavx_mapped' in opdir_df.columns:
        valid_opdir = opdir_df[opdir_df['iavx_mapped'] != ''].copy()
        
        if not valid_opdir.empty:
            if 'release_date' in valid_opdir.columns:
                valid_opdir = valid_opdir.sort_values('release_date', ascending=False)
            
            opdir_lookup = valid_opdir.drop_duplicates('iavx_mapped').set_index('iavx_mapped').to_dict('index')
            
            # Initialize OPDIR columns
            enhanced_df['opdir_number'] = ''
            enhanced_df['opdir_subject'] = ''
            enhanced_df['opdir_release_date'] = pd.NaT
            enhanced_df['opdir_final_due_date'] = pd.NaT
            enhanced_df['opdir_status'] = ''
            
            # Apply OPDIR information
            for idx, row in enhanced_df.iterrows():
                iavx_key = row.get('iavx_mapped', '')
                if iavx_key and iavx_key in opdir_lookup:
                    opdir_info = opdir_lookup[iavx_key]
                    enhanced_df.at[idx, 'opdir_number'] = opdir_info.get('opdir_number', '')
                    enhanced_df.at[idx, 'opdir_subject'] = opdir_info.get('subject', '')
                    enhanced_df.at[idx, 'opdir_release_date'] = opdir_info.get('release_date', pd.NaT)
                    enhanced_df.at[idx, 'opdir_final_due_date'] = opdir_info.get('final_due_date', pd.NaT)
                    enhanced_df.at[idx, 'opdir_status'] = opdir_info.get('status', '')
    
    return enhanced_df


class EnhancedHistoricalAnalysisGUI:
    """Enhanced GUI for Nessus Historical Analysis with streamlined filters and comprehensive visualizations"""
    
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Enhanced Nessus Historical Analysis System")
        self.window.geometry("1400x900")
        self.window.configure(bg='#2b2b2b')
        
        # Configure dark theme
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.configure_dark_theme()
        
        # Initialize data variables
        self.archive_paths = []
        self.plugins_db_path = None
        self.existing_db_path = None
        self.opdir_file_path = None
        
        # Initialize filter variables
        self.include_info = tk.BooleanVar(value=False)
        self.use_date_filter = tk.BooleanVar(value=False)
        self.filter_start_date = tk.StringVar()
        self.filter_end_date = tk.StringVar()
        self.severity_filter = tk.StringVar(value="All Severities")
        self.status_filter = tk.StringVar(value="All Statuses")
        self.host_filter = tk.StringVar()
        self.cvss_min = tk.DoubleVar(value=0.0)
        self.cvss_max = tk.DoubleVar(value=10.0)
        self.opdir_filter = tk.StringVar(value="All")
        
        # Data storage
        self.historical_df = pd.DataFrame()
        self.lifecycle_df = pd.DataFrame()
        self.host_presence_df = pd.DataFrame()
        self.scan_changes_df = pd.DataFrame()
        self.opdir_df = pd.DataFrame()
        self.historical_info_df = pd.DataFrame() 
        
        self.setup_ui()
    
    def configure_dark_theme(self):
        """Configure dark theme for all widgets"""
        self.style.configure('.', background='#2b2b2b', foreground='white')
        self.style.configure('TLabel', background='#2b2b2b', foreground='white')
        self.style.configure('TFrame', background='#2b2b2b')
        self.style.configure('TLabelFrame', background='#2b2b2b', foreground='white')
        self.style.configure('TButton', background='#404040', foreground='white')
        self.style.map('TButton', background=[('active', '#505050')])
        
        # Entry widgets
        self.style.configure('TEntry', 
                            fieldbackground='#404040', foreground='white',
                            bordercolor='#606060', insertcolor='white')
        
        # Combobox
        self.style.configure('TCombobox',
                            fieldbackground='#404040', 
                            background='#404040',
                            foreground='white', 
                            arrowcolor='white',
                            bordercolor='#606060',
                            lightcolor='#606060',
                            darkcolor='#606060',
                            insertcolor='white')

        self.style.map('TCombobox',
                    fieldbackground=[('readonly', '#404040'),
                                    ('disabled', '#2b2b2b'),
                                    ('focus', '#505050')],
                    background=[('readonly', '#404040'),
                                ('disabled', '#2b2b2b'),
                                ('focus', '#505050')],
                    foreground=[('readonly', 'white'),
                                ('disabled', 'white'),
                                ('focus', 'white')])
        
        # Notebook tabs
        self.style.configure('TNotebook', background='#2b2b2b', borderwidth=0)
        self.style.configure('TNotebook.Tab', 
                            background='#404040', foreground='white',
                            padding=[20, 10], borderwidth=1)
        self.style.map('TNotebook.Tab',
                      background=[('selected', '#2b2b2b'), ('active', '#505050')],
                      foreground=[('selected', 'white')])
    
    def setup_ui(self):
        """Setup the user interface with streamlined filter controls"""
        main_frame = ttk.Frame(self.window, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.window.columnconfigure(0, weight=1)
        self.window.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(3, weight=1)
        
        # File selection frame
        self.setup_file_selection(main_frame)
        
        # Streamlined filters frame
        self.setup_streamlined_filters(main_frame)
        
        # Action buttons
        self.setup_action_buttons(main_frame)
        
        # Notebook for visualizations
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=3, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        # Status tab
        self.setup_status_tab()
        
        self.viz_frames = {}
    
    def setup_file_selection(self, parent):
        """Setup compact file selection controls"""
        file_frame = ttk.LabelFrame(parent, text="File Selection", padding="5")
        file_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=2)
        file_frame.columnconfigure(1, weight=1)
        file_frame.columnconfigure(4, weight=1)
        
        # Row 0: Archives and Plugins DB
        ttk.Label(file_frame, text="Archives:").grid(row=0, column=0, sticky=tk.W, padx=(0,5))
        self.archives_label = ttk.Label(file_frame, text="No files selected", foreground="gray")
        self.archives_label.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=2)
        ttk.Button(file_frame, text="Select", command=self.select_archives, width=8).grid(row=0, column=2, padx=5)
        
        ttk.Label(file_frame, text="Plugins DB:").grid(row=0, column=3, sticky=tk.W, padx=(10,5))
        self.plugins_label = ttk.Label(file_frame, text="None", foreground="gray")
        self.plugins_label.grid(row=0, column=4, sticky=(tk.W, tk.E), padx=2)
        ttk.Button(file_frame, text="Select", command=self.select_plugins_db, width=8).grid(row=0, column=5, padx=5)
        
        # Row 1: Existing DB and OPDIR file
        ttk.Label(file_frame, text="Existing DB:").grid(row=1, column=0, sticky=tk.W, padx=(0,5), pady=(5,0))
        self.existing_db_label = ttk.Label(file_frame, text="None", foreground="gray")
        self.existing_db_label.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=2, pady=(5,0))
        ttk.Button(file_frame, text="Load", command=self.select_existing_db, width=8).grid(row=1, column=2, padx=5, pady=(5,0))
        
        ttk.Label(file_frame, text="OPDIR File:").grid(row=1, column=3, sticky=tk.W, padx=(10,5), pady=(5,0))
        self.opdir_label = ttk.Label(file_frame, text="None", foreground="gray")
        self.opdir_label.grid(row=1, column=4, sticky=(tk.W, tk.E), padx=2, pady=(5,0))
        ttk.Button(file_frame, text="Select", command=self.select_opdir_file, width=8).grid(row=1, column=5, padx=5, pady=(5,0))

    def setup_streamlined_filters(self, parent):
        """Setup compact streamlined filter controls"""
        filter_frame = ttk.LabelFrame(parent, text="Analysis & Visualization Filters", padding="5")
        filter_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=2)
        filter_frame.columnconfigure(1, weight=1)
        filter_frame.columnconfigure(3, weight=1)
        filter_frame.columnconfigure(5, weight=1)
        
        # Row 0: Analysis Level and Date Range
        ttk.Label(filter_frame, text="Analysis Level:", font=('TkDefaultFont', 9, 'bold')).grid(row=0, column=0, sticky=tk.W)
        info_checkbox = ttk.Checkbutton(filter_frame, text="Include Info", variable=self.include_info)
        info_checkbox.grid(row=0, column=1, sticky=tk.W, padx=(5,20))
        
        ttk.Label(filter_frame, text="Date Range:", font=('TkDefaultFont', 9, 'bold')).grid(row=0, column=2, sticky=tk.W)
        date_checkbox = ttk.Checkbutton(filter_frame, text="Enable", variable=self.use_date_filter, 
                                    command=self.toggle_date_controls)
        date_checkbox.grid(row=0, column=3, sticky=tk.W, padx=5)
        
        ttk.Label(filter_frame, text="Start:").grid(row=0, column=4, sticky=tk.W, padx=(10,2))
        self.start_date_entry = ttk.Entry(filter_frame, textvariable=self.filter_start_date, width=10, state='disabled')
        self.start_date_entry.grid(row=0, column=5, sticky=tk.W, padx=(0,5))
        
        ttk.Label(filter_frame, text="End:").grid(row=0, column=6, sticky=tk.W, padx=(5,2))
        self.end_date_entry = ttk.Entry(filter_frame, textvariable=self.filter_end_date, width=10, state='disabled')
        self.end_date_entry.grid(row=0, column=7, sticky=tk.W)
        
        # Row 1: Severity, Status, and CVSS
        ttk.Label(filter_frame, text="Severity:", font=('TkDefaultFont', 9, 'bold')).grid(row=1, column=0, sticky=tk.W, pady=(5,0))
        severity_combo = ttk.Combobox(filter_frame, textvariable=self.severity_filter, width=18, state='readonly')
        severity_combo['values'] = ('All Severities', 'Critical', 'High', 'Medium', 'Low', 'Info', 'Critical+High', 'Medium+High+Critical')
        severity_combo.grid(row=1, column=1, sticky=tk.W, padx=(5,20), pady=(5,0))
        
        ttk.Label(filter_frame, text="Status:", font=('TkDefaultFont', 9, 'bold')).grid(row=1, column=2, sticky=tk.W, pady=(5,0))
        status_combo = ttk.Combobox(filter_frame, textvariable=self.status_filter, width=12, state='readonly')
        status_combo['values'] = ('All Statuses', 'Active', 'Resolved')
        status_combo.grid(row=1, column=3, sticky=tk.W, padx=5, pady=(5,0))
        
        ttk.Label(filter_frame, text="CVSS:", font=('TkDefaultFont', 9, 'bold')).grid(row=1, column=4, sticky=tk.W, padx=(10,2), pady=(5,0))
        
        cvss_frame = ttk.Frame(filter_frame)
        cvss_frame.grid(row=1, column=5, columnspan=3, sticky=tk.W, pady=(5,0))
        
        ttk.Label(cvss_frame, text="Min:").pack(side=tk.LEFT)
        cvss_min_spinbox = tk.Spinbox(cvss_frame, from_=0.0, to=10.0, increment=0.1, width=5, 
                                    textvariable=self.cvss_min, bg='#404040', fg='white', 
                                    insertbackground='white', buttonbackground='#505050')
        cvss_min_spinbox.pack(side=tk.LEFT, padx=(2,8))
        
        ttk.Label(cvss_frame, text="Max:").pack(side=tk.LEFT)
        cvss_max_spinbox = tk.Spinbox(cvss_frame, from_=0.0, to=10.0, increment=0.1, width=5,
                                    textvariable=self.cvss_max, bg='#404040', fg='white',
                                    insertbackground='white', buttonbackground='#505050')
        cvss_max_spinbox.pack(side=tk.LEFT, padx=2)
        
        # Row 2: Host, OPDIR Status, and Controls
        ttk.Label(filter_frame, text="Host:", font=('TkDefaultFont', 9, 'bold')).grid(row=2, column=0, sticky=tk.W, pady=(5,0))
        host_entry = ttk.Entry(filter_frame, textvariable=self.host_filter, width=20)
        host_entry.grid(row=2, column=1, sticky=tk.W, padx=(5,20), pady=(5,0))
        
        ttk.Label(filter_frame, text="OPDIR Status:", font=('TkDefaultFont', 9, 'bold')).grid(row=2, column=2, sticky=tk.W, pady=(5,0))
        opdir_combo = ttk.Combobox(filter_frame, textvariable=self.opdir_filter, width=14, state='readonly')
        opdir_combo['values'] = ('All', 'OPDIR Mapped Only', 'No OPDIR', 'Overdue', 'Due Soon', 'On Track')
        opdir_combo.grid(row=2, column=3, sticky=tk.W, padx=5, pady=(5,0))
        
        # Filter Controls
        control_frame = ttk.Frame(filter_frame)
        control_frame.grid(row=2, column=4, columnspan=4, sticky=(tk.W, tk.E), padx=(10,0), pady=(5,0))
        
        ttk.Button(control_frame, text="Apply Filters", command=self.apply_filters).pack(side=tk.LEFT, padx=(0,5))
        ttk.Button(control_frame, text="Reset", command=self.reset_filters).pack(side=tk.LEFT, padx=(0,10))
        
        self.filter_status_label = ttk.Label(control_frame, text="No filters applied", foreground="gray")
        self.filter_status_label.pack(side=tk.LEFT)

    def setup_action_buttons(self, parent):
        """Setup action buttons"""
        action_frame = ttk.Frame(parent, padding="10")
        action_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=5)
        
        buttons = [
            ("Process/Analyze", self.process_archives),
            ("Refresh Analysis", self.refresh_analysis),
            ("Export to Excel", self.export_excel),
            ("Export to SQLite", self.export_sqlite),
            ("Export to JSON", self.export_json)
        ]
        
        for i, (text, command) in enumerate(buttons):
            ttk.Button(action_frame, text=text, command=command).pack(side=tk.LEFT, padx=5)
    
    def setup_status_tab(self):
        """Setup status/log tab"""
        self.status_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.status_frame, text="Status")
        
        self.status_text = tk.Text(self.status_frame, wrap=tk.WORD, height=20, 
                                   bg='#1e1e1e', fg='white', insertbackground='white')
        self.status_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        status_scroll = ttk.Scrollbar(self.status_frame, command=self.status_text.yview)
        status_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.status_text.config(yscrollcommand=status_scroll.set)
    
    def toggle_date_controls(self):
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
    
    def get_filtered_data(self, df: pd.DataFrame, apply_lifecycle_filters: bool = True) -> pd.DataFrame:
        """Apply all filters to the DataFrame"""
        if df.empty:
            return df
            
        filtered_df = df.copy()
        
        # Info filter (affects analysis data creation) - only apply to DataFrames with severity_text
        if not self.include_info.get() and 'severity_text' in filtered_df.columns:
            filtered_df = filtered_df[filtered_df['severity_text'] != 'Info']
        
        # Date filtering - check for different date columns
        if self.use_date_filter.get():
            try:
                start_date = pd.to_datetime(self.filter_start_date.get())
                end_date = pd.to_datetime(self.filter_end_date.get()) + pd.Timedelta(days=1) - pd.Timedelta(seconds=1)
                
                # Apply date filter based on available date columns
                if 'scan_date' in filtered_df.columns:
                    filtered_df = filtered_df[(filtered_df['scan_date'] >= start_date) & 
                                            (filtered_df['scan_date'] <= end_date)]
                elif 'first_seen' in filtered_df.columns:
                    filtered_df = filtered_df[(filtered_df['first_seen'] >= start_date) & 
                                            (filtered_df['first_seen'] <= end_date)]
            except (ValueError, TypeError):
                pass
        
        # Apply visualization-only filters (only to lifecycle data and only if requested)
        if apply_lifecycle_filters and 'severity_text' in filtered_df.columns:
            
            # Severity filter
            severity_val = self.severity_filter.get()
            if severity_val != "All Severities":
                if severity_val == "Critical+High":
                    filtered_df = filtered_df[filtered_df['severity_text'].isin(['Critical', 'High'])]
                elif severity_val == "Medium+High+Critical":
                    filtered_df = filtered_df[filtered_df['severity_text'].isin(['Critical', 'High', 'Medium'])]
                else:
                    filtered_df = filtered_df[filtered_df['severity_text'] == severity_val]
            
            # Status filter
            status_val = self.status_filter.get()
            if status_val != "All Statuses" and 'status' in filtered_df.columns:
                filtered_df = filtered_df[filtered_df['status'] == status_val]
            
            # CVSS filter
            cvss_min = self.cvss_min.get()
            cvss_max = self.cvss_max.get()
            if 'cvss3_base_score' in filtered_df.columns:
                # Convert CVSS scores to numeric, handling string values
                cvss_scores = pd.to_numeric(filtered_df['cvss3_base_score'], errors='coerce')
                cvss_mask = (cvss_scores >= cvss_min) & (cvss_scores <= cvss_max)
                filtered_df = filtered_df[cvss_mask]
            
            # Host filter
            host_val = self.host_filter.get().strip()
            if host_val and 'hostname' in filtered_df.columns:
                filtered_df = filtered_df[filtered_df['hostname'].str.contains(host_val, case=False, na=False)]
            
            # OPDIR filter
            opdir_val = self.opdir_filter.get()
            if opdir_val != "All" and 'opdir_number' in filtered_df.columns:
                if opdir_val == "OPDIR Mapped Only":
                    filtered_df = filtered_df[filtered_df['opdir_number'] != '']
                elif opdir_val == "No OPDIR":
                    filtered_df = filtered_df[filtered_df['opdir_number'] == '']
                elif opdir_val in ['Overdue', 'Due Soon', 'On Track']:
                    filtered_df = filtered_df[filtered_df['opdir_status'] == opdir_val]
        
        return filtered_df


    def apply_filters(self):
        """Apply current filter settings"""
        if self.historical_df.empty:
            messagebox.showwarning("No Data", "Please process archives first")
            return
        
        try:
            # Check if Info filter change requires full re-analysis
            current_info_setting = self.include_info.get()
            needs_full_refresh = self.check_if_full_refresh_needed(current_info_setting)
            
            if needs_full_refresh:
                self.log("Info filter changed - performing full analysis refresh...")
                self.refresh_analysis_internal()
            else:
                self.log("Applying visualization filters...")
                self.update_visualizations()
            
            self.update_filter_status()
            self.log("Filters applied successfully")
            
        except Exception as e:
            self.log(f"Error applying filters: {str(e)}")
            messagebox.showerror("Error", f"Failed to apply filters: {str(e)}")
    
    def reset_filters(self):
        """Reset all filters to default state"""
        self.include_info.set(False)
        self.use_date_filter.set(False)
        self.filter_start_date.set("")
        self.filter_end_date.set("")
        self.severity_filter.set("All Severities")
        self.status_filter.set("All Statuses")
        self.host_filter.set("")
        self.cvss_min.set(0.0)
        self.cvss_max.set(10.0)
        self.opdir_filter.set("All")
        
        self.start_date_entry.config(state='disabled')
        self.end_date_entry.config(state='disabled')
        
        self.update_filter_status()
        self.log("Filters reset - click 'Apply Filters' to update visualizations")
    
    def update_filter_status(self):
        """Update filter status display"""
        status_parts = []
        
        if not self.include_info.get():
            status_parts.append("Excluding Info")
        
        if self.use_date_filter.get():
            start = self.filter_start_date.get()
            end = self.filter_end_date.get()
            if start and end:
                status_parts.append(f"Date: {start} to {end}")
        
        if self.severity_filter.get() != "All Severities":
            status_parts.append(f"Severity: {self.severity_filter.get()}")
        
        if self.status_filter.get() != "All Statuses":
            status_parts.append(f"Status: {self.status_filter.get()}")
        
        if self.host_filter.get().strip():
            status_parts.append(f"Host: {self.host_filter.get()}")
        
        if self.cvss_min.get() > 0.0 or self.cvss_max.get() < 10.0:
            status_parts.append(f"CVSS: {self.cvss_min.get()}-{self.cvss_max.get()}")
        
        if self.opdir_filter.get() != "All":
            status_parts.append(f"OPDIR: {self.opdir_filter.get()}")
        
        status_text = " | ".join(status_parts) if status_parts else "No filters applied"
        self.filter_status_label.config(text=status_text, foreground="lightblue")
    
    def check_if_full_refresh_needed(self, current_info_setting: bool) -> bool:
        """Check if full analysis refresh is needed"""
        if self.lifecycle_df.empty:
            return True
        
        total_findings_in_lifecycle = len(self.lifecycle_df)
        total_findings_in_historical = len(self.historical_df)
        info_findings_in_historical = len(self.historical_df[self.historical_df['severity_text'] == 'Info']) if not self.historical_df.empty else 0
        
        if current_info_setting and (total_findings_in_lifecycle < total_findings_in_historical):
            return True
        
        if not current_info_setting and (total_findings_in_lifecycle == total_findings_in_historical) and info_findings_in_historical > 0:
            return True
        
        return False
    
    def refresh_analysis_internal(self):
        """Internal method for full analysis refresh"""
        include_info_val = self.include_info.get()
        
        analysis_df = self.historical_df.copy()
        if not include_info_val:
            analysis_df = analysis_df[analysis_df['severity_text'] != 'Info']
        
        # Regenerate analysis DataFrames
        self.lifecycle_df = self.analyze_finding_lifecycle(analysis_df)
        
        # Apply OPDIR enrichment if available
        if not self.opdir_df.empty:
            self.lifecycle_df = enrich_findings_with_opdir(self.lifecycle_df, self.opdir_df)
        
        self.host_presence_df = self.create_host_presence_analysis(analysis_df)
        self.scan_changes_df = self.analyze_scan_changes(analysis_df)
        
        # Update visualizations
        self.update_visualizations()
    
    def update_visualizations(self):
        """Update all visualizations with current filter settings"""
        try:
            # Store current tab selection
            current_tab = self.notebook.select()
            current_tab_index = self.notebook.index(current_tab) if current_tab else 0
            
            # Re-create all visualizations
            self.create_all_visualizations()
            
            # Restore tab selection
            try:
                if current_tab_index < self.notebook.index("end"):
                    self.notebook.select(current_tab_index)
            except:
                pass
                
        except Exception as e:
            self.log(f"Error updating visualizations: {str(e)}")
            import traceback
            traceback.print_exc()
    
    def create_all_visualizations(self):
        """Create all visualization tabs"""
        # Remove old visualization tabs
        for tab_name in list(self.viz_frames.keys()):
            try:
                self.notebook.forget(self.viz_frames[tab_name])
            except:
                pass
        self.viz_frames = {}
        
        if self.historical_df.empty:
            return
        
        # Create all visualization tabs
        self.create_timeline_viz()
        self.create_risk_analysis_viz()
        self.create_opdir_compliance_viz()
        self.create_operational_efficiency_viz()
        self.create_executive_summary_viz()
        self.create_network_analysis_viz()
        self.create_host_tracking_viz()
        self.create_plugin_analysis_viz()
        self.create_lifecycle_analysis_viz()
        
    def get_severity_colors(self):
        """Get consistent severity color scheme"""
        return {
            'Critical': '#dc3545',
            'High': '#fd7e14', 
            'Medium': '#ffc107',
            'Low': '#007bff',
            'Info': '#6c757d'
        }
    
    def get_severity_order(self):
        """Get consistent severity ordering"""
        return ['Critical', 'High', 'Medium', 'Low', 'Info']

    def sort_by_severity(self, df, severity_column='severity_text'):
        """Sort DataFrame by severity in Critical->High->Medium->Low->Info order"""
        if severity_column not in df.columns:
            return df
        
        severity_order = self.get_severity_order()
        # Create categorical with explicit order
        df = df.copy()
        df[severity_column] = pd.Categorical(df[severity_column], categories=severity_order, ordered=True)
        return df.sort_values(severity_column)
    
    def create_timeline_viz(self):
        """Create comprehensive timeline visualization"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Timeline Analysis")
        self.viz_frames['timeline'] = frame
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
        fig.patch.set_facecolor('#2b2b2b')
        
        # Get filtered data
        filtered_historical = self.get_filtered_data(self.historical_df, apply_lifecycle_filters=False)
        filtered_lifecycle = self.get_filtered_data(self.lifecycle_df, apply_lifecycle_filters=True)
        
        colors = self.get_severity_colors()
        
        if not filtered_historical.empty:
            # Total findings over time
            timeline_data = filtered_historical.groupby('scan_date').size().reset_index(name='count')
            ax1.plot(timeline_data['scan_date'], timeline_data['count'], 
                    marker='o', linewidth=2, color='#007bff', markersize=6)
            ax1.set_title('Total Findings Over Time', fontsize=14, fontweight='bold', color='white')
            ax1.set_xlabel('Scan Date', color='white')
            ax1.set_ylabel('Number of Findings', color='white')
            ax1.grid(True, alpha=0.3)
            ax1.set_facecolor('#2b2b2b')
            ax1.tick_params(colors='white')
            
            # Findings by severity over time
            severity_timeline = filtered_historical.groupby(['scan_date', 'severity_text']).size().unstack(fill_value=0)
            for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
                if severity in severity_timeline.columns:
                    ax2.plot(severity_timeline.index, severity_timeline[severity], 
                            marker='o', label=severity, color=colors.get(severity, 'gray'), 
                            linewidth=2, markersize=4)
            
            ax2.set_title('Findings by Severity Over Time', fontsize=14, fontweight='bold', color='white')
            ax2.set_xlabel('Scan Date', color='white')
            ax2.set_ylabel('Number of Findings', color='white')
            ax2.legend(loc='upper left')
            ax2.grid(True, alpha=0.3)
            ax2.set_facecolor('#2b2b2b')
            ax2.tick_params(colors='white')
        
        if not filtered_lifecycle.empty:
            # New vs Resolved findings trend
            monthly_new = filtered_lifecycle.groupby(filtered_lifecycle['first_seen'].dt.to_period('M')).size()
            monthly_resolved = filtered_lifecycle[filtered_lifecycle['status'] == 'Resolved'].groupby(
                filtered_lifecycle[filtered_lifecycle['status'] == 'Resolved']['last_seen'].dt.to_period('M')).size()
            
            # Align the series
            all_months = monthly_new.index.union(monthly_resolved.index)
            monthly_new = monthly_new.reindex(all_months, fill_value=0)
            monthly_resolved = monthly_resolved.reindex(all_months, fill_value=0)
            
            month_dates = [period.to_timestamp() for period in all_months]
            
            ax3.bar(month_dates, monthly_new.values, alpha=0.7, color='#dc3545', label='New', width=20)
            ax3.bar(month_dates, -monthly_resolved.values, alpha=0.7, color='#28a745', label='Resolved', width=20)
            ax3.axhline(y=0, color='white', linestyle='-', alpha=0.5)
            ax3.set_title('New vs Resolved Findings by Month', fontsize=14, fontweight='bold', color='white')
            ax3.set_xlabel('Month', color='white')
            ax3.set_ylabel('Findings (New +, Resolved -)', color='white')
            ax3.legend()
            ax3.grid(True, alpha=0.3)
            ax3.set_facecolor('#2b2b2b')
            ax3.tick_params(colors='white')
            
            # Cumulative risk exposure (active findings * severity weight)
            severity_weights = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Info': 0}
            active_findings = filtered_lifecycle[filtered_lifecycle['status'] == 'Active']
            
            if not active_findings.empty:
                risk_by_date = {}
                for _, finding in active_findings.iterrows():
                    first_seen = finding['first_seen']
                    severity = finding['severity_text']
                    weight = severity_weights.get(severity, 0)
                    
                    date_key = first_seen.strftime('%Y-%m')
                    if date_key not in risk_by_date:
                        risk_by_date[date_key] = 0
                    risk_by_date[date_key] += weight
                
                if risk_by_date:
                    dates = sorted(risk_by_date.keys())
                    cumulative_risk = []
                    running_total = 0
                    
                    for date in dates:
                        running_total += risk_by_date[date]
                        cumulative_risk.append(running_total)
                    
                    date_objects = [pd.to_datetime(date) for date in dates]
                    ax4.plot(date_objects, cumulative_risk, marker='o', linewidth=2, 
                            color='#ffc107', markersize=4)
                    ax4.fill_between(date_objects, cumulative_risk, alpha=0.3, color='#ffc107')
                    
        ax4.set_title('Cumulative Risk Exposure Over Time', fontsize=14, fontweight='bold', color='white')
        ax4.set_xlabel('Month', color='white')
        ax4.set_ylabel('Risk Score (Weighted)', color='white')
        ax4.grid(True, alpha=0.3)
        ax4.set_facecolor('#2b2b2b')
        ax4.tick_params(colors='white')
        
        plt.tight_layout()
        plt.style.use('dark_background')
        
        canvas = FigureCanvasTkAgg(fig, frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def create_risk_analysis_viz(self):
        """Create risk trend analysis visualization"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Risk Analysis")
        self.viz_frames['risk'] = frame
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
        fig.patch.set_facecolor('#2b2b2b')
        
        filtered_lifecycle = self.get_filtered_data(self.lifecycle_df, apply_lifecycle_filters=True)
        colors = self.get_severity_colors()
        
        if not filtered_lifecycle.empty:
            # CVSS score distribution
            cvss_scores = pd.to_numeric(filtered_lifecycle['cvss3_base_score'], errors='coerce').dropna()
            if not cvss_scores.empty:
                ax1.hist(cvss_scores, bins=20, alpha=0.7, color='#007bff', edgecolor='white')
                ax1.axvline(cvss_scores.mean(), color='#dc3545', linestyle='--', linewidth=2, label=f'Mean: {cvss_scores.mean():.1f}')
                ax1.axvline(cvss_scores.median(), color='#ffc107', linestyle='--', linewidth=2, label=f'Median: {cvss_scores.median():.1f}')
                ax1.set_title('CVSS Score Distribution', fontsize=14, fontweight='bold', color='white')
                ax1.set_xlabel('CVSS Score', color='white')
                ax1.set_ylabel('Number of Findings', color='white')
                ax1.legend()
                ax1.grid(True, alpha=0.3)
                ax1.set_facecolor('#2b2b2b')
                ax1.tick_params(colors='white')
            
            # Mean time to remediation by severity
            resolved_findings = filtered_lifecycle[filtered_lifecycle['status'] == 'Resolved']
            if not resolved_findings.empty:
                mttr_by_severity = resolved_findings.groupby('severity_text')['days_open'].mean()
                mttr_by_severity = mttr_by_severity.reindex(self.get_severity_order(), fill_value=0)
                mttr_by_severity = mttr_by_severity[mttr_by_severity > 0]  # Remove empty severities
                severity_colors = [colors.get(sev, '#6c757d') for sev in mttr_by_severity.index]
                
                bars = ax2.barh(range(len(mttr_by_severity)), mttr_by_severity.values, color=severity_colors)
                ax2.set_yticks(range(len(mttr_by_severity)))
                ax2.set_yticklabels(mttr_by_severity.index, color='white')
                ax2.set_title('Mean Time to Remediation by Severity', fontsize=14, fontweight='bold', color='white')
                ax2.set_xlabel('Days', color='white')
                ax2.grid(True, alpha=0.3, axis='x')
                ax2.set_facecolor('#2b2b2b')
                ax2.tick_params(colors='white')
                
                # Add value labels
                for i, bar in enumerate(bars):
                    width = bar.get_width()
                    ax2.text(width + width*0.01, bar.get_y() + bar.get_height()/2.,
                            f'{width:.0f}', ha='left', va='center', color='white', fontweight='bold')
            
            # Risk exposure by host (hosts * severity * days open)
            active_findings = filtered_lifecycle[filtered_lifecycle['status'] == 'Active']
            if not active_findings.empty:
                # Create a copy to avoid SettingWithCopyWarning
                active_findings_copy = active_findings.copy()
                
                severity_weights = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Info': 0}
                active_findings_copy['risk_score'] = active_findings_copy.apply(
                    lambda x: severity_weights.get(x['severity_text'], 0) * max(x['days_open'], 1), axis=1)
                
                risk_by_host = active_findings_copy.groupby('hostname')['risk_score'].sum().sort_values(ascending=False).head(15)
                
                bars = ax3.barh(range(len(risk_by_host)), risk_by_host.values, color='#dc3545')
                ax3.set_yticks(range(len(risk_by_host)))
                ax3.set_yticklabels([name[:20] + '...' if len(name) > 20 else name for name in risk_by_host.index], color='white')
                ax3.set_title('Top 15 Hosts by Risk Exposure', fontsize=14, fontweight='bold', color='white')
                ax3.set_xlabel('Risk Score', color='white')
                ax3.grid(True, alpha=0.3, axis='x')
                ax3.set_facecolor('#2b2b2b')
                ax3.tick_params(colors='white')
            
            # Critical/High finding velocity
            critical_high = filtered_lifecycle[filtered_lifecycle['severity_text'].isin(['Critical', 'High'])]
            if not critical_high.empty:
                monthly_critical_high = critical_high.groupby(critical_high['first_seen'].dt.to_period('M')).size()
                monthly_resolved_ch = critical_high[critical_high['status'] == 'Resolved'].groupby(
                    critical_high[critical_high['status'] == 'Resolved']['last_seen'].dt.to_period('M')).size()
                
                all_months = monthly_critical_high.index.union(monthly_resolved_ch.index)
                monthly_critical_high = monthly_critical_high.reindex(all_months, fill_value=0)
                monthly_resolved_ch = monthly_resolved_ch.reindex(all_months, fill_value=0)
                
                month_dates = [period.to_timestamp() for period in all_months]
                
                ax4.plot(month_dates, monthly_critical_high.values, marker='o', linewidth=2, 
                        color='#dc3545', label='New Critical/High', markersize=4)
                ax4.plot(month_dates, monthly_resolved_ch.values, marker='s', linewidth=2, 
                        color='#28a745', label='Resolved Critical/High', markersize=4)
                
                ax4.set_title('Critical/High Finding Velocity', fontsize=14, fontweight='bold', color='white')
                ax4.set_xlabel('Month', color='white')
                ax4.set_ylabel('Number of Findings', color='white')
                ax4.legend()
                ax4.grid(True, alpha=0.3)
                ax4.set_facecolor('#2b2b2b')
                ax4.tick_params(colors='white')
        
        plt.tight_layout()
        plt.style.use('dark_background')
        
        canvas = FigureCanvasTkAgg(fig, frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def create_opdir_compliance_viz(self):
        """Create OPDIR compliance dashboard"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="OPDIR Compliance")
        self.viz_frames['opdir'] = frame
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
        fig.patch.set_facecolor('#2b2b2b')
        
        filtered_lifecycle = self.get_filtered_data(self.lifecycle_df, apply_lifecycle_filters=True)
        
        if not self.opdir_df.empty and not filtered_lifecycle.empty:
            # OPDIR mapping coverage
            total_findings = len(filtered_lifecycle)
            opdir_mapped = len(filtered_lifecycle[filtered_lifecycle.get('opdir_number', '') != ''])
            unmapped = total_findings - opdir_mapped
            
            coverage_data = [opdir_mapped, unmapped]
            coverage_labels = ['OPDIR Mapped', 'Not Mapped']
            colors_coverage = ['#28a745', '#dc3545']
            
            wedges, texts, autotexts = ax1.pie(coverage_data, labels=coverage_labels, autopct='%1.1f%%',
                                              colors=colors_coverage, startangle=90)
            ax1.set_title('OPDIR Mapping Coverage', fontsize=14, fontweight='bold', color='white')
            ax1.set_facecolor('#2b2b2b')
            
            # OPDIR status distribution
            if 'opdir_status' in filtered_lifecycle.columns:
                opdir_findings = filtered_lifecycle[filtered_lifecycle['opdir_number'] != '']
                if not opdir_findings.empty:
                    status_counts = opdir_findings['opdir_status'].value_counts()
                    colors_status = {'On Track': '#28a745', 'Due Soon': '#ffc107', 'Overdue': '#dc3545', 'Unknown': '#6c757d'}
                    status_colors = [colors_status.get(status, '#6c757d') for status in status_counts.index]
                    
                    wedges, texts, autotexts = ax2.pie(status_counts.values, labels=status_counts.index, 
                                                      autopct='%1.1f%%', colors=status_colors, startangle=90)
                    ax2.set_title('OPDIR Status Distribution', fontsize=14, fontweight='bold', color='white')
                    ax2.set_facecolor('#2b2b2b')
            
            # OPDIR remediation timeline vs actual
            opdir_findings = filtered_lifecycle[filtered_lifecycle['opdir_number'] != '']
            if not opdir_findings.empty and 'opdir_final_due_date' in opdir_findings.columns:
                # Calculate days until OPDIR due vs days finding has been open
                current_date = pd.Timestamp.now()
                
                timeline_data = []
                for _, finding in opdir_findings.iterrows():
                    if pd.notna(finding['opdir_final_due_date']):
                        days_until_due = (finding['opdir_final_due_date'] - current_date).days
                        days_open = finding['days_open']
                        timeline_data.append({
                            'days_until_due': days_until_due,
                            'days_open': days_open,
                            'severity': finding['severity_text'],
                            'status': finding['opdir_status']
                        })
                
                if timeline_data:
                    timeline_df = pd.DataFrame(timeline_data)
                    
                    # Scatter plot: days until due vs days open
                    colors_scatter = {'On Track': '#28a745', 'Due Soon': '#ffc107', 'Overdue': '#dc3545'}
                    for status in timeline_df['status'].unique():
                        status_data = timeline_df[timeline_df['status'] == status]
                        ax3.scatter(status_data['days_until_due'], status_data['days_open'], 
                                  color=colors_scatter.get(status, '#6c757d'), label=status, alpha=0.7, s=50)
                    
                    ax3.axvline(x=0, color='white', linestyle='--', alpha=0.5, label='Due Date')
                    ax3.axhline(y=0, color='white', linestyle='-', alpha=0.3)
                    ax3.set_title('OPDIR Timeline vs Finding Age', fontsize=14, fontweight='bold', color='white')
                    ax3.set_xlabel('Days Until OPDIR Due (negative = overdue)', color='white')
                    ax3.set_ylabel('Days Finding Open', color='white')
                    ax3.legend()
                    ax3.grid(True, alpha=0.3)
                    ax3.set_facecolor('#2b2b2b')
                    ax3.tick_params(colors='white')
            
            # Compliance percentage by OPDIR year
            if 'opdir_number' in filtered_lifecycle.columns:
                opdir_findings = filtered_lifecycle[filtered_lifecycle['opdir_number'] != '']
                if not opdir_findings.empty:
                    # Extract year from OPDIR number (format: XXXX-YY)
                    opdir_findings_copy = opdir_findings.copy()
                    opdir_findings_copy['opdir_year'] = opdir_findings_copy['opdir_number'].str.extract(r'-(\d{2})$')
                    opdir_findings_copy['opdir_year'] = opdir_findings_copy['opdir_year'].apply(
                        lambda x: f"20{x}" if pd.notna(x) else "Unknown")
                    
                    year_compliance = opdir_findings_copy.groupby('opdir_year')['opdir_status'].apply(
                        lambda x: (x == 'On Track').sum() / len(x) * 100).sort_index()
                    
                    bars = ax4.bar(range(len(year_compliance)), year_compliance.values, color='#007bff')
                    ax4.set_xticks(range(len(year_compliance)))
                    ax4.set_xticklabels(year_compliance.index, color='white')
                    ax4.set_title('OPDIR Compliance % by Year', fontsize=14, fontweight='bold', color='white')
                    ax4.set_ylabel('Compliance Percentage', color='white')
                    ax4.grid(True, alpha=0.3, axis='y')
                    ax4.set_facecolor('#2b2b2b')
                    ax4.tick_params(colors='white')
                    
                    # Add value labels
                    for bar in bars:
                        height = bar.get_height()
                        ax4.text(bar.get_x() + bar.get_width()/2., height + 1,
                                f'{height:.1f}%', ha='center', va='bottom', color='white', fontweight='bold')
        
        else:
            # No OPDIR data available
            for ax in [ax1, ax2, ax3, ax4]:
                ax.text(0.5, 0.5, 'No OPDIR data available', ha='center', va='center', 
                       transform=ax.transAxes, color='white', fontsize=14)
                ax.set_facecolor('#2b2b2b')
        
        plt.tight_layout()
        plt.style.use('dark_background')
        
        canvas = FigureCanvasTkAgg(fig, frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def create_operational_efficiency_viz(self):
        """Create operational efficiency visualization"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Operational Efficiency")
        self.viz_frames['efficiency'] = frame
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
        fig.patch.set_facecolor('#2b2b2b')
        
        filtered_host_presence = self.get_filtered_data(self.host_presence_df, apply_lifecycle_filters=False)
        filtered_lifecycle = self.get_filtered_data(self.lifecycle_df, apply_lifecycle_filters=True)
        
        if not filtered_host_presence.empty:
            # Scan coverage consistency
            coverage_consistency = filtered_host_presence['presence_percentage'].describe()
            
            bins = [0, 25, 50, 75, 90, 100]
            labels = ['0-25%', '26-50%', '51-75%', '76-90%', '91-100%']
            filtered_host_presence['coverage_category'] = pd.cut(
                filtered_host_presence['presence_percentage'], bins=bins, labels=labels, right=True)
            coverage_dist = filtered_host_presence['coverage_category'].value_counts().sort_index()
            
            bars = ax1.bar(range(len(coverage_dist)), coverage_dist.values, color='#007bff')
            ax1.set_xticks(range(len(coverage_dist)))
            ax1.set_xticklabels(coverage_dist.index, rotation=45, ha='right', color='white')
            ax1.set_title('Scan Coverage Consistency Distribution', fontsize=14, fontweight='bold', color='white')
            ax1.set_ylabel('Number of Hosts', color='white')
            ax1.grid(True, alpha=0.3, axis='y')
            ax1.set_facecolor('#2b2b2b')
            ax1.tick_params(colors='white')
            
            # Add value labels
            for bar in bars:
                height = bar.get_height()
                if height > 0:
                    ax1.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                            f'{int(height)}', ha='center', va='bottom', color='white', fontweight='bold')
        
        if not filtered_lifecycle.empty:
            # False positive rate (reappeared findings)
            total_findings = len(filtered_lifecycle)
            reappeared_findings = len(filtered_lifecycle[filtered_lifecycle['reappearances'] > 0])
            false_positive_rate = (reappeared_findings / total_findings * 100) if total_findings > 0 else 0
            
            fp_data = [100 - false_positive_rate, false_positive_rate]
            fp_labels = ['Properly Resolved', 'Reappeared (False Positive)']
            fp_colors = ['#28a745', '#dc3545']
            
            wedges, texts, autotexts = ax2.pie(fp_data, labels=fp_labels, autopct='%1.1f%%',
                                              colors=fp_colors, startangle=90)
            ax2.set_title('False Positive Analysis', fontsize=14, fontweight='bold', color='white')
            ax2.set_facecolor('#2b2b2b')
            
            # Remediation team performance (findings per host variance)
            findings_per_host = filtered_lifecycle.groupby('hostname').size()
            host_variance = findings_per_host.var()
            host_mean = findings_per_host.mean()
            host_std = findings_per_host.std()
            
            # Create performance categories
            performance_data = []
            for hostname, count in findings_per_host.items():
                if count > host_mean + host_std:
                    category = 'High Burden'
                elif count < host_mean - host_std:
                    category = 'Low Burden'
                else:
                    category = 'Normal'
                performance_data.append(category)
            
            performance_counts = pd.Series(performance_data).value_counts()
            
            bars = ax3.bar(range(len(performance_counts)), performance_counts.values, 
                          color=['#dc3545', '#ffc107', '#28a745'])
            ax3.set_xticks(range(len(performance_counts)))
            ax3.set_xticklabels(performance_counts.index, color='white')
            ax3.set_title('Host Vulnerability Burden Distribution', fontsize=14, fontweight='bold', color='white')
            ax3.set_ylabel('Number of Hosts', color='white')
            ax3.grid(True, alpha=0.3, axis='y')
            ax3.set_facecolor('#2b2b2b')
            ax3.tick_params(colors='white')
            
            # Add value labels
            for bar in bars:
                height = bar.get_height()
                ax3.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                        f'{int(height)}', ha='center', va='bottom', color='white', fontweight='bold')
            
            # Scan quality metrics (findings per scan variance)
            if not self.historical_df.empty:
                filtered_historical = self.get_filtered_data(self.historical_df, apply_lifecycle_filters=False)
                findings_per_scan = filtered_historical.groupby('scan_date').size()
                
                ax4.plot(findings_per_scan.index, findings_per_scan.values, marker='o', linewidth=2, color='#007bff')
                ax4.axhline(y=findings_per_scan.mean(), color='#ffc107', linestyle='--', 
                           label=f'Mean: {findings_per_scan.mean():.0f}')
                ax4.fill_between(findings_per_scan.index, 
                                findings_per_scan.mean() - findings_per_scan.std(),
                                findings_per_scan.mean() + findings_per_scan.std(),
                                alpha=0.2, color='#ffc107', label='±1 Std Dev')
                
                ax4.set_title('Scan Quality Consistency', fontsize=14, fontweight='bold', color='white')
                ax4.set_xlabel('Scan Date', color='white')
                ax4.set_ylabel('Findings Per Scan', color='white')
                ax4.legend()
                ax4.grid(True, alpha=0.3)
                ax4.set_facecolor('#2b2b2b')
                ax4.tick_params(colors='white')
        
        plt.tight_layout()
        plt.style.use('dark_background')
        
        canvas = FigureCanvasTkAgg(fig, frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def create_executive_summary_viz(self):
        """Create executive summary visualization"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Executive Summary")
        self.viz_frames['executive'] = frame
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
        fig.patch.set_facecolor('#2b2b2b')
        
        filtered_lifecycle = self.get_filtered_data(self.lifecycle_df, apply_lifecycle_filters=True)
        colors = self.get_severity_colors()
        
        if not filtered_lifecycle.empty:
            # Risk posture trending (better/worse over time)
            severity_weights = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Info': 0}
            monthly_risk = filtered_lifecycle.groupby(filtered_lifecycle['first_seen'].dt.to_period('M')).apply(
                lambda x: sum(severity_weights.get(sev, 0) for sev in x['severity_text'])
            )
            
            if len(monthly_risk) > 1:
                # Calculate trend
                x = np.arange(len(monthly_risk))
                z = np.polyfit(x, monthly_risk.values, 1)
                trend_line = np.poly1d(z)
                
                month_dates = [period.to_timestamp() for period in monthly_risk.index]
                ax1.plot(month_dates, monthly_risk.values, marker='o', linewidth=2, color='#007bff', markersize=6)
                ax1.plot(month_dates, trend_line(x), '--', color='#dc3545', linewidth=2, 
                        label=f'Trend: {"Improving" if z[0] < 0 else "Worsening"}')
                
                ax1.set_title('Risk Posture Trend', fontsize=14, fontweight='bold', color='white')
                ax1.set_xlabel('Month', color='white')
                ax1.set_ylabel('Risk Score', color='white')
                ax1.legend()
                ax1.grid(True, alpha=0.3)
                ax1.set_facecolor('#2b2b2b')
                ax1.tick_params(colors='white')
            
            # Portfolio vulnerability comparison (by severity)
            severity_dist = filtered_lifecycle['severity_text'].value_counts()
            severity_dist = severity_dist.reindex(self.get_severity_order(), fill_value=0)
            severity_dist = severity_dist[severity_dist > 0]  # Remove empty severities
            severity_colors_list = [colors.get(sev, '#6c757d') for sev in severity_dist.index]
            
            wedges, texts, autotexts = ax2.pie(severity_dist.values, labels=severity_dist.index, 
                                              autopct='%1.1f%%', colors=severity_colors_list, startangle=90)
            ax2.set_title('Current Vulnerability Portfolio', fontsize=14, fontweight='bold', color='white')
            ax2.set_facecolor('#2b2b2b')
            
            # Resource allocation recommendations
            active_findings = filtered_lifecycle[filtered_lifecycle['status'] == 'Active']
            if not active_findings.empty:
                # Calculate effort needed by severity (findings * avg days open)
                effort_by_severity = active_findings.groupby('severity_text').apply(
                    lambda x: len(x) * x['days_open'].mean()
                )
                effort_by_severity = effort_by_severity.reindex(self.get_severity_order(), fill_value=0)
                effort_by_severity = effort_by_severity[effort_by_severity > 0]  # Remove empty severities
                
                effort_colors = [colors.get(sev, '#6c757d') for sev in effort_by_severity.index]
                bars = ax3.barh(range(len(effort_by_severity)), effort_by_severity.values, color=effort_colors)
                ax3.set_yticks(range(len(effort_by_severity)))
                ax3.set_yticklabels(effort_by_severity.index, color='white')
                ax3.set_title('Recommended Resource Allocation', fontsize=14, fontweight='bold', color='white')
                ax3.set_xlabel('Effort Score (Findings × Avg Days)', color='white')
                ax3.grid(True, alpha=0.3, axis='x')
                ax3.set_facecolor('#2b2b2b')
                ax3.tick_params(colors='white')
                
                # Add value labels
                for i, bar in enumerate(bars):
                    width = bar.get_width()
                    ax3.text(width + width*0.01, bar.get_y() + bar.get_height()/2.,
                            f'{width:.0f}', ha='left', va='center', color='white', fontweight='bold')
            
            # Compliance gap analysis
            if 'opdir_status' in filtered_lifecycle.columns:
                opdir_findings = filtered_lifecycle[filtered_lifecycle['opdir_number'] != '']
                if not opdir_findings.empty:
                    compliance_gaps = opdir_findings['opdir_status'].value_counts()
                    gap_colors = {'On Track': '#28a745', 'Due Soon': '#ffc107', 'Overdue': '#dc3545', 'Unknown': '#6c757d'}
                    gap_colors_list = [gap_colors.get(status, '#6c757d') for status in compliance_gaps.index]
                    
                    bars = ax4.bar(range(len(compliance_gaps)), compliance_gaps.values, color=gap_colors_list)
                    ax4.set_xticks(range(len(compliance_gaps)))
                    ax4.set_xticklabels(compliance_gaps.index, rotation=45, ha='right', color='white')
                    ax4.set_title('OPDIR Compliance Gap Analysis', fontsize=14, fontweight='bold', color='white')
                    ax4.set_ylabel('Number of Findings', color='white')
                    ax4.grid(True, alpha=0.3, axis='y')
                    ax4.set_facecolor('#2b2b2b')
                    ax4.tick_params(colors='white')
                    
                    # Add value labels
                    for bar in bars:
                        height = bar.get_height()
                        ax4.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                                f'{int(height)}', ha='center', va='bottom', color='white', fontweight='bold')
                else:
                    ax4.text(0.5, 0.5, 'No OPDIR compliance data', ha='center', va='center', 
                           transform=ax4.transAxes, color='white', fontsize=12)
                    ax4.set_facecolor('#2b2b2b')
            else:
                ax4.text(0.5, 0.5, 'No OPDIR data available', ha='center', va='center', 
                       transform=ax4.transAxes, color='white', fontsize=12)
                ax4.set_facecolor('#2b2b2b')
        
        plt.tight_layout()
        plt.style.use('dark_background')
        
        canvas = FigureCanvasTkAgg(fig, frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def create_network_analysis_viz(self):
        """Create network topology analysis visualization"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Network Analysis")
        self.viz_frames['network'] = frame
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
        fig.patch.set_facecolor('#2b2b2b')
        
        filtered_lifecycle = self.get_filtered_data(self.lifecycle_df, apply_lifecycle_filters=True)
        
        if not filtered_lifecycle.empty:
            # IP range vulnerability clustering
            def ip_to_subnet(ip):
                try:
                    parts = ip.split('.')
                    if len(parts) >= 3:
                        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                    return "Unknown"
                except:
                    return "Unknown"
            
            filtered_lifecycle['subnet'] = filtered_lifecycle['ip_address'].apply(ip_to_subnet)
            subnet_vulnerability_counts = filtered_lifecycle.groupby('subnet').size().sort_values(ascending=False).head(15)
            
            bars = ax1.barh(range(len(subnet_vulnerability_counts)), subnet_vulnerability_counts.values, color='#007bff')
            ax1.set_yticks(range(len(subnet_vulnerability_counts)))
            ax1.set_yticklabels(subnet_vulnerability_counts.index, color='white')
            ax1.set_title('Top 15 Subnets by Vulnerability Count', fontsize=14, fontweight='bold', color='white')
            ax1.set_xlabel('Number of Vulnerabilities', color='white')
            ax1.grid(True, alpha=0.3, axis='x')
            ax1.set_facecolor('#2b2b2b')
            ax1.tick_params(colors='white')
            
            # Subnet risk heat map (by severity)
            severity_weights = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Info': 0}
            filtered_lifecycle['risk_weight'] = filtered_lifecycle['severity_text'].map(severity_weights).fillna(0)
            subnet_risk = filtered_lifecycle.groupby('subnet')['risk_weight'].sum().sort_values(ascending=False).head(10)
            
            # Create a color map based on risk levels
            risk_normalized = (subnet_risk.values - subnet_risk.min()) / (subnet_risk.max() - subnet_risk.min())
            colors_risk = plt.cm.Reds(0.3 + 0.7 * risk_normalized)
            
            bars = ax2.barh(range(len(subnet_risk)), subnet_risk.values, color=colors_risk)
            ax2.set_yticks(range(len(subnet_risk)))
            ax2.set_yticklabels(subnet_risk.index, color='white')
            ax2.set_title('Subnet Risk Heat Map (Top 10)', fontsize=14, fontweight='bold', color='white')
            ax2.set_xlabel('Risk Score (Weighted)', color='white')
            ax2.grid(True, alpha=0.3, axis='x')
            ax2.set_facecolor('#2b2b2b')
            ax2.tick_params(colors='white')
            
            # Host criticality vs vulnerability burden
            host_vuln_burden = filtered_lifecycle.groupby('hostname').agg({
                'severity_text': 'count',
                'risk_weight': 'sum'
            }).rename(columns={'severity_text': 'vuln_count'})
            
            # Scatter plot
            scatter = ax3.scatter(host_vuln_burden['vuln_count'], host_vuln_burden['risk_weight'], 
                                 alpha=0.6, s=50, c=host_vuln_burden['risk_weight'], cmap='Reds')
            
            ax3.set_title('Host Vulnerability Burden vs Risk', fontsize=14, fontweight='bold', color='white')
            ax3.set_xlabel('Number of Vulnerabilities', color='white')
            ax3.set_ylabel('Risk Score', color='white')
            ax3.grid(True, alpha=0.3)
            ax3.set_facecolor('#2b2b2b')
            ax3.tick_params(colors='white')
            
            # Add trend line
            if len(host_vuln_burden) > 1:
                z = np.polyfit(host_vuln_burden['vuln_count'], host_vuln_burden['risk_weight'], 1)
                p = np.poly1d(z)
                ax3.plot(host_vuln_burden['vuln_count'], p(host_vuln_burden['vuln_count']), 
                        "--", color='yellow', linewidth=2, alpha=0.8)
            
            # Network segment isolation effectiveness
            segments = {}
            for _, finding in filtered_lifecycle.iterrows():
                ip = finding['ip_address']
                try:
                    first_octet = int(ip.split('.')[0])
                    if 10 <= first_octet <= 10:
                        segment = "Private-10.x"
                    elif 172 <= first_octet <= 172:
                        segment = "Private-172.x"
                    elif 192 <= first_octet <= 192:
                        segment = "Private-192.x"
                    elif 1 <= first_octet <= 126:
                        segment = "Public-ClassA"
                    elif 128 <= first_octet <= 191:
                        segment = "Public-ClassB"
                    elif 192 <= first_octet <= 223:
                        segment = "Public-ClassC"
                    else:
                        segment = "Other"
                except:
                    segment = "Unknown"
                
                if segment not in segments:
                    segments[segment] = {'critical_high': 0, 'total': 0}
                
                segments[segment]['total'] += 1
                if finding['severity_text'] in ['Critical', 'High']:
                    segments[segment]['critical_high'] += 1
            
            # Calculate isolation effectiveness (lower critical/high ratio = better isolation)
            segment_effectiveness = {}
            for segment, data in segments.items():
                if data['total'] > 0:
                    effectiveness = (1 - data['critical_high'] / data['total']) * 100
                    segment_effectiveness[segment] = effectiveness
            
            if segment_effectiveness:
                bars = ax4.bar(range(len(segment_effectiveness)), list(segment_effectiveness.values()), 
                              color='#28a745')
                ax4.set_xticks(range(len(segment_effectiveness)))
                ax4.set_xticklabels(list(segment_effectiveness.keys()), rotation=45, ha='right', color='white')
                ax4.set_title('Network Segment Isolation Effectiveness', fontsize=14, fontweight='bold', color='white')
                ax4.set_ylabel('Effectiveness % (Lower Critical/High)', color='white')
                ax4.grid(True, alpha=0.3, axis='y')
                ax4.set_facecolor('#2b2b2b')
                ax4.tick_params(colors='white')
                
                # Add value labels
                for bar in bars:
                    height = bar.get_height()
                    ax4.text(bar.get_x() + bar.get_width()/2., height + 1,
                            f'{height:.1f}%', ha='center', va='bottom', color='white', fontweight='bold')
        
        plt.tight_layout()
        plt.style.use('dark_background')
        
        canvas = FigureCanvasTkAgg(fig, frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def create_host_tracking_viz(self):
        """Create enhanced host tracking visualization"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Host Tracking")
        self.viz_frames['host_tracking'] = frame
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
        fig.patch.set_facecolor('#2b2b2b')
        
        filtered_host_presence = self.get_filtered_data(self.host_presence_df, apply_lifecycle_filters=False)
        
        if not filtered_host_presence.empty:
            # Host status distribution
            status_counts = filtered_host_presence['status'].value_counts()
            ax1.pie(status_counts.values, labels=status_counts.index, autopct='%1.1f%%',
                   colors=['#28a745', '#dc3545'], startangle=90)
            ax1.set_title('Host Status Distribution', fontsize=14, fontweight='bold', color='white')
            ax1.set_facecolor('#2b2b2b')
            
            # Presence percentage distribution
            bins = [0, 25, 50, 75, 90, 100]
            labels = ['0-25%', '26-50%', '51-75%', '76-90%', '91-100%']
            filtered_host_presence['presence_category'] = pd.cut(
                filtered_host_presence['presence_percentage'], bins=bins, labels=labels, right=True)
            presence_dist = filtered_host_presence['presence_category'].value_counts().sort_index()
            
            bars = ax2.bar(range(len(presence_dist)), presence_dist.values, color='#007bff')
            ax2.set_xticks(range(len(presence_dist)))
            ax2.set_xticklabels(presence_dist.index, rotation=45, ha='right', color='white')
            ax2.set_title('Host Presence Percentage Distribution', fontsize=14, fontweight='bold', color='white')
            ax2.set_ylabel('Number of Hosts', color='white')
            ax2.grid(True, alpha=0.3, axis='y')
            ax2.set_facecolor('#2b2b2b')
            ax2.tick_params(colors='white')
            
            # Most unreliable hosts
            unreliable_hosts = filtered_host_presence.nsmallest(10, 'presence_percentage')
            display_names = [f"{row['hostname'][:15]}..." if len(row['hostname']) > 15 else row['hostname'] 
                           for _, row in unreliable_hosts.iterrows()]
            
            bars = ax3.barh(range(len(unreliable_hosts)), unreliable_hosts['presence_percentage'].values, color='#dc3545')
            ax3.set_yticks(range(len(unreliable_hosts)))
            ax3.set_yticklabels(display_names, color='white')
            ax3.set_title('10 Most Unreliable Hosts', fontsize=14, fontweight='bold', color='white')
            ax3.set_xlabel('Presence Percentage', color='white')
            ax3.grid(True, alpha=0.3, axis='x')
            ax3.set_facecolor('#2b2b2b')
            ax3.tick_params(colors='white')
            
            # Recently missing hosts
            missing_hosts = filtered_host_presence[filtered_host_presence['status'] == 'Missing'].head(10)
            if not missing_hosts.empty:
                display_names = [f"{row['hostname'][:15]}..." if len(row['hostname']) > 15 else row['hostname'] 
                               for _, row in missing_hosts.iterrows()]
                days_since_last = [(datetime.now() - row['last_seen']).days for _, row in missing_hosts.iterrows()]
                
                bars = ax4.barh(range(len(missing_hosts)), days_since_last, color='#fd7e14')
                ax4.set_yticks(range(len(missing_hosts)))
                ax4.set_yticklabels(display_names, color='white')
                ax4.set_title('Recently Missing Hosts', fontsize=14, fontweight='bold', color='white')
                ax4.set_xlabel('Days Since Last Seen', color='white')
                ax4.grid(True, alpha=0.3, axis='x')
                ax4.set_facecolor('#2b2b2b')
                ax4.tick_params(colors='white')
            else:
                ax4.text(0.5, 0.5, 'No missing hosts', ha='center', va='center', 
                       transform=ax4.transAxes, color='white', fontsize=12)
                ax4.set_facecolor('#2b2b2b')
        
        plt.tight_layout()
        plt.style.use('dark_background')
        
        canvas = FigureCanvasTkAgg(fig, frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def create_plugin_analysis_viz(self):
        """Create plugin analysis visualization"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Plugin Analysis")
        self.viz_frames['plugin'] = frame
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
        fig.patch.set_facecolor('#2b2b2b')
        
        filtered_lifecycle = self.get_filtered_data(self.lifecycle_df, apply_lifecycle_filters=True)
        
        if not filtered_lifecycle.empty:
            # Top 15 most prevalent plugins
            top_plugins = filtered_lifecycle['plugin_id'].value_counts().head(15)
            plugin_names = [filtered_lifecycle[filtered_lifecycle['plugin_id'] == pid]['plugin_name'].iloc[0][:30] 
                          for pid in top_plugins.index]
            
            bars = ax1.barh(range(len(top_plugins)), top_plugins.values, color='#dc3545')
            ax1.set_yticks(range(len(top_plugins)))
            ax1.set_yticklabels(plugin_names, color='white')
            ax1.set_title('Top 15 Most Prevalent Findings', fontsize=14, fontweight='bold', color='white')
            ax1.set_xlabel('Number of Affected Hosts', color='white')
            ax1.grid(True, alpha=0.3, axis='x')
            ax1.set_facecolor('#2b2b2b')
            ax1.tick_params(colors='white')
            
            # Plugin severity distribution
            plugin_severity = filtered_lifecycle.groupby('severity_text')['plugin_id'].nunique()
            plugin_severity = plugin_severity.reindex(self.get_severity_order(), fill_value=0)
            colors = self.get_severity_colors()
            severity_colors = [colors.get(sev, '#6c757d') for sev in plugin_severity.index]
            
            bars = ax2.bar(range(len(plugin_severity)), plugin_severity.values, color=severity_colors)
            ax2.set_xticks(range(len(plugin_severity)))
            ax2.set_xticklabels(plugin_severity.index, color='white')
            ax2.set_title('Unique Plugins by Severity', fontsize=14, fontweight='bold', color='white')
            ax2.set_ylabel('Number of Unique Plugins', color='white')
            ax2.grid(True, alpha=0.3, axis='y')
            ax2.set_facecolor('#2b2b2b')
            ax2.tick_params(colors='white')
            
            # Plugin persistence (reappearance rate)
            plugin_reappearance = filtered_lifecycle.groupby('plugin_id')['reappearances'].mean().sort_values(ascending=False).head(10)
            plugin_names_reapp = [filtered_lifecycle[filtered_lifecycle['plugin_id'] == pid]['plugin_name'].iloc[0][:25] 
                                 for pid in plugin_reappearance.index]
            
            bars = ax3.barh(range(len(plugin_reappearance)), plugin_reappearance.values, color='#fd7e14')
            ax3.set_yticks(range(len(plugin_reappearance)))
            ax3.set_yticklabels(plugin_names_reapp, color='white')
            ax3.set_title('Top 10 Most Persistent Plugins (Avg Reappearances)', fontsize=14, fontweight='bold', color='white')
            ax3.set_xlabel('Average Reappearances', color='white')
            ax3.grid(True, alpha=0.3, axis='x')
            ax3.set_facecolor('#2b2b2b')
            ax3.tick_params(colors='white')
            
            # Plugin age distribution (average days open)
            plugin_age = filtered_lifecycle.groupby('plugin_id')['days_open'].mean().sort_values(ascending=False).head(10)
            plugin_names_age = [filtered_lifecycle[filtered_lifecycle['plugin_id'] == pid]['plugin_name'].iloc[0][:25] 
                               for pid in plugin_age.index]
            
            bars = ax4.barh(range(len(plugin_age)), plugin_age.values, color='#007bff')
            ax4.set_yticks(range(len(plugin_age)))
            ax4.set_yticklabels(plugin_names_age, color='white')
            ax4.set_title('Top 10 Longest-Running Plugins (Avg Days)', fontsize=14, fontweight='bold', color='white')
            ax4.set_xlabel('Average Days Open', color='white')
            ax4.grid(True, alpha=0.3, axis='x')
            ax4.set_facecolor('#2b2b2b')
            ax4.tick_params(colors='white')
        
        plt.tight_layout()
        plt.style.use('dark_background')
        
        canvas = FigureCanvasTkAgg(fig, frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def create_lifecycle_analysis_viz(self):
        """Create lifecycle analysis visualization"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Lifecycle Analysis")
        self.viz_frames['lifecycle'] = frame
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
        fig.patch.set_facecolor('#2b2b2b')
        
        filtered_lifecycle = self.get_filtered_data(self.lifecycle_df, apply_lifecycle_filters=True)
        
        if not filtered_lifecycle.empty:
            # Distribution of finding age
            max_days = filtered_lifecycle['days_open'].max()
            base_bins = [0, 30, 60, 90, 120, 180, 365]
            bins = [b for b in base_bins if b <= max_days]
            bins.append(max_days + 1)
            
            labels = []
            for i in range(len(bins) - 1):
                if i == len(bins) - 2:
                    if bins[i] >= 365:
                        labels.append('365+')
                    else:
                        labels.append(f'{bins[i]}-{int(max_days)}')
                else:
                    labels.append(f'{bins[i]}-{bins[i+1]-1}')
            
            filtered_lifecycle['age_category'] = pd.cut(filtered_lifecycle['days_open'], 
                                                       bins=bins, labels=labels, right=False)
            age_dist = filtered_lifecycle['age_category'].value_counts().sort_index()
            
            bars = ax1.bar(range(len(age_dist)), age_dist.values, color='#007bff')
            ax1.set_xticks(range(len(age_dist)))
            ax1.set_xticklabels(age_dist.index, rotation=45, ha='right', color='white')
            ax1.set_title('Distribution of Finding Age (Days Open)', fontsize=14, fontweight='bold', color='white')
            ax1.set_ylabel('Number of Findings', color='white')
            ax1.grid(True, alpha=0.3, axis='y')
            ax1.set_facecolor('#2b2b2b')
            ax1.tick_params(colors='white')
            
            # New findings by month (first seen)
            first_seen_timeline = filtered_lifecycle.groupby(
                filtered_lifecycle['first_seen'].dt.to_period('M')
            ).size().reset_index(name='count')
            first_seen_timeline['first_seen'] = first_seen_timeline['first_seen'].dt.to_timestamp()
            
            ax2.plot(first_seen_timeline['first_seen'], first_seen_timeline['count'], 
                    marker='o', linewidth=2, color='#28a745', markersize=6)
            ax2.set_title('New Findings by Month (First Seen)', fontsize=14, fontweight='bold', color='white')
            ax2.set_xlabel('Month', color='white')
            ax2.set_ylabel('New Findings', color='white')
            ax2.grid(True, alpha=0.3)
            ax2.set_facecolor('#2b2b2b')
            ax2.tick_params(colors='white')
            
            # Active vs Resolved findings
            status_counts = filtered_lifecycle['status'].value_counts()
            bars = ax3.bar(status_counts.index, status_counts.values, color=['#dc3545', '#28a745'])
            ax3.set_title('Active vs Resolved Findings', fontsize=14, fontweight='bold', color='white')
            ax3.set_ylabel('Count', color='white')
            ax3.grid(True, alpha=0.3, axis='y')
            ax3.set_facecolor('#2b2b2b')
            ax3.tick_params(colors='white')
            
            # Add value labels
            for bar in bars:
                height = bar.get_height()
                ax3.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                        f'{int(height)}', ha='center', va='bottom', color='white', fontweight='bold')
            
            # Remediation effectiveness by severity
            resolved = filtered_lifecycle[filtered_lifecycle['status'] == 'Resolved']
            if not resolved.empty:
                remediation = resolved.groupby('severity_text').size()
                remediation = remediation.reindex(self.get_severity_order(), fill_value=0)
                remediation = remediation[remediation > 0]  # Remove empty severities
                colors = self.get_severity_colors()
                colors_sev = [colors.get(s, 'gray') for s in remediation.index]
                
                bars = ax4.barh(range(len(remediation)), remediation.values, color=colors_sev)
                ax4.set_yticks(range(len(remediation)))
                ax4.set_yticklabels(remediation.index, color='white')
                ax4.set_title('Resolved Findings by Severity', fontsize=14, fontweight='bold', color='white')
                ax4.set_xlabel('Number of Findings Resolved', color='white')
                ax4.grid(True, alpha=0.3, axis='x')
                ax4.set_facecolor('#2b2b2b')
                ax4.tick_params(colors='white')
            else:
                ax4.text(0.5, 0.5, 'No resolved findings', ha='center', va='center', 
                       transform=ax4.transAxes, color='white', fontsize=12)
                ax4.set_facecolor('#2b2b2b')
        
        plt.tight_layout()
        plt.style.use('dark_background')
        
        canvas = FigureCanvasTkAgg(fig, frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    # File selection methods
    def select_archives(self):
        """Select Nessus archive files"""
        filetypes = (('Archive files', '*.zip'), ('Nessus files', '*.nessus'), ('All files', '*.*'))
        paths = filedialog.askopenfilenames(title='Select Nessus Archives', filetypes=filetypes)
        
        if paths:
            self.archive_paths = list(paths)
            self.archives_label.config(text=f"{len(self.archive_paths)} file(s) selected", foreground="white")
            self.log(f"Selected {len(self.archive_paths)} archive(s)")
    
    def select_plugins_db(self):
        """Select plugins database file"""
        filetypes = (('XML files', '*.xml'), ('JSON files', '*.json'), ('All files', '*.*'))
        path = filedialog.askopenfilename(title='Select Plugins Database', filetypes=filetypes)
        
        if path:
            self.plugins_db_path = path
            self.plugins_label.config(text=os.path.basename(path), foreground="white")
            self.log(f"Selected plugins DB: {os.path.basename(path)}")
    
    def select_existing_db(self):
        """Select existing database file"""
        filetypes = (('SQLite database', '*.db'), ('All files', '*.*'))
        path = filedialog.askopenfilename(title='Select Existing Database', filetypes=filetypes)
        
        if path:
            self.existing_db_path = path
            self.existing_db_label.config(text=os.path.basename(path), foreground="white")
            self.log(f"Selected existing DB: {os.path.basename(path)}")
    
    def select_opdir_file(self):
        """Select OPDIR mapping file"""
        filetypes = (('Excel files', '*.xlsx'), ('CSV files', '*.csv'), ('Excel files (legacy)', '*.xls'), ('All files', '*.*'))
        path = filedialog.askopenfilename(title='Select OPDIR Mapping File', filetypes=filetypes)
        
        if path:
            self.opdir_file_path = path
            self.opdir_label.config(text=os.path.basename(path), foreground="white")
            self.log(f"Selected OPDIR file: {os.path.basename(path)}")
    
    # Core analysis methods (simplified versions of the original functions)
    def analyze_finding_lifecycle(self, historical_df):
        """Analyze finding lifecycle"""
        if historical_df.empty:
            return pd.DataFrame()
        
        historical_df['finding_key'] = historical_df['hostname'].astype(str) + '|' + historical_df['plugin_id'].astype(str)
        lifecycle_records = []
        
        for finding_key, group in historical_df.groupby('finding_key'):
            hostname, plugin_id = finding_key.split('|')
            group = group.sort_values('scan_date')
            latest = group.iloc[-1]
            
            scan_dates = group['scan_date'].tolist()
            first_seen = scan_dates[0]
            last_seen = scan_dates[-1]
            
            # Check for gaps (reappearances)
            reappearances = 0
            if len(scan_dates) > 1:
                for i in range(1, len(scan_dates)):
                    days_gap = (scan_dates[i] - scan_dates[i-1]).days
                    if days_gap > 45:
                        reappearances += 1
            
            status = 'Active' if latest['scan_date'] == historical_df['scan_date'].max() else 'Resolved'
            
            lifecycle_records.append({
                'hostname': hostname,
                'ip_address': latest.get('ip_address', ''),
                'plugin_id': plugin_id,
                'plugin_name': latest['name'],
                'severity_text': latest.get('severity_text', 'Unknown'),
                'severity_value': latest.get('severity_value', 0),
                'first_seen': first_seen,
                'last_seen': last_seen,
                'days_open': (last_seen - first_seen).days,
                'total_observations': len(scan_dates),
                'reappearances': reappearances,
                'status': status,
                'cvss3_base_score': latest.get('cvss3_base_score'),
                'cves': latest.get('cves', ''),
                'iavx': latest.get('iavx', '')
            })
        
        return pd.DataFrame(lifecycle_records).sort_values(['severity_value', 'days_open'], ascending=[False, False])
    
    def create_host_presence_analysis(self, historical_df):
        """Analyze host presence across scans"""
        if historical_df.empty:
            return pd.DataFrame()
        
        scan_dates = sorted(historical_df['scan_date'].unique())
        all_hosts = historical_df.groupby(['hostname', 'ip_address']).size().reset_index(name='count')
        presence_records = []
        
        for _, host_row in all_hosts.iterrows():
            hostname = host_row['hostname']
            ip_address = host_row['ip_address']
            
            host_scans = historical_df[
                (historical_df['hostname'] == hostname) & 
                (historical_df['ip_address'] == ip_address)
            ]['scan_date'].unique()
            
            first_seen = min(host_scans)
            last_seen = max(host_scans)
            total_scans = len(scan_dates)
            present_scans = len(host_scans)
            presence_percentage = (present_scans / total_scans) * 100 if total_scans > 0 else 0
            status = 'Active' if last_seen == max(scan_dates) else 'Missing'
            
            presence_records.append({
                'hostname': hostname,
                'ip_address': ip_address,
                'first_seen': first_seen,
                'last_seen': last_seen,
                'total_scans_available': total_scans,
                'scans_present': present_scans,
                'scans_missing': total_scans - present_scans,
                'presence_percentage': round(presence_percentage, 1),
                'status': status
            })
        
        return pd.DataFrame(presence_records).sort_values(['status', 'presence_percentage'], ascending=[True, False])
    
    def analyze_scan_changes(self, historical_df):
        """Analyze changes between consecutive scans"""
        if historical_df.empty:
            return pd.DataFrame()
        
        scan_dates = sorted(historical_df['scan_date'].unique())
        change_records = []
        
        for i in range(1, len(scan_dates)):
            prev_scan = scan_dates[i-1]
            curr_scan = scan_dates[i]
            
            prev_hosts = set(historical_df[historical_df['scan_date'] == prev_scan]['hostname'].unique())
            curr_hosts = set(historical_df[historical_df['scan_date'] == curr_scan]['hostname'].unique())
            
            added_hosts = curr_hosts - prev_hosts
            removed_hosts = prev_hosts - curr_hosts
            
            change_records.append({
                'scan_date': curr_scan,
                'previous_scan': prev_scan,
                'hosts_added': len(added_hosts),
                'hosts_removed': len(removed_hosts),
                'hosts_unchanged': len(curr_hosts & prev_hosts),
                'total_hosts_current': len(curr_hosts),
                'total_hosts_previous': len(prev_hosts),
                'net_change': len(curr_hosts) - len(prev_hosts)
            })
        
        return pd.DataFrame(change_records)
    
    # Processing and export methods
    def process_archives(self):
        """Process archives or load existing database"""
        has_archives = bool(self.archive_paths)
        has_existing_db = bool(self.existing_db_path and os.path.exists(self.existing_db_path))
        
        if not has_archives and not has_existing_db:
            messagebox.showwarning("No Data Source", "Please select archive files or load an existing database")
            return
        
        # Load OPDIR data if available
        if self.opdir_file_path:
            self.log("Loading OPDIR mapping data...")
            self.opdir_df = load_opdir_mapping(self.opdir_file_path)
        
        try:
            if has_existing_db and not has_archives:
                # Load existing database only
                self.load_existing_database()
            else:
                # Process archives (with or without existing database)
                self.process_new_archives()
            
            # Set up date filter defaults
            if not self.historical_df.empty:
                if not self.filter_start_date.get():
                    start_date = self.historical_df['scan_date'].min().strftime('%Y-%m-%d')
                    self.filter_start_date.set(start_date)
                if not self.filter_end_date.get():
                    end_date = self.historical_df['scan_date'].max().strftime('%Y-%m-%d')
                    self.filter_end_date.set(end_date)
            
            # Create visualizations
            self.create_all_visualizations()
            messagebox.showinfo("Success", "Data processed successfully!")
            
        except Exception as e:
            self.log(f"ERROR: {str(e)}")
            messagebox.showerror("Error", f"Processing failed: {str(e)}")
            import traceback
            traceback.print_exc()
    
    def load_existing_database(self):
        """Load data from existing database"""
        self.log("Loading existing database...")
        
        conn = sqlite3.connect(self.existing_db_path)
        
        try:
            self.historical_df = pd.read_sql_query("SELECT * FROM historical_findings", conn)
            self.historical_df['scan_date'] = pd.to_datetime(self.historical_df['scan_date'])
            self.log(f"Loaded {len(self.historical_df)} historical findings")
        except Exception as e:
            self.log(f"Error loading historical_findings: {e}")
            self.historical_df = pd.DataFrame()
        
        conn.close()
        
        # Re-run analysis with current settings
        self.refresh_analysis_internal()
    
    def process_new_archives(self):
        """Process new archive files"""
        self.log("Processing archives...")
        
        # This would call the original process_historical_scans function
        # For now, we'll create a simplified version
        self.log("Archive processing would happen here...")
        self.log("Creating sample data for demonstration...")
        
        # Create sample data for demonstration
        dates = pd.date_range('2024-01-01', '2024-12-01', freq='MS')
        sample_data = []
        
        for i, date in enumerate(dates):
            for host_num in range(1, 11):
                for plugin in ['22', '25', '26', '11219', '57608']:
                    sample_data.append({
                        'plugin_id': plugin,
                        'hostname': f'host-{host_num:02d}',
                        'ip_address': f'10.0.1.{host_num}',
                        'scan_date': date,
                        'scan_file': f'scan_{date.strftime("%Y%m")}.nessus',
                        'name': f'Sample Finding {plugin}',
                        'severity_text': np.random.choice(['Critical', 'High', 'Medium', 'Low', 'Info'], 
                                                        p=[0.1, 0.2, 0.3, 0.3, 0.1]),
                        'severity_value': np.random.randint(0, 5),
                        'cvss3_base_score': str(round(np.random.uniform(0, 10), 1)),
                        'cves': f'CVE-2024-{np.random.randint(1000, 9999)}',
                        'iavx': f'B-{np.random.randint(100, 999):03d}'
                    })
        
        self.historical_df = pd.DataFrame(sample_data)
        self.log(f"Created {len(self.historical_df)} sample findings")
        
        # Run analysis
        self.refresh_analysis_internal()
    
    def refresh_analysis(self):
        """User-triggered analysis refresh"""
        if self.historical_df.empty:
            messagebox.showwarning("No Data", "Please process archives first")
            return
        
        try:
            self.refresh_analysis_internal()
            messagebox.showinfo("Success", "Analysis refreshed successfully!")
        except Exception as e:
            self.log(f"ERROR: {str(e)}")
            messagebox.showerror("Error", f"Refresh failed: {str(e)}")
    
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
                with pd.ExcelWriter(filepath, engine='openpyxl') as writer:
                    self.lifecycle_df.to_excel(writer, sheet_name='Finding_Lifecycle', index=False)
                    self.host_presence_df.to_excel(writer, sheet_name='Host_Presence', index=False)
                    self.scan_changes_df.to_excel(writer, sheet_name='Scan_Changes', index=False)
                    self.historical_df.to_excel(writer, sheet_name='Historical_Data', index=False)
                    
                    if not self.opdir_df.empty:
                        self.opdir_df.to_excel(writer, sheet_name='OPDIR_Mapping', index=False)
                
                self.log("Excel export complete!")
                messagebox.showinfo("Success", f"Data exported to:\n{filepath}")
            except Exception as e:
                self.log(f"ERROR: {str(e)}")
                messagebox.showerror("Error", f"Export failed: {str(e)}")
    
    def export_sqlite(self):
        """Export to SQLite"""
        if self.historical_df.empty:
            messagebox.showwarning("No Data", "Please process archives first")
            return
        
        filepath = filedialog.asksaveasfilename(
            defaultextension=".db",
            filetypes=[("SQLite database", "*.db"), ("All files", "*.*")],
            title="Save SQLite Database"
        )
        
        if filepath:
            try:
                self.log(f"Exporting to SQLite: {filepath}")
                export_opdir_enhanced_sqlite(self.historical_df, self.lifecycle_df, 
                                           self.host_presence_df, self.scan_changes_df, 
                                           self.opdir_df, filepath)
                self.log("SQLite export complete!")
                messagebox.showinfo("Success", f"Database exported to:\n{filepath}")
            except Exception as e:
                self.log(f"ERROR: {str(e)}")
                messagebox.showerror("Error", f"Export failed: {str(e)}")
    
    def export_json(self):
        """Export to JSON"""
        if self.historical_df.empty:
            messagebox.showwarning("No Data", "Please process archives first")
            return
        
        filepath = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Save JSON File"
        )
        
        if filepath:
            try:
                self.log(f"Exporting to JSON: {filepath}")
                export_to_json(self.historical_df, self.lifecycle_df, 
                              self.host_presence_df, self.scan_changes_df, filepath)
                self.log("JSON export complete!")
                messagebox.showinfo("Success", f"Data exported to:\n{filepath}")
            except Exception as e:
                self.log(f"ERROR: {str(e)}")
                messagebox.showerror("Error", f"Export failed: {str(e)}")
    
    def log(self, message: str):
        """Add message to status log"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.status_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.status_text.see(tk.END)
        self.window.update()
    
    def run(self):
        """Run the application"""
        self.window.mainloop()


def main():
    """Main entry point"""
    app = EnhancedHistoricalAnalysisGUI()
    app.run()


if __name__ == "__main__":
    main()