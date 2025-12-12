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
            
            # Auto-fit columns and add filters
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


class EnhancedHistoricalAnalysisGUI:
    """Enhanced GUI for Nessus Historical Analysis System with host tracking and OPDIR integration"""
    
    def __init__(self):
            self.window = tk.Tk()
            self.window.title("Enhanced Nessus Historical Analysis System with OPDIR Integration")
            self.window.geometry("1400x900")
            self.window.configure(bg='#2b2b2b')  # Dark theme background
            
            # Configure style for dark theme
            self.style = ttk.Style()
            self.style.theme_use('clam')
            self.style.configure('.', background='#2b2b2b', foreground='white')
            self.style.configure('TLabel', background='#2b2b2b', foreground='white')
            self.style.configure('TFrame', background='#2b2b2b')
            self.style.configure('TLabelFrame', background='#2b2b2b', foreground='white')
            self.style.configure('TButton', background='#404040', foreground='white')
            self.style.map('TButton', background=[('active', '#505050')])
            
            # Configure Entry widgets for dark theme
            self.style.configure('TEntry', 
                                fieldbackground='#404040',  # Dark background
                                foreground='white',         # White text
                                bordercolor='#606060',      # Subtle border
                                lightcolor='#606060',       # Light border color
                                darkcolor='#606060',        # Dark border color
                                insertcolor='white')        # White cursor
            
            # Configure for different states
            self.style.map('TEntry',
                        fieldbackground=[('readonly', '#2b2b2b'),
                                        ('disabled', '#2b2b2b'),
                                        ('focus', '#505050')],
                        foreground=[('readonly', 'white'),
                                    ('disabled', 'white'),
                                    ('focus', 'white')])
            
            # Configure Notebook (tabs) for dark theme
            self.style.configure('TNotebook', 
                                background='#2b2b2b',       # Notebook background
                                borderwidth=0)              # Remove border
            
            self.style.configure('TNotebook.Tab', 
                                background='#404040',       # Inactive tab background
                                foreground='white',         # Tab text color
                                padding=[20, 10],           # Tab padding (width, height)
                                borderwidth=1,              # Tab border
                                focuscolor='none')          # Remove focus rectangle
            
            # Configure tab states (hover, active, selected)
            self.style.map('TNotebook.Tab',
                        background=[('selected', '#2b2b2b'),    # Active tab background
                                    ('active', '#505050'),       # Hover tab background
                                    ('!active', '#404040')],     # Inactive tab background
                        foreground=[('selected', 'white'),     # Active tab text
                                    ('active', 'white'),         # Hover tab text  
                                    ('!active', '#cccccc')],     # Inactive tab text
                        expand=[('selected', [1, 1, 1, 0])])   # Expand selected tab slightly
            
            # Configure Combobox for dark theme (if you use any)
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
            
            # Configure Scrollbar for dark theme (if visible)
            self.style.configure('Vertical.TScrollbar',
                                background='#404040',
                                troughcolor='#2b2b2b',
                                bordercolor='#606060',
                                arrowcolor='white',
                                darkcolor='#404040',
                                lightcolor='#404040')
            
            # Rest of your initialization code...
            self.archive_paths = []
            self.plugins_db_path = None
            self.existing_db_path = None
            self.opdir_file_path = None
            self.include_info = tk.BooleanVar(value=False)
            
            # Date filter variables
            self.filter_start_date = tk.StringVar()
            self.filter_end_date = tk.StringVar()
            self.use_date_filter = tk.BooleanVar(value=False)
            
            self.historical_df = pd.DataFrame()
            self.lifecycle_df = pd.DataFrame()
            self.host_presence_df = pd.DataFrame()
            self.scan_changes_df = pd.DataFrame()
            self.opdir_df = pd.DataFrame()
            self.opdir_summary = {}
            
            self.setup_ui()
    
    def setup_ui(self):
        """Setup the user interface with dark theme and manual filter application"""
        # Main container with padding
        main_frame = ttk.Frame(self.window, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.window.columnconfigure(0, weight=1)
        self.window.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(3, weight=1)
        
        # File selection frame
        file_frame = ttk.LabelFrame(main_frame, text="File Selection", padding="10")
        file_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)
        file_frame.columnconfigure(1, weight=1)
        
        # Archive selection
        ttk.Label(file_frame, text="Nessus Archives:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.archives_label = ttk.Label(file_frame, text="No files selected (optional if database loaded)", foreground="gray")
        self.archives_label.grid(row=0, column=1, sticky=tk.W, padx=5)
        ttk.Button(file_frame, text="Select Archives", command=self.select_archives).grid(row=0, column=2, padx=5)
        
        # Plugins DB selection
        ttk.Label(file_frame, text="Plugins DB (optional):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.plugins_label = ttk.Label(file_frame, text="None selected", foreground="gray")
        self.plugins_label.grid(row=1, column=1, sticky=tk.W, padx=5)
        ttk.Button(file_frame, text="Select Plugins DB", command=self.select_plugins_db).grid(row=1, column=2, padx=5)
        
        # Existing DB selection
        ttk.Label(file_frame, text="Existing DB (optional):").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.existing_db_label = ttk.Label(file_frame, text="None selected", foreground="gray")
        self.existing_db_label.grid(row=2, column=1, sticky=tk.W, padx=5)
        ttk.Button(file_frame, text="Load Existing DB", command=self.select_existing_db).grid(row=2, column=2, padx=5)
        
        # OPDIR file selection
        ttk.Label(file_frame, text="OPDIR File (optional):").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.opdir_label = ttk.Label(file_frame, text="None selected", foreground="gray")
        self.opdir_label.grid(row=3, column=1, sticky=tk.W, padx=5)
        ttk.Button(file_frame, text="Select OPDIR File", command=self.select_opdir_file).grid(row=3, column=2, padx=5)
        
        # Analysis options frame
        options_frame = ttk.LabelFrame(main_frame, text="Analysis & Filter Options", padding="10")
        options_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        options_frame.columnconfigure(1, weight=1)
        
        # Include Info findings checkbox - NO AUTO-UPDATE
        info_checkbox = ttk.Checkbutton(
            options_frame, 
            text="Include Info-level findings in analysis and visualizations", 
            variable=self.include_info
            # Removed command= to prevent auto-update
        )
        info_checkbox.grid(row=0, column=0, columnspan=4, sticky=tk.W, pady=5)
        
        # Info label
        info_label = ttk.Label(
            options_frame, 
            text="Note: Info findings are always stored in database, this only affects analysis/visuals",
            foreground="gray"
        )
        info_label.grid(row=1, column=0, columnspan=4, sticky=tk.W, pady=2)
        
        # Date filtering controls
        ttk.Separator(options_frame, orient='horizontal').grid(row=2, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=10)
        
        date_filter_checkbox = ttk.Checkbutton(
            options_frame,
            text="Filter visualizations by date range",
            variable=self.use_date_filter,
            command=self.toggle_date_filter_manual  # Only enables/disables fields, no auto-update
        )
        date_filter_checkbox.grid(row=3, column=0, columnspan=4, sticky=tk.W, pady=5)
        
        # Start date - NO AUTO-UPDATE BINDING
        ttk.Label(options_frame, text="Start Date:").grid(row=4, column=0, sticky=tk.W, padx=(20, 5), pady=2)
        self.start_date_entry = ttk.Entry(options_frame, textvariable=self.filter_start_date, width=12, state='disabled')
        self.start_date_entry.grid(row=4, column=1, sticky=tk.W, padx=5, pady=2)
        ttk.Label(options_frame, text="(YYYY-MM-DD)", foreground="gray").grid(row=4, column=2, sticky=tk.W, padx=5, pady=2)
        
        # End date - NO AUTO-UPDATE BINDING
        ttk.Label(options_frame, text="End Date:").grid(row=5, column=0, sticky=tk.W, padx=(20, 5), pady=2)
        self.end_date_entry = ttk.Entry(options_frame, textvariable=self.filter_end_date, width=12, state='disabled')
        self.end_date_entry.grid(row=5, column=1, sticky=tk.W, padx=5, pady=2)
        ttk.Label(options_frame, text="(YYYY-MM-DD)", foreground="gray").grid(row=5, column=2, sticky=tk.W, padx=5, pady=2)
        
        # Filter control buttons
        filter_button_frame = ttk.Frame(options_frame)
        filter_button_frame.grid(row=6, column=0, columnspan=4, sticky=tk.W, pady=10)
        
        # Apply Filters button (primary action)
        apply_filters_btn = ttk.Button(filter_button_frame, text="Apply Filters", command=self.apply_filters_manual)
        apply_filters_btn.pack(side=tk.LEFT, padx=5)
        
        # Reset Filters button
        reset_filters_btn = ttk.Button(filter_button_frame, text="Reset Filters", command=self.reset_filters_manual)
        reset_filters_btn.pack(side=tk.LEFT, padx=5)
        
        # Current filter status display
        self.filter_status_label = ttk.Label(options_frame, text="No filters applied", foreground="gray")
        self.filter_status_label.grid(row=7, column=0, columnspan=4, sticky=tk.W, pady=5)
        
        # Action buttons frame
        action_frame = ttk.Frame(main_frame, padding="10")
        action_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Button(action_frame, text="Process/Analyze", command=self.process_archives).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Refresh Analysis", command=self.refresh_analysis).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Export to Excel", command=self.export_excel).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Export to SQLite", command=self.export_sqlite).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Export to JSON", command=self.export_json).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Export JSON Schema", command=self.export_schema).pack(side=tk.LEFT, padx=5)
        
        # Notebook for different views
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=3, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        # Status tab
        self.status_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.status_frame, text="Status")
        
        self.status_text = tk.Text(self.status_frame, wrap=tk.WORD, height=20, 
                                   bg='#1e1e1e', fg='white', insertbackground='white')
        self.status_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        status_scroll = ttk.Scrollbar(self.status_frame, command=self.status_text.yview)
        status_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.status_text.config(yscrollcommand=status_scroll.set)
        
        # Visualization tabs (created after processing)
        self.viz_frames = {}
    
    def apply_filters_manual(self):
        """Apply current filter settings to visualizations"""
        if self.historical_df.empty:
            messagebox.showwarning("No Data", "Please process archives first")
            return
        
        try:
            # Check if Info filter change requires full re-analysis
            current_info_setting = self.include_info.get()
            
            # Check if this is different from what's currently in lifecycle_df
            needs_full_refresh = self.check_if_full_refresh_needed(current_info_setting)
            
            if needs_full_refresh:
                self.log("Info filter changed - performing full analysis refresh...")
                
                # Show progress
                original_text = self.window.title()
                self.window.title("Refreshing analysis - please wait...")
                self.window.update()
                
                try:
                    self.refresh_analysis_internal()
                    self.log("Full analysis refresh complete")
                finally:
                    self.window.title(original_text)
            else:
                # Just update visualizations (fast)
                self.log("Applying visualization filters...")
                self.update_visualizations_only()
                self.log("Visualization filters applied")
            
            # Update status display
            self.update_filter_status_display()
            
        except Exception as e:
            self.log(f"Error applying filters: {str(e)}")
            messagebox.showerror("Error", f"Failed to apply filters: {str(e)}")

    def check_if_full_refresh_needed(self, current_info_setting: bool) -> bool:
        """
        Check if the Info setting change requires full re-analysis.
        
        Args:
            current_info_setting: Current state of include_info checkbox
            
        Returns:
            True if full refresh needed, False if just visualization update needed
        """
        if self.lifecycle_df.empty:
            return True  # First time, need full analysis
        
        # Check current lifecycle data to see what Info setting was used
        total_findings_in_lifecycle = len(self.lifecycle_df)
        total_findings_in_historical = len(self.historical_df)
        info_findings_in_historical = len(self.historical_df[self.historical_df['severity_text'] == 'Info']) if not self.historical_df.empty else 0
        
        # If including Info and lifecycle has less than total (missing Info), need refresh
        if current_info_setting and (total_findings_in_lifecycle < total_findings_in_historical):
            return True
        
        # If excluding Info and lifecycle equals total (includes Info), need refresh  
        if not current_info_setting and (total_findings_in_lifecycle == total_findings_in_historical) and info_findings_in_historical > 0:
            return True
        
        # No change needed
        return False

    def update_filter_status_display(self):
        """Update the filter status label to show pending changes"""
        if not hasattr(self, 'filter_status_label'):
            return
            
        status_text = self.get_filter_status_text()
        
        # Check if filters have been applied or are pending
        if hasattr(self, 'viz_frames') and self.viz_frames:
            # If visualizations exist, show if filters need to be applied
            self.filter_status_label.config(
                text=f"Current: {status_text} (Click 'Apply Filters' to update)",
                foreground="orange"
            )
        else:
            # No visualizations yet
            self.filter_status_label.config(
                text=f"Ready: {status_text}",
                foreground="gray"
            )

    def reset_filters_manual(self):
        """Reset all filters to default state"""
        self.log("Resetting all filters...")
        
        # Reset Info filter
        self.include_info.set(False)
        
        # Reset date filter
        self.use_date_filter.set(False)
        self.filter_start_date.set("")
        self.filter_end_date.set("")
        
        # Disable date entry fields
        self.start_date_entry.config(state='disabled')
        self.end_date_entry.config(state='disabled')
        
        # Update status display
        self.update_filter_status_display()
        
        self.log("Filters reset - click 'Apply Filters' to update visualizations")

    def toggle_date_filter_manual(self):
        """Enable/disable date filter controls WITHOUT auto-updating visualizations"""
        state = 'normal' if self.use_date_filter.get() else 'disabled'
        self.start_date_entry.config(state=state)
        self.end_date_entry.config(state=state)
        
        # Set default dates when enabling (but don't apply yet)
        if self.use_date_filter.get() and not self.historical_df.empty:
            if not self.filter_start_date.get():
                start_date = self.historical_df['scan_date'].min().strftime('%Y-%m-%d')
                self.filter_start_date.set(start_date)
            if not self.filter_end_date.get():
                end_date = self.historical_df['scan_date'].max().strftime('%Y-%m-%d')
                self.filter_end_date.set(end_date)
        
        # Update status display only
        self.update_filter_status_display()
        
        # Log the change but don't apply
        if self.use_date_filter.get():
            self.log("Date filter enabled - click 'Apply Filters' to update visualizations")
        else:
            self.log("Date filter disabled - click 'Apply Filters' to update visualizations")

    def select_archives(self):
        """Select Nessus archive files with dark theme dialog"""
        filetypes = (
            ('Archive files', '*.zip'),
            ('Nessus files', '*.nessus'),
            ('All files', '*.*')
        )
        
        paths = filedialog.askopenfilenames(
            title='Select Nessus Archives',
            filetypes=filetypes
        )
        
        if paths:
            self.archive_paths = list(paths)
            self.archives_label.config(
                text=f"{len(self.archive_paths)} file(s) selected",
                foreground="white"
            )
            self.log(f"Selected {len(self.archive_paths)} archive(s)")
        else:
            # Update archives label to show current mode when no files selected
            self.archives_label.config(
                text="No files selected (archives optional if database loaded)",
                foreground="gray"
            )
    
    def select_plugins_db(self):
        """Select plugins database file with dark theme dialog"""
        filetypes = (
            ('XML files', '*.xml'),
            ('JSON files', '*.json'),
            ('All files', '*.*')
        )
        
        path = filedialog.askopenfilename(
            title='Select Plugins Database',
            filetypes=filetypes
        )
        
        if path:
            self.plugins_db_path = path
            self.plugins_label.config(
                text=os.path.basename(path),
                foreground="white"
            )
            self.log(f"Selected plugins DB: {os.path.basename(path)}")
    
    def select_existing_db(self):
        """Select existing database file for updating"""
        filetypes = (
            ('SQLite database', '*.db'),
            ('All files', '*.*')
        )
        
        path = filedialog.askopenfilename(
            title='Select Existing Database',
            filetypes=filetypes
        )
        
        if path:
            self.existing_db_path = path
            self.existing_db_label.config(
                text=os.path.basename(path),
                foreground="white"
            )
            self.log(f"Selected existing DB: {os.path.basename(path)}")
    
    def select_opdir_file(self):
        """Select OPDIR mapping file with dark theme dialog"""
        filetypes = (
            ('Excel files', '*.xlsx'),
            ('CSV files', '*.csv'),
            ('Excel files (legacy)', '*.xls'),
            ('All files', '*.*')
        )
        
        path = filedialog.askopenfilename(
            title='Select OPDIR Mapping File',
            filetypes=filetypes
        )
        
        if path:
            self.opdir_file_path = path
            self.opdir_label.config(
                text=os.path.basename(path),
                foreground="white"
            )
            self.log(f"Selected OPDIR file: {os.path.basename(path)}")
    
    def load_opdir_data(self):
        """Load OPDIR data if file is selected"""
        if self.opdir_file_path:
            self.log("Loading OPDIR mapping data...")
            self.opdir_df = load_opdir_mapping(self.opdir_file_path)
            if not self.opdir_df.empty:
                self.log(f"Successfully loaded {len(self.opdir_df)} OPDIR records")
                # Create summary for display
                if 'status' in self.opdir_df.columns:
                    status_counts = self.opdir_df['status'].value_counts()
                    self.log(f"OPDIR Status: {dict(status_counts)}")
                return True
            else:
                self.log("Warning: No OPDIR data could be loaded")
                return False
        return True  # Return True if no OPDIR file selected (optional)
    
    def on_visualization_filter_change(self):
        """Called when visualization-only filters change (date filters) - fast update"""
        if not self.historical_df.empty and hasattr(self, 'viz_frames') and self.viz_frames:
            self.log("Visualization filter changed - updating displays...")
            try:
                self.update_visualizations_only()
            except Exception as e:
                self.log(f"Error updating visualizations: {str(e)}")
    
    def get_filtered_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """Apply date and info filtering to DataFrame"""
        filtered_df = df.copy()
        
        # Apply Info filtering
        if not self.include_info.get():
            filtered_df = filtered_df[filtered_df['severity_text'] != 'Info']
        
        # Apply date filtering
        if self.use_date_filter.get() and not filtered_df.empty:
            try:
                start_date = pd.to_datetime(self.filter_start_date.get())
                end_date = pd.to_datetime(self.filter_end_date.get())
                
                # Ensure we include the full end date
                end_date = end_date + pd.Timedelta(days=1) - pd.Timedelta(seconds=1)
                
                filtered_df = filtered_df[
                    (filtered_df['scan_date'] >= start_date) & 
                    (filtered_df['scan_date'] <= end_date)
                ]
            except (ValueError, TypeError) as e:
                self.log(f"Date filter error: {e}")
        
        return filtered_df
    
    def on_visualization_filter_change(self):
        """Called when visualization-only filters change (date filters) - fast update"""
        if not self.historical_df.empty and hasattr(self, 'viz_frames') and self.viz_frames:
            self.log("Visualization filter changed - updating displays...")
            try:
                self.update_visualizations_only()
            except Exception as e:
                self.log(f"Error updating visualizations: {str(e)}")
    
    def on_date_filter_change(self, *args):
        """Called when date filter values change - with debouncing to prevent excessive updates"""
        # Only proceed if date filtering is enabled
        if not self.use_date_filter.get():
            return
        
        # Cancel any pending update to avoid excessive calls while typing
        if hasattr(self, '_filter_update_job'):
            self.window.after_cancel(self._filter_update_job)
        
        # Schedule update after 800ms delay (debouncing)
        self._filter_update_job = self.window.after(800, self.on_visualization_filter_change)
    
    def update_visualizations_only(self):
        """Update only the visualizations without re-analyzing data - FAST operation"""
        try:
            if hasattr(self, 'viz_frames') and self.viz_frames:
                self.log(f"Updating visualizations with filters: {self.get_filter_status_text()}")
                
                # Store current tab selection
                current_tab = self.notebook.select()
                current_tab_index = self.notebook.index(current_tab) if current_tab else 0
                
                # Re-create visualizations with current filter settings
                self.create_visualizations()
                
                # Restore tab selection
                try:
                    if current_tab_index < self.notebook.index("end"):
                        self.notebook.select(current_tab_index)
                except:
                    pass
                
                self.log("Visualizations updated successfully")
            
        except Exception as e:
            self.log(f"Error updating visualizations: {str(e)}")
            import traceback
            traceback.print_exc()
    
    def refresh_analysis_internal(self):
        """Internal method for full analysis refresh without user prompts"""
        include_info_val = self.include_info.get()
        self.log(f"Performing internal analysis refresh")
        self.log(f"Filter status: {self.get_filter_status_text()}")
        
        # Filter data for analysis if needed
        analysis_df = self.historical_df.copy()
        if not include_info_val:
            analysis_df = analysis_df[analysis_df['severity_text'] != 'Info']
            info_filtered = len(self.historical_df) - len(analysis_df)
            self.log(f"Filtered out {info_filtered} Info-level findings from analysis")
        
        # Regenerate analysis DataFrames (this is the expensive operation)
        self.lifecycle_df = analyze_finding_lifecycle(analysis_df)
        
        # Apply OPDIR enrichment if data is available
        if not self.opdir_df.empty:
            self.log("Re-applying OPDIR enrichment...")
            self.lifecycle_df = enrich_findings_with_opdir(self.lifecycle_df, self.opdir_df)
            self.opdir_summary = create_opdir_summary_report(self.lifecycle_df, self.opdir_df)
            self.log_opdir_summary()
        
        self.host_presence_df = create_host_presence_analysis(analysis_df)
        self.scan_changes_df = analyze_scan_changes(analysis_df)
        
        # Update date filter defaults if enabled
        if self.use_date_filter.get():
            if not self.filter_start_date.get() and not self.historical_df.empty:
                start_date = self.historical_df['scan_date'].min().strftime('%Y-%m-%d')
                self.filter_start_date.set(start_date)
            if not self.filter_end_date.get() and not self.historical_df.empty:
                end_date = self.historical_df['scan_date'].max().strftime('%Y-%m-%d')
                self.filter_end_date.set(end_date)
        
        # Update visualizations
        self.create_visualizations()
        
        self.log(f"Internal analysis refresh complete!")
        self.log(f"Findings in analysis: {len(self.lifecycle_df)}")
    
    def refresh_analysis(self):
        """User-triggered full analysis refresh with user feedback"""
        if self.historical_df.empty:
            messagebox.showwarning("No Data", "Please process archives first")
            return
        
        try:
            # Call internal refresh method
            self.refresh_analysis_internal()
            
            # Show completion message
            messagebox.showinfo("Success", "Analysis refreshed with current settings and OPDIR integration!")
            
        except Exception as e:
            self.log(f"ERROR: {str(e)}")
            messagebox.showerror("Error", f"Refresh failed: {str(e)}")
            import traceback
            traceback.print_exc()
    
    def create_timeline_viz(self):
        """Create findings timeline visualization with manual filter status"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Timeline")
        self.viz_frames['timeline'] = frame
        
        # Add filter status display (no apply button on individual tabs)
        control_frame = ttk.Frame(frame)
        control_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
        
        # Filter status (shows what's currently applied)
        status_label = ttk.Label(control_frame, text=f"Applied Filters: {self.get_filter_status_text()}", foreground="lightblue")
        status_label.pack(side=tk.LEFT)
        
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8))
        fig.patch.set_facecolor('#2b2b2b')
        
        # Apply all filters to get visualization data
        filtered_df = self.get_filtered_data(self.historical_df)
        
        if filtered_df.empty:
            ax1.text(0.5, 0.5, 'No data matches current filters', ha='center', va='center', 
                    transform=ax1.transAxes, color='white', fontsize=14)
            ax2.text(0.5, 0.5, 'No data matches current filters', ha='center', va='center', 
                    transform=ax2.transAxes, color='white', fontsize=14)
        else:
            # Total findings over time
            timeline_data = filtered_df.groupby('scan_date').size().reset_index(name='count')
            ax1.plot(timeline_data['scan_date'], timeline_data['count'], marker='o', linewidth=2, color='#007bff')
            
            filter_suffix = ""
            if self.use_date_filter.get():
                filter_suffix += f" ({self.filter_start_date.get()} to {self.filter_end_date.get()})"
            if not self.include_info.get():
                filter_suffix += " (Excluding Info)"
            
            ax1.set_title(f'Total Findings Over Time{filter_suffix}', fontsize=14, fontweight='bold', color='white')
            ax1.set_xlabel('Scan Date', color='white')
            ax1.set_ylabel('Number of Findings', color='white')
            ax1.grid(True, alpha=0.3)
            ax1.set_facecolor('#2b2b2b')
            ax1.tick_params(colors='white')
            ax1.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
            plt.setp(ax1.xaxis.get_majorticklabels(), rotation=45, ha='right')
            
            # Findings by severity over time
            severity_timeline = filtered_df.groupby(['scan_date', 'severity_text']).size().unstack(fill_value=0)
            
            colors = self.get_severity_colors()
            for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
                if severity in severity_timeline.columns:
                    ax2.plot(severity_timeline.index, severity_timeline[severity], 
                            marker='o', label=severity, color=colors.get(severity, 'gray'), linewidth=2)
            
            ax2.set_title(f'Findings by Severity Over Time{filter_suffix}', fontsize=14, fontweight='bold', color='white')
            ax2.set_xlabel('Scan Date', color='white')
            ax2.set_ylabel('Number of Findings', color='white')
            ax2.legend(loc='upper left')
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

    def reset_all_filters(self):
        """Reset all filters to default state"""
        self.log("Resetting all filters to defaults...")
        
        # Reset Info filter
        self.include_info.set(False)
        
        # Reset date filter
        self.use_date_filter.set(False)
        self.filter_start_date.set("")
        self.filter_end_date.set("")
        
        # Disable date entry fields
        self.start_date_entry.config(state='disabled')
        self.end_date_entry.config(state='disabled')
        
        # Trigger update
        self.on_visualization_filter_change()
        self.log("All filters reset to defaults")

    def get_severity_colors(self):
        """Get the standard severity color scheme"""
        return {
            'Critical': '#dc3545',  # Red
            'High': '#fd7e14',      # Orange  
            'Medium': '#ffc107',    # Yellow
            'Low': '#007bff',       # Blue
            'Info': '#6c757d'       # Gray
        }
    
    def get_filter_status_text(self):
        """Get descriptive text for current filter settings"""
        status_parts = []
        
        # Info filter status
        if not self.include_info.get():
            if not self.historical_df.empty:
                info_count = len(self.historical_df[self.historical_df['severity_text'] == 'Info'])
                total_count = len(self.historical_df)
                status_parts.append(f"Excluding Info ({info_count} of {total_count} findings)")
            else:
                status_parts.append("Excluding Info findings")
        else:
            status_parts.append("Including Info findings")
        
        # Date filter status
        if self.use_date_filter.get():
            start_date = self.filter_start_date.get()
            end_date = self.filter_end_date.get()
            if start_date and end_date:
                status_parts.append(f"Date Range: {start_date} to {end_date}")
            else:
                status_parts.append("Date filter enabled (no dates set)")
        
        return " | ".join(status_parts) if status_parts else "No filters applied"
    
    def log(self, message: str):
        """Add message to status log"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.status_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.status_text.see(tk.END)
        self.window.update()
    
    def process_archives(self):
        """Process selected archives with enhanced features including OPDIR integration or analyze existing database"""
        # Check if we have either archives or an existing database
        has_archives = bool(self.archive_paths)
        has_existing_db = bool(self.existing_db_path and os.path.exists(self.existing_db_path))
        
        if not has_archives and not has_existing_db:
            messagebox.showwarning("No Data Source", "Please select archive files or load an existing database")
            return
        
        # Load OPDIR data first if available
        if not self.load_opdir_data():
            return
        
        if not has_archives and has_existing_db:
            # Load and analyze existing database only
            self.log("="*60)
            self.log("Loading and analyzing existing database with OPDIR integration...")
            self.log("="*60)
            
            try:
                # Load existing database
                existing_historical_df, existing_lifecycle_df, existing_host_presence_df, existing_scan_changes_df = load_existing_database(self.existing_db_path)
                
                if existing_historical_df.empty:
                    messagebox.showerror("Error", "No data found in the existing database")
                    return
                
                # Set the loaded data
                self.historical_df = existing_historical_df
                
                # Re-run analysis with current filter settings
                include_info_val = self.include_info.get()
                self.log(f"Re-analyzing with current filter settings")
                self.log(f"Filter status: {self.get_filter_status_text()}")
                
                # Filter data for analysis if needed
                analysis_df = self.historical_df.copy()
                if not include_info_val:
                    analysis_df = analysis_df[analysis_df['severity_text'] != 'Info']
                    info_filtered = len(self.historical_df) - len(analysis_df)
                    self.log(f"Filtered out {info_filtered} Info-level findings from analysis")
                
                # Regenerate analysis DataFrames with current settings
                self.lifecycle_df = analyze_finding_lifecycle(analysis_df)
                
                # Apply OPDIR enrichment if data is available
                if not self.opdir_df.empty:
                    self.log("Enriching findings with OPDIR information...")
                    self.lifecycle_df = enrich_findings_with_opdir(self.lifecycle_df, self.opdir_df)
                    self.opdir_summary = create_opdir_summary_report(self.lifecycle_df, self.opdir_df)
                    self.log_opdir_summary()
                
                self.host_presence_df = create_host_presence_analysis(analysis_df)
                self.scan_changes_df = analyze_scan_changes(analysis_df)
                
                # Set up date filter defaults
                if not self.filter_start_date.get() and not self.historical_df.empty:
                    start_date = self.historical_df['scan_date'].min().strftime('%Y-%m-%d')
                    self.filter_start_date.set(start_date)
                if not self.filter_end_date.get() and not self.historical_df.empty:
                    end_date = self.historical_df['scan_date'].max().strftime('%Y-%m-%d')
                    self.filter_end_date.set(end_date)
                
                self.log(f"Database analysis complete!")
                self.log(f"Total findings in database: {len(self.historical_df)}")
                self.log(f"Date range: {self.historical_df['scan_date'].min()} to {self.historical_df['scan_date'].max()}")
                if not include_info_val:
                    info_count = len(self.historical_df[self.historical_df['severity_text'] == 'Info'])
                    self.log(f"Info findings in database (excluded from analysis): {info_count}")
                self.log(f"Findings in analysis: {len(self.lifecycle_df)}")
                self.log(f"Hosts tracked: {len(self.host_presence_df)}")
                self.log(f"Scan changes: {len(self.scan_changes_df)}")
                
                # Create visualizations
                self.create_visualizations()
                
                messagebox.showinfo("Success", "Existing database loaded and analyzed successfully with OPDIR integration!")
                
            except Exception as e:
                self.log(f"ERROR: {str(e)}")
                messagebox.showerror("Error", f"Database analysis failed: {str(e)}")
                import traceback
                traceback.print_exc()
            
            return
        
        # Original archive processing logic (when archives are provided)
        self.log("="*60)
        self.log("Starting enhanced archive processing with OPDIR integration...")
        self.log("="*60)
        
        try:
            # Process archives with enhanced features
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
            
            # Apply OPDIR enrichment if data is available
            if not self.opdir_df.empty:
                self.log("Enriching findings with OPDIR information...")
                self.lifecycle_df = enrich_findings_with_opdir(self.lifecycle_df, self.opdir_df)
                self.opdir_summary = create_opdir_summary_report(self.lifecycle_df, self.opdir_df)
                self.log_opdir_summary()
            
            # Set up date filter defaults
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
            
            # Create visualizations
            self.create_visualizations()
            
            messagebox.showinfo("Success", "Archives processed successfully with enhanced features and OPDIR integration!")
            
        except Exception as e:
            self.log(f"ERROR: {str(e)}")
            messagebox.showerror("Error", f"Processing failed: {str(e)}")
            import traceback
            traceback.print_exc()
    
    def log_opdir_summary(self):
        """Log OPDIR integration summary to status"""
        if self.opdir_summary:
            self.log("OPDIR Integration Summary:")
            
            # OPDIR stats
            if 'opdir_stats' in self.opdir_summary:
                stats = self.opdir_summary['opdir_stats']
                self.log(f"  Total OPDIRs: {stats.get('total_opdirs', 0)}")
                self.log(f"  OPDIRs with IAVx: {stats.get('opdirs_with_iavx', 0)}")
                if 'status_distribution' in stats:
                    for status, count in stats['status_distribution'].items():
                        self.log(f"    {status}: {count}")
            
            # Mapping stats
            if 'mapping_stats' in self.opdir_summary:
                stats = self.opdir_summary['mapping_stats']
                self.log(f"  Findings mapped to OPDIR: {stats.get('opdir_mapped_findings', 0)} of {stats.get('total_findings', 0)} ({stats.get('mapping_percentage', 0)}%)")
            
            # Risk stats
            if 'risk_stats' in self.opdir_summary:
                stats = self.opdir_summary['risk_stats']
                if stats.get('overdue_active_findings', 0) > 0:
                    self.log(f"  WARNING: {stats['overdue_active_findings']} active findings linked to overdue OPDIRs")
                if stats.get('high_risk_findings', 0) > 0:
                    self.log(f"  HIGH RISK: {stats['high_risk_findings']} Critical/High findings are overdue")
    
    def refresh_analysis(self):
        """Refresh analysis with current Info filtering setting without reprocessing archives"""
        if self.historical_df.empty:
            messagebox.showwarning("No Data", "Please process archives first")
            return
        
        try:
            include_info_val = self.include_info.get()
            self.log(f"Refreshing analysis with current filter settings")
            self.log(f"Filter status: {self.get_filter_status_text()}")
            
            # Filter data for analysis if needed
            analysis_df = self.historical_df.copy()
            if not include_info_val:
                analysis_df = analysis_df[analysis_df['severity_text'] != 'Info']
                info_filtered = len(self.historical_df) - len(analysis_df)
                self.log(f"Filtered out {info_filtered} Info-level findings from analysis")
            
            # Regenerate analysis DataFrames
            self.lifecycle_df = analyze_finding_lifecycle(analysis_df)
            
            # Apply OPDIR enrichment if data is available
            if not self.opdir_df.empty:
                self.log("Re-applying OPDIR enrichment...")
                self.lifecycle_df = enrich_findings_with_opdir(self.lifecycle_df, self.opdir_df)
                self.opdir_summary = create_opdir_summary_report(self.lifecycle_df, self.opdir_df)
                self.log_opdir_summary()
            
            self.host_presence_df = create_host_presence_analysis(analysis_df)
            self.scan_changes_df = analyze_scan_changes(analysis_df)
            
            # Update date filter defaults if enabled
            if self.use_date_filter.get():
                self.toggle_date_filter()
            
            # Update visualizations
            self.create_visualizations()
            
            self.log(f"Analysis refreshed!")
            self.log(f"Total findings in database: {len(self.historical_df)}")
            if not include_info_val:
                info_count = len(self.historical_df[self.historical_df['severity_text'] == 'Info'])
                self.log(f"Info findings in database (excluded from analysis): {info_count}")
            self.log(f"Findings in analysis: {len(self.lifecycle_df)}")
            
            messagebox.showinfo("Success", "Analysis refreshed with current settings and OPDIR integration!")
            
        except Exception as e:
            self.log(f"ERROR: {str(e)}")
            messagebox.showerror("Error", f"Refresh failed: {str(e)}")
    
    def create_visualizations(self):
        """Create enhanced visualization tabs"""
        # Remove old visualization tabs
        for tab_name in list(self.viz_frames.keys()):
            self.notebook.forget(self.viz_frames[tab_name])
        self.viz_frames = {}
        
        # Create new visualization tabs
        self.create_timeline_viz()
        self.create_host_presence_viz()
        self.create_scan_changes_viz()
        self.create_severity_trend_viz()
        self.create_host_viz()
        self.create_plugin_viz()
        self.create_lifecycle_viz()
        if not self.opdir_df.empty:
            self.create_opdir_viz()
    
    def create_timeline_viz(self):
        """Create findings timeline visualization with date filtering and corrected colors"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Timeline")
        self.viz_frames['timeline'] = frame
        
        # Add filter status and controls
        control_frame = ttk.Frame(frame)
        control_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
        
        # Filter status
        status_label = ttk.Label(control_frame, text=f"Filters: {self.get_filter_status_text()}", foreground="orange")
        status_label.pack(side=tk.LEFT)
        
        # Refresh button
        ttk.Button(control_frame, text="Apply Filters", command=self.create_visualizations).pack(side=tk.RIGHT, padx=5)
        
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8))
        fig.patch.set_facecolor('#2b2b2b')
        
        # Apply all filters to get visualization data
        filtered_df = self.get_filtered_data(self.historical_df)
        
        if filtered_df.empty:
            ax1.text(0.5, 0.5, 'No data matches current filters', ha='center', va='center', 
                    transform=ax1.transAxes, color='white', fontsize=14)
            ax2.text(0.5, 0.5, 'No data matches current filters', ha='center', va='center', 
                    transform=ax2.transAxes, color='white', fontsize=14)
        else:
            # Total findings over time
            timeline_data = filtered_df.groupby('scan_date').size().reset_index(name='count')
            ax1.plot(timeline_data['scan_date'], timeline_data['count'], marker='o', linewidth=2, color='#007bff')
            
            filter_suffix = ""
            if self.use_date_filter.get():
                filter_suffix += f" ({self.filter_start_date.get()} to {self.filter_end_date.get()})"
            if not self.include_info.get():
                filter_suffix += " (Excluding Info)"
            
            ax1.set_title(f'Total Findings Over Time{filter_suffix}', fontsize=14, fontweight='bold', color='white')
            ax1.set_xlabel('Scan Date', color='white')
            ax1.set_ylabel('Number of Findings', color='white')
            ax1.grid(True, alpha=0.3)
            ax1.set_facecolor('#2b2b2b')
            ax1.tick_params(colors='white')
            ax1.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
            plt.setp(ax1.xaxis.get_majorticklabels(), rotation=45, ha='right')
            
            # Findings by severity over time
            severity_timeline = filtered_df.groupby(['scan_date', 'severity_text']).size().unstack(fill_value=0)
            
            colors = self.get_severity_colors()
            for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
                if severity in severity_timeline.columns:
                    ax2.plot(severity_timeline.index, severity_timeline[severity], 
                            marker='o', label=severity, color=colors.get(severity, 'gray'), linewidth=2)
            
            ax2.set_title(f'Findings by Severity Over Time{filter_suffix}', fontsize=14, fontweight='bold', color='white')
            ax2.set_xlabel('Scan Date', color='white')
            ax2.set_ylabel('Number of Findings', color='white')
            ax2.legend(loc='upper left')
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
        """Create host presence visualization with date filtering"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Host Tracking")
        self.viz_frames['host_presence'] = frame
        
        # Add filter status
        control_frame = ttk.Frame(frame)
        control_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
        
        status_label = ttk.Label(control_frame, text=f"Filters: {self.get_filter_status_text()}", foreground="orange")
        status_label.pack(side=tk.LEFT)
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(14, 10))
        fig.patch.set_facecolor('#2b2b2b')
        
        # Get filtered host presence data based on date range
        filtered_host_presence = self.host_presence_df.copy()
        if self.use_date_filter.get() and not filtered_host_presence.empty:
            try:
                start_date = pd.to_datetime(self.filter_start_date.get())
                end_date = pd.to_datetime(self.filter_end_date.get()) + pd.Timedelta(days=1) - pd.Timedelta(seconds=1)
                
                # Filter based on last_seen date for host presence
                filtered_host_presence = filtered_host_presence[
                    (filtered_host_presence['last_seen'] >= start_date) | 
                    (filtered_host_presence['first_seen'] <= end_date)
                ]
            except (ValueError, TypeError):
                pass
        
        # Host status distribution
        if not filtered_host_presence.empty:
            status_counts = filtered_host_presence['status'].value_counts()
            ax1.pie(status_counts.values, labels=status_counts.index, autopct='%1.1f%%',
                   colors=['#28a745', '#dc3545'], startangle=90)
            ax1.set_title('Host Status Distribution', fontsize=12, fontweight='bold', color='white')
            ax1.set_facecolor('#2b2b2b')
        else:
            ax1.text(0.5, 0.5, 'No data matches filters', ha='center', va='center', 
                    transform=ax1.transAxes, color='white', fontsize=12)
            ax1.set_facecolor('#2b2b2b')
        
        # Presence percentage distribution
        if not filtered_host_presence.empty:
            bins = [0, 25, 50, 75, 90, 100]
            labels = ['0-25%', '26-50%', '51-75%', '76-90%', '91-100%']
            filtered_host_presence['presence_category'] = pd.cut(
                filtered_host_presence['presence_percentage'], 
                bins=bins, labels=labels, right=True
            )
            presence_dist = filtered_host_presence['presence_category'].value_counts().sort_index()
            
            bars = ax2.bar(range(len(presence_dist)), presence_dist.values, color='#007bff')
            ax2.set_xticks(range(len(presence_dist)))
            ax2.set_xticklabels(presence_dist.index, rotation=45, ha='right', color='white')
            ax2.set_title('Host Presence Percentage Distribution', fontsize=12, fontweight='bold', color='white')
            ax2.set_ylabel('Number of Hosts', color='white')
            ax2.set_facecolor('#2b2b2b')
            ax2.tick_params(colors='white')
            
            # Add data labels on bars
            for bar in bars:
                height = bar.get_height()
                if height > 0:  # Only show label if there's a value
                    ax2.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                            f'{int(height)}', ha='center', va='bottom', color='white', fontweight='bold')
        else:
            ax2.text(0.5, 0.5, 'No data matches filters', ha='center', va='center', 
                    transform=ax2.transAxes, color='white', fontsize=12)
            ax2.set_facecolor('#2b2b2b')
        
        # Most unreliable hosts (lowest presence percentage)
        if not filtered_host_presence.empty:
            unreliable_hosts = filtered_host_presence.nsmallest(10, 'presence_percentage')
            display_names = [f"{row['hostname']} ({row['ip_address']})" for _, row in unreliable_hosts.iterrows()]
            
            bars = ax3.barh(range(len(unreliable_hosts)), unreliable_hosts['presence_percentage'].values, color='#dc3545')
            ax3.set_yticks(range(len(unreliable_hosts)))
            ax3.set_yticklabels(display_names, color='white')
            ax3.set_title('10 Most Unreliable Hosts', fontsize=12, fontweight='bold', color='white')
            ax3.set_xlabel('Presence Percentage', color='white')
            ax3.set_facecolor('#2b2b2b')
            ax3.tick_params(colors='white')
            
            # Add data labels on horizontal bars
            for i, bar in enumerate(bars):
                width = bar.get_width()
                ax3.text(width + 1, bar.get_y() + bar.get_height()/2.,
                        f'{width:.1f}%', ha='left', va='center', color='white', fontweight='bold')
        else:
            ax3.text(0.5, 0.5, 'No data matches filters', ha='center', va='center', 
                    transform=ax3.transAxes, color='white', fontsize=12)
            ax3.set_facecolor('#2b2b2b')
        
        # Recently missing hosts
        if not filtered_host_presence.empty:
            missing_hosts = filtered_host_presence[filtered_host_presence['status'] == 'Missing'].head(10)
            if not missing_hosts.empty:
                display_names = [f"{row['hostname']} ({row['ip_address']})" for _, row in missing_hosts.iterrows()]
                days_since_last = [(datetime.now() - row['last_seen']).days for _, row in missing_hosts.iterrows()]
                
                bars = ax4.barh(range(len(missing_hosts)), days_since_last, color='#fd7e14')
                ax4.set_yticks(range(len(missing_hosts)))
                ax4.set_yticklabels(display_names, color='white')
                ax4.set_title('Recently Missing Hosts', fontsize=12, fontweight='bold', color='white')
                ax4.set_xlabel('Days Since Last Seen', color='white')
                ax4.set_facecolor('#2b2b2b')
                ax4.tick_params(colors='white')
                
                # Add data labels on horizontal bars
                for bar in bars:
                    width = bar.get_width()
                    ax4.text(width + width*0.01, bar.get_y() + bar.get_height()/2.,
                            f'{int(width)}', ha='left', va='center', color='white', fontweight='bold')
            else:
                ax4.text(0.5, 0.5, 'No missing hosts', ha='center', va='center', 
                        transform=ax4.transAxes, color='white', fontsize=12)
                ax4.set_facecolor('#2b2b2b')
        else:
            ax4.text(0.5, 0.5, 'No data matches filters', ha='center', va='center', 
                    transform=ax4.transAxes, color='white', fontsize=12)
            ax4.set_facecolor('#2b2b2b')
        
        plt.tight_layout()
        plt.style.use('dark_background')
        
        canvas = FigureCanvasTkAgg(fig, frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def create_scan_changes_viz(self):
        """Create scan changes visualization"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Scan Changes")
        self.viz_frames['scan_changes'] = frame
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(14, 10))
        fig.patch.set_facecolor('#2b2b2b')
        
        if not self.scan_changes_df.empty:
            # Host additions over time
            ax1.plot(self.scan_changes_df['scan_date'], self.scan_changes_df['hosts_added'], 
                    marker='o', linewidth=2, color='#28a745', label='Added')
            ax1.plot(self.scan_changes_df['scan_date'], self.scan_changes_df['hosts_removed'], 
                    marker='s', linewidth=2, color='#dc3545', label='Removed')
            ax1.set_title('Host Additions/Removals Over Time', fontsize=12, fontweight='bold', color='white')
            ax1.set_xlabel('Scan Date', color='white')
            ax1.set_ylabel('Number of Hosts', color='white')
            ax1.legend()
            ax1.grid(True, alpha=0.3)
            ax1.set_facecolor('#2b2b2b')
            ax1.tick_params(colors='white')
            ax1.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
            plt.setp(ax1.xaxis.get_majorticklabels(), rotation=45, ha='right')
            
            # Net change over time
            bars = ax2.bar(range(len(self.scan_changes_df)), self.scan_changes_df['net_change'].values,
                   color=['#28a745' if x >= 0 else '#dc3545' for x in self.scan_changes_df['net_change']])
            ax2.set_title('Net Host Change by Scan', fontsize=12, fontweight='bold', color='white')
            ax2.set_xlabel('Scan Number', color='white')
            ax2.set_ylabel('Net Change', color='white')
            ax2.axhline(y=0, color='white', linestyle='-', alpha=0.5)
            ax2.set_facecolor('#2b2b2b')
            ax2.tick_params(colors='white')
            
            # Add data labels on bars
            for bar in bars:
                height = bar.get_height()
                label_y = height + (abs(height) * 0.02) if height >= 0 else height - (abs(height) * 0.02)
                ax2.text(bar.get_x() + bar.get_width()/2., label_y,
                        f'{int(height)}', ha='center', va='bottom' if height >= 0 else 'top', 
                        color='white', fontweight='bold')
            
            # Total hosts over time
            ax3.plot(self.scan_changes_df['scan_date'], self.scan_changes_df['total_hosts_current'], 
                    marker='o', linewidth=2, color='#007bff')
            ax3.set_title('Total Hosts Over Time', fontsize=12, fontweight='bold', color='white')
            ax3.set_xlabel('Scan Date', color='white')
            ax3.set_ylabel('Total Hosts', color='white')
            ax3.grid(True, alpha=0.3)
            ax3.set_facecolor('#2b2b2b')
            ax3.tick_params(colors='white')
            ax3.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
            plt.setp(ax3.xaxis.get_majorticklabels(), rotation=45, ha='right')
            
            # Stability metrics
            stability_data = {
                'High Turnover': len(self.scan_changes_df[abs(self.scan_changes_df['net_change']) > 5]),
                'Medium Turnover': len(self.scan_changes_df[(abs(self.scan_changes_df['net_change']) > 1) & 
                                                           (abs(self.scan_changes_df['net_change']) <= 5)]),
                'Stable': len(self.scan_changes_df[abs(self.scan_changes_df['net_change']) <= 1])
            }
            
            ax4.pie(stability_data.values(), labels=stability_data.keys(), autopct='%1.1f%%',
                   colors=['#dc3545', '#ffc107', '#28a745'], startangle=90)
            ax4.set_title('Scan Stability Distribution', fontsize=12, fontweight='bold', color='white')
            ax4.set_facecolor('#2b2b2b')
        
        plt.tight_layout()
        plt.style.use('dark_background')
        
        canvas = FigureCanvasTkAgg(fig, frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def create_severity_trend_viz(self):
        """Create severity trend visualization with date filtering and corrected colors"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Severity Trends")
        self.viz_frames['severity'] = frame
        
        # Add filter status
        control_frame = ttk.Frame(frame)
        control_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
        
        status_label = ttk.Label(control_frame, text=f"Filters: {self.get_filter_status_text()}", foreground="orange")
        status_label.pack(side=tk.LEFT)
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(14, 10))
        fig.patch.set_facecolor('#2b2b2b')
        
        # Get filtered lifecycle data
        filtered_lifecycle = self.lifecycle_df.copy()
        if self.use_date_filter.get() and not filtered_lifecycle.empty:
            try:
                start_date = pd.to_datetime(self.filter_start_date.get())
                end_date = pd.to_datetime(self.filter_end_date.get()) + pd.Timedelta(days=1) - pd.Timedelta(seconds=1)
                
                # Filter by first_seen date for lifecycle data
                filtered_lifecycle = filtered_lifecycle[
                    (filtered_lifecycle['first_seen'] >= start_date) & 
                    (filtered_lifecycle['first_seen'] <= end_date)
                ]
            except (ValueError, TypeError):
                pass
        
        colors = self.get_severity_colors()
        
        # Current severity distribution
        if not filtered_lifecycle.empty:
            severity_counts = filtered_lifecycle['severity_text'].value_counts()
            severity_colors = [colors.get(sev, '#6c757d') for sev in severity_counts.index]
            ax1.pie(severity_counts.values, labels=severity_counts.index, autopct='%1.1f%%', 
                   colors=severity_colors, startangle=90)
            ax1.set_title('Severity Distribution', fontsize=12, fontweight='bold', color='white')
            ax1.set_facecolor('#2b2b2b')
        else:
            ax1.text(0.5, 0.5, 'No data matches filters', ha='center', va='center', 
                    transform=ax1.transAxes, color='white', fontsize=12)
            ax1.set_facecolor('#2b2b2b')
        
        # Active vs Resolved
        if not filtered_lifecycle.empty:
            status_counts = filtered_lifecycle['status'].value_counts()
            bars = ax2.bar(status_counts.index, status_counts.values, color=['#dc3545', '#28a745'])
            ax2.set_title('Active vs Resolved Findings', fontsize=12, fontweight='bold', color='white')
            ax2.set_ylabel('Count', color='white')
            ax2.grid(True, alpha=0.3, axis='y')
            ax2.set_facecolor('#2b2b2b')
            ax2.tick_params(colors='white')
            
            # Add data labels on bars
            for bar in bars:
                height = bar.get_height()
                ax2.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                        f'{int(height)}', ha='center', va='bottom', color='white', fontweight='bold')
        else:
            ax2.text(0.5, 0.5, 'No data matches filters', ha='center', va='center', 
                    transform=ax2.transAxes, color='white', fontsize=12)
            ax2.set_facecolor('#2b2b2b')
        
        # Average days open by severity
        if not filtered_lifecycle.empty:
            avg_days = filtered_lifecycle.groupby('severity_text')['days_open'].mean().sort_values(ascending=False)
            severity_colors = [colors.get(sev, '#6c757d') for sev in avg_days.index]
            bars = ax3.barh(avg_days.index, avg_days.values, color=severity_colors)
            ax3.set_title('Average Days Open by Severity', fontsize=12, fontweight='bold', color='white')
            ax3.set_xlabel('Average Days', color='white')
            ax3.grid(True, alpha=0.3, axis='x')
            ax3.set_facecolor('#2b2b2b')
            ax3.tick_params(colors='white')
            
            # Add data labels on horizontal bars
            for bar in bars:
                width = bar.get_width()
                ax3.text(width + width*0.01, bar.get_y() + bar.get_height()/2.,
                        f'{width:.0f}', ha='left', va='center', color='white', fontweight='bold')
        else:
            ax3.text(0.5, 0.5, 'No data matches filters', ha='center', va='center', 
                    transform=ax3.transAxes, color='white', fontsize=12)
            ax3.set_facecolor('#2b2b2b')
        
        # Reappearance rate
        if not filtered_lifecycle.empty:
            reappeared = len(filtered_lifecycle[filtered_lifecycle['reappearances'] > 0])
            never_reappeared = len(filtered_lifecycle[filtered_lifecycle['reappearances'] == 0])
            ax4.pie([reappeared, never_reappeared], labels=['Reappeared', 'Never Reappeared'],
                   autopct='%1.1f%%', colors=['#dc3545', '#28a745'], startangle=90)
            ax4.set_title('Finding Reappearance Rate', fontsize=12, fontweight='bold', color='white')
            ax4.set_facecolor('#2b2b2b')
        else:
            ax4.text(0.5, 0.5, 'No data matches filters', ha='center', va='center', 
                    transform=ax4.transAxes, color='white', fontsize=12)
            ax4.set_facecolor('#2b2b2b')
        
        plt.tight_layout()
        plt.style.use('dark_background')
        
        canvas = FigureCanvasTkAgg(fig, frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def create_host_viz(self):
        """Create host-specific visualization with enhanced display"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Host Analysis")
        self.viz_frames['host'] = frame
        
        # Create controls frame
        control_frame = ttk.Frame(frame)
        control_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)
        
        ttk.Label(control_frame, text="Select Host:").pack(side=tk.LEFT, padx=5)
        
        # Get unique hostnames with IP addresses for better display
        host_data = self.historical_df[['hostname', 'ip_address']].drop_duplicates()
        host_options = [f"{row['hostname']} ({row['ip_address']})" for _, row in host_data.iterrows()]
        host_options = sorted(host_options)
        
        self.host_var = tk.StringVar(value=host_options[0] if host_options else "")
        host_combo = ttk.Combobox(control_frame, textvariable=self.host_var, values=host_options, width=50)
        host_combo.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(control_frame, text="Update", command=self.update_host_viz).pack(side=tk.LEFT, padx=5)
        
        # Create figure
        self.host_fig, ((self.host_ax1, self.host_ax2), (self.host_ax3, self.host_ax4)) = plt.subplots(2, 2, figsize=(14, 10))
        self.host_fig.patch.set_facecolor('#2b2b2b')
        
        self.host_canvas = FigureCanvasTkAgg(self.host_fig, frame)
        self.host_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Initial update
        if host_options:
            self.update_host_viz()
    
    def update_host_viz(self):
        """Update host visualization based on selected host with enhanced display"""
        host_str = self.host_var.get()
        if not host_str:
            return
        
        # Extract hostname from "hostname (ip)" format
        hostname = host_str.split(' (')[0]
        
        # Clear axes
        for ax in [self.host_ax1, self.host_ax2, self.host_ax3, self.host_ax4]:
            ax.clear()
            ax.set_facecolor('#2b2b2b')
        
        # Filter data for selected host
        host_data = self.historical_df[self.historical_df['hostname'] == hostname]
        host_lifecycle = self.lifecycle_df[self.lifecycle_df['hostname'] == hostname]
        
        # Findings over time for this host
        timeline = host_data.groupby('scan_date').size().reset_index(name='count')
        self.host_ax1.plot(timeline['scan_date'], timeline['count'], marker='o', linewidth=2, color='#007bff')
        self.host_ax1.set_title(f'Findings Timeline - {host_str}', fontsize=12, fontweight='bold', color='white')
        self.host_ax1.set_xlabel('Scan Date', color='white')
        self.host_ax1.set_ylabel('Number of Findings', color='white')
        self.host_ax1.grid(True, alpha=0.3)
        self.host_ax1.tick_params(colors='white')
        self.host_ax1.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
        plt.setp(self.host_ax1.xaxis.get_majorticklabels(), rotation=45, ha='right')
        
        # Severity distribution
        if not host_lifecycle.empty:
            severity_counts = host_lifecycle['severity_text'].value_counts()
            colors = ['#dc3545', '#fd7e14', '#ffc107', '#28a745', '#6c757d']
            self.host_ax2.pie(severity_counts.values, labels=severity_counts.index, autopct='%1.1f%%',
                             colors=colors[:len(severity_counts)], startangle=90)
            self.host_ax2.set_title(f'Severity Distribution - {hostname}', fontsize=12, fontweight='bold', color='white')
        
        # Top 10 plugins for this host
        if not host_lifecycle.empty:
            top_plugins = host_lifecycle.nlargest(10, 'days_open')[['plugin_name', 'days_open']]
            self.host_ax3.barh(range(len(top_plugins)), top_plugins['days_open'].values, color='#dc3545')
            self.host_ax3.set_yticks(range(len(top_plugins)))
            self.host_ax3.set_yticklabels([name[:40] + '...' if len(name) > 40 else name 
                                          for name in top_plugins['plugin_name'].values], color='white')
            self.host_ax3.set_title(f'Top 10 Longest-Running Findings - {hostname}', fontsize=12, fontweight='bold', color='white')
            self.host_ax3.set_xlabel('Days Open', color='white')
            self.host_ax3.grid(True, alpha=0.3, axis='x')
            self.host_ax3.tick_params(colors='white')
        
        # Status breakdown
        if not host_lifecycle.empty:
            status_counts = host_lifecycle['status'].value_counts()
            colors_status = {'Active': '#dc3545', 'Resolved': '#28a745'}
            bars = self.host_ax4.bar(status_counts.index, status_counts.values, 
                             color=[colors_status.get(s, 'gray') for s in status_counts.index])
            self.host_ax4.set_title(f'Finding Status - {hostname}', fontsize=12, fontweight='bold', color='white')
            self.host_ax4.set_ylabel('Count', color='white')
            self.host_ax4.grid(True, alpha=0.3, axis='y')
            self.host_ax4.tick_params(colors='white')
            
            # Add data labels on bars
            for bar in bars:
                height = bar.get_height()
                self.host_ax4.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                        f'{int(height)}', ha='center', va='bottom', color='white', fontweight='bold')
        
        plt.tight_layout()
        plt.style.use('dark_background')
        self.host_canvas.draw()
    
    def create_plugin_viz(self):
        """Create plugin-specific visualization"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Plugin Analysis")
        self.viz_frames['plugin'] = frame
        
        # Create controls frame
        control_frame = ttk.Frame(frame)
        control_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)
        
        ttk.Label(control_frame, text="Select Plugin ID:").pack(side=tk.LEFT, padx=5)
        
        # Get unique plugin IDs with names
        plugin_list = self.lifecycle_df[['plugin_id', 'plugin_name']].drop_duplicates()
        plugin_list = plugin_list.sort_values('plugin_id')
        plugin_options = [f"{row['plugin_id']} - {row['plugin_name'][:50]}" 
                         for _, row in plugin_list.iterrows()]
        
        self.plugin_var = tk.StringVar(value=plugin_options[0] if plugin_options else "")
        plugin_combo = ttk.Combobox(control_frame, textvariable=self.plugin_var, 
                                   values=plugin_options, width=60)
        plugin_combo.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(control_frame, text="Update", command=self.update_plugin_viz).pack(side=tk.LEFT, padx=5)
        
        # Create figure
        self.plugin_fig, ((self.plugin_ax1, self.plugin_ax2), (self.plugin_ax3, self.plugin_ax4)) = plt.subplots(2, 2, figsize=(14, 10))
        self.plugin_fig.patch.set_facecolor('#2b2b2b')
        
        self.plugin_canvas = FigureCanvasTkAgg(self.plugin_fig, frame)
        self.plugin_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Initial update
        if plugin_options:
            self.update_plugin_viz()
    
    def update_plugin_viz(self):
        """Update plugin visualization based on selected plugin"""
        plugin_str = self.plugin_var.get()
        if not plugin_str:
            return
        
        plugin_id = plugin_str.split(' - ')[0]
        
        # Clear axes
        for ax in [self.plugin_ax1, self.plugin_ax2, self.plugin_ax3, self.plugin_ax4]:
            ax.clear()
            ax.set_facecolor('#2b2b2b')
        
        # Filter data for selected plugin
        plugin_data = self.historical_df[self.historical_df['plugin_id'] == plugin_id]
        plugin_lifecycle = self.lifecycle_df[self.lifecycle_df['plugin_id'] == plugin_id]
        
        # Affected hosts over time
        timeline = plugin_data.groupby('scan_date')['hostname'].nunique().reset_index(name='host_count')
        self.plugin_ax1.plot(timeline['scan_date'], timeline['host_count'], marker='o', linewidth=2, color='#dc3545')
        self.plugin_ax1.set_title(f'Affected Hosts Over Time - Plugin {plugin_id}', fontsize=12, fontweight='bold', color='white')
        self.plugin_ax1.set_xlabel('Scan Date', color='white')
        self.plugin_ax1.set_ylabel('Number of Hosts', color='white')
        self.plugin_ax1.grid(True, alpha=0.3)
        self.plugin_ax1.tick_params(colors='white')
        self.plugin_ax1.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
        plt.setp(self.plugin_ax1.xaxis.get_majorticklabels(), rotation=45, ha='right')
        
        # Host status distribution
        if not plugin_lifecycle.empty:
            status_counts = plugin_lifecycle['status'].value_counts()
            colors_status = {'Active': '#dc3545', 'Resolved': '#28a745'}
            self.plugin_ax2.pie(status_counts.values, labels=status_counts.index, autopct='%1.1f%%',
                               colors=[colors_status.get(s, 'gray') for s in status_counts.index], 
                               startangle=90)
            self.plugin_ax2.set_title(f'Status Distribution - Plugin {plugin_id}', fontsize=12, fontweight='bold', color='white')
        
        # Top affected hosts with hostname (IP) format
        if not plugin_lifecycle.empty:
            top_hosts = plugin_lifecycle.nlargest(10, 'days_open')[['hostname', 'ip_address', 'days_open']]
            display_names = [f"{row['hostname']} ({row['ip_address']})" for _, row in top_hosts.iterrows()]
            
            self.plugin_ax3.barh(range(len(top_hosts)), top_hosts['days_open'].values, color='#fd7e14')
            self.plugin_ax3.set_yticks(range(len(top_hosts)))
            self.plugin_ax3.set_yticklabels(display_names, color='white')
            self.plugin_ax3.set_title(f'Top 10 Hosts by Days Open - Plugin {plugin_id}', fontsize=12, fontweight='bold', color='white')
            self.plugin_ax3.set_xlabel('Days Open', color='white')
            self.plugin_ax3.grid(True, alpha=0.3, axis='x')
            self.plugin_ax3.tick_params(colors='white')
        
        # Reappearance statistics
        if not plugin_lifecycle.empty:
            reappeared = len(plugin_lifecycle[plugin_lifecycle['reappearances'] > 0])
            never_reappeared = len(plugin_lifecycle[plugin_lifecycle['reappearances'] == 0])
            bars = self.plugin_ax4.bar(['Reappeared', 'Never Reappeared'], [reappeared, never_reappeared],
                               color=['#dc3545', '#28a745'])
            self.plugin_ax4.set_title(f'Reappearance Statistics - Plugin {plugin_id}', fontsize=12, fontweight='bold', color='white')
            self.plugin_ax4.set_ylabel('Number of Hosts', color='white')
            self.plugin_ax4.grid(True, alpha=0.3, axis='y')
            self.plugin_ax4.tick_params(colors='white')
            
            # Add data labels on bars
            for bar in bars:
                height = bar.get_height()
                if height > 0:
                    self.plugin_ax4.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                            f'{int(height)}', ha='center', va='bottom', color='white', fontweight='bold')
        
        plt.tight_layout()
        plt.style.use('dark_background')
        self.plugin_canvas.draw()
        
    def create_lifecycle_viz(self):
        """Create lifecycle analysis visualization with dark theme"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Lifecycle Analysis")
        self.viz_frames['lifecycle'] = frame
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(14, 10))
        fig.patch.set_facecolor('#2b2b2b')
        
        # Distribution of days open
        if not self.lifecycle_df.empty:
            max_days = self.lifecycle_df['days_open'].max()
            
            # Create bins that are guaranteed to be monotonically increasing
            base_bins = [0, 30, 60, 90, 120, 180, 365]
            bins = [b for b in base_bins if b <= max_days]
            bins.append(max_days + 1)  # Always add max as the final bin
            
            # Create labels for the bins
            labels = []
            for i in range(len(bins) - 1):
                if i == len(bins) - 2:  # Last label
                    if bins[i] >= 365:
                        labels.append('365+')
                    else:
                        labels.append(f'{bins[i]}-{int(max_days)}')
                else:
                    labels.append(f'{bins[i]}-{bins[i+1]-1}')
            
            self.lifecycle_df['age_category'] = pd.cut(self.lifecycle_df['days_open'], 
                                                        bins=bins, labels=labels, right=False)
            age_dist = self.lifecycle_df['age_category'].value_counts().sort_index()
            
            bars = ax1.bar(range(len(age_dist)), age_dist.values, color='#007bff')
            ax1.set_xticks(range(len(age_dist)))
            ax1.set_xticklabels(age_dist.index, rotation=45, ha='right', color='white')
            ax1.set_title('Distribution of Finding Age (Days Open)', fontsize=12, fontweight='bold', color='white')
            ax1.set_ylabel('Number of Findings', color='white')
            ax1.grid(True, alpha=0.3, axis='y')
            ax1.set_facecolor('#2b2b2b')
            ax1.tick_params(colors='white')
            
            # Add data labels on bars
            for bar in bars:
                height = bar.get_height()
                if height > 0:
                    ax1.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                            f'{int(height)}', ha='center', va='bottom', color='white', fontweight='bold')
        
        # Top 15 most prevalent plugins
        if not self.lifecycle_df.empty:
            top_plugins = self.lifecycle_df['plugin_id'].value_counts().head(15)
            plugin_names = [self.lifecycle_df[self.lifecycle_df['plugin_id'] == pid]['plugin_name'].iloc[0][:30] 
                        for pid in top_plugins.index]
            
            bars = ax2.barh(range(len(top_plugins)), top_plugins.values, color='#dc3545')
            ax2.set_yticks(range(len(top_plugins)))
            ax2.set_yticklabels(plugin_names, color='white')
            ax2.set_title('Top 15 Most Prevalent Findings', fontsize=12, fontweight='bold', color='white')
            ax2.set_xlabel('Number of Affected Hosts', color='white')
            ax2.grid(True, alpha=0.3, axis='x')
            ax2.set_facecolor('#2b2b2b')
            ax2.tick_params(colors='white')
            
            # Add data labels on horizontal bars
            for bar in bars:
                width = bar.get_width()
                ax2.text(width + width*0.01, bar.get_y() + bar.get_height()/2.,
                        f'{int(width)}', ha='left', va='center', color='white', fontweight='bold')
        
        # Findings by first seen date
        if not self.lifecycle_df.empty:
            first_seen_timeline = self.lifecycle_df.groupby(
                self.lifecycle_df['first_seen'].dt.to_period('M')
            ).size().reset_index(name='count')
            first_seen_timeline['first_seen'] = first_seen_timeline['first_seen'].dt.to_timestamp()
            
            ax3.plot(first_seen_timeline['first_seen'], first_seen_timeline['count'], 
                    marker='o', linewidth=2, color='#28a745')
            ax3.set_title('New Findings by Month (First Seen)', fontsize=12, fontweight='bold', color='white')
            ax3.set_xlabel('Month', color='white')
            ax3.set_ylabel('New Findings', color='white')
            ax3.grid(True, alpha=0.3)
            ax3.set_facecolor('#2b2b2b')
            ax3.tick_params(colors='white')
            ax3.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m'))
            plt.setp(ax3.xaxis.get_majorticklabels(), rotation=45, ha='right')
        
        # Remediation effectiveness (resolved findings by severity)
        if not self.lifecycle_df.empty:
            resolved = self.lifecycle_df[self.lifecycle_df['status'] == 'Resolved']
            if not resolved.empty:
                remediation = resolved.groupby('severity_text').size().sort_values(ascending=True)
                colors_sev = {'Critical': '#dc3545', 'High': '#fd7e14', 'Medium': '#ffc107', 
                            'Low': '#007bff', 'Info': '#6c757d'}
                
                bars = ax4.barh(range(len(remediation)), remediation.values,
                        color=[colors_sev.get(s, 'gray') for s in remediation.index])
                ax4.set_yticks(range(len(remediation)))
                ax4.set_yticklabels(remediation.index, color='white')
                ax4.set_title('Resolved Findings by Severity', fontsize=12, fontweight='bold', color='white')
                ax4.set_xlabel('Number of Findings Resolved', color='white')
                ax4.grid(True, alpha=0.3, axis='x')
                ax4.set_facecolor('#2b2b2b')
                ax4.tick_params(colors='white')
                
                # Add data labels on horizontal bars
                for bar in bars:
                    width = bar.get_width()
                    ax4.text(width + width*0.01, bar.get_y() + bar.get_height()/2.,
                            f'{int(width)}', ha='left', va='center', color='white', fontweight='bold')
        
        plt.tight_layout()
        plt.style.use('dark_background')
        
        canvas = FigureCanvasTkAgg(fig, frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def create_opdir_viz(self):
        """Create OPDIR compliance and tracking visualization"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="OPDIR Compliance")
        self.viz_frames['opdir'] = frame
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(14, 10))
        fig.patch.set_facecolor('#2b2b2b')
        
        # OPDIR status distribution
        if not self.opdir_df.empty and 'status' in self.opdir_df.columns:
            status_counts = self.opdir_df['status'].value_counts()
            colors_opdir = {'On Track': '#28a745', 'Due Soon': '#ffc107', 'Overdue': '#dc3545', 'Unknown': '#6c757d'}
            opdir_colors = [colors_opdir.get(status, '#6c757d') for status in status_counts.index]
            
            ax1.pie(status_counts.values, labels=status_counts.index, autopct='%1.1f%%',
                   colors=opdir_colors, startangle=90)
            ax1.set_title('OPDIR Status Distribution', fontsize=12, fontweight='bold', color='white')
            ax1.set_facecolor('#2b2b2b')
        else:
            ax1.text(0.5, 0.5, 'No OPDIR data available', ha='center', va='center', 
                    transform=ax1.transAxes, color='white', fontsize=12)
            ax1.set_facecolor('#2b2b2b')
        
        # Finding to OPDIR mapping rate
        if not self.lifecycle_df.empty:
            total_findings = len(self.lifecycle_df)
            opdir_mapped = len(self.lifecycle_df[self.lifecycle_df.get('opdir_number', '') != ''])
            unmapped = total_findings - opdir_mapped
            
            bars = ax2.bar(['OPDIR Mapped', 'Not Mapped'], [opdir_mapped, unmapped], 
                          color=['#28a745', '#dc3545'])
            ax2.set_title('Finding OPDIR Mapping Coverage', fontsize=12, fontweight='bold', color='white')
            ax2.set_ylabel('Number of Findings', color='white')
            ax2.grid(True, alpha=0.3, axis='y')
            ax2.set_facecolor('#2b2b2b')
            ax2.tick_params(colors='white')
            
            # Add data labels on bars
            for bar in bars:
                height = bar.get_height()
                percentage = (height / total_findings) * 100
                ax2.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                        f'{int(height)}\n({percentage:.1f}%)', ha='center', va='bottom', 
                        color='white', fontweight='bold')
        
        # OPDIR compliance by severity
        if not self.lifecycle_df.empty and 'opdir_status' in self.lifecycle_df.columns:
            opdir_findings = self.lifecycle_df[self.lifecycle_df['opdir_number'] != '']
            if not opdir_findings.empty:
                compliance_by_severity = opdir_findings.groupby(['severity_text', 'opdir_status']).size().unstack(fill_value=0)
                
                if not compliance_by_severity.empty:
                    compliance_by_severity.plot(kind='bar', stacked=True, ax=ax3, 
                                              color=['#28a745', '#ffc107', '#dc3545', '#6c757d'])
                    ax3.set_title('OPDIR Compliance by Severity', fontsize=12, fontweight='bold', color='white')
                    ax3.set_xlabel('Severity', color='white')
                    ax3.set_ylabel('Number of Findings', color='white')
                    ax3.legend(loc='upper right')
                    ax3.grid(True, alpha=0.3, axis='y')
                    ax3.set_facecolor('#2b2b2b')
                    ax3.tick_params(colors='white')
                    plt.setp(ax3.xaxis.get_majorticklabels(), rotation=45, ha='right')
        
        if ax3.get_title() == '':  # If no compliance data plotted
            ax3.text(0.5, 0.5, 'No OPDIR compliance data available', ha='center', va='center', 
                    transform=ax3.transAxes, color='white', fontsize=12)
            ax3.set_facecolor('#2b2b2b')
        
        # High-risk OPDIR findings (Critical/High + Overdue)
        if not self.lifecycle_df.empty and 'opdir_status' in self.lifecycle_df.columns:
            high_severity = self.lifecycle_df[self.lifecycle_df['severity_text'].isin(['Critical', 'High'])]
            opdir_high_sev = high_severity[high_severity['opdir_number'] != '']
            
            if not opdir_high_sev.empty:
                risk_data = {
                    'On Track': len(opdir_high_sev[opdir_high_sev['opdir_status'] == 'On Track']),
                    'Due Soon': len(opdir_high_sev[opdir_high_sev['opdir_status'] == 'Due Soon']),
                    'Overdue': len(opdir_high_sev[opdir_high_sev['opdir_status'] == 'Overdue'])
                }
                
                # Filter out zero values
                risk_data = {k: v for k, v in risk_data.items() if v > 0}
                
                if risk_data:
                    colors_risk = {'On Track': '#28a745', 'Due Soon': '#ffc107', 'Overdue': '#dc3545'}
                    ax4.pie(risk_data.values(), labels=risk_data.keys(), autopct='%1.1f%%',
                           colors=[colors_risk.get(k, '#6c757d') for k in risk_data.keys()], 
                           startangle=90)
                    ax4.set_title('High-Risk Findings\n(Critical/High + OPDIR Status)', 
                                 fontsize=12, fontweight='bold', color='white')
                    ax4.set_facecolor('#2b2b2b')
                else:
                    ax4.text(0.5, 0.5, 'No high-risk OPDIR findings', ha='center', va='center', 
                            transform=ax4.transAxes, color='white', fontsize=12)
                    ax4.set_facecolor('#2b2b2b')
            else:
                ax4.text(0.5, 0.5, 'No high-severity OPDIR findings', ha='center', va='center', 
                        transform=ax4.transAxes, color='white', fontsize=12)
                ax4.set_facecolor('#2b2b2b')
        else:
            ax4.text(0.5, 0.5, 'No OPDIR compliance data', ha='center', va='center', 
                    transform=ax4.transAxes, color='white', fontsize=12)
            ax4.set_facecolor('#2b2b2b')
        
        plt.tight_layout()
        plt.style.use('dark_background')
        
        canvas = FigureCanvasTkAgg(fig, frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def export_excel(self):
        """Export to Excel with enhanced data including OPDIR"""
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
                               self.host_presence_df, self.scan_changes_df, filepath)
                self.log("Excel export complete!")
                messagebox.showinfo("Success", f"Enhanced data exported to:\n{filepath}")
            except Exception as e:
                self.log(f"ERROR: {str(e)}")
                messagebox.showerror("Error", f"Export failed: {str(e)}")
    
    def export_sqlite(self):
        """Export to SQLite with enhanced data including OPDIR"""
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
                self.log(f"Exporting to SQLite with OPDIR data: {filepath}")
                export_opdir_enhanced_sqlite(self.historical_df, self.lifecycle_df, 
                                           self.host_presence_df, self.scan_changes_df, 
                                           self.opdir_df, filepath)
                self.log("SQLite export complete!")
                messagebox.showinfo("Success", f"Enhanced database with OPDIR exported to:\n{filepath}")
            except Exception as e:
                self.log(f"ERROR: {str(e)}")
                messagebox.showerror("Error", f"Export failed: {str(e)}")
    
    def export_json(self):
        """Export to JSON with enhanced data"""
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
                messagebox.showinfo("Success", f"Enhanced data exported to:\n{filepath}")
            except Exception as e:
                self.log(f"ERROR: {str(e)}")
                messagebox.showerror("Error", f"Export failed: {str(e)}")
    
    def export_schema(self):
        """Export JSON schema"""
        filepath = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Save JSON Schema File"
        )
        
        if filepath:
            try:
                self.log(f"Exporting JSON schema: {filepath}")
                export_json_schema(filepath)
                self.log("JSON schema export complete!")
                messagebox.showinfo("Success", f"JSON schema exported to:\n{filepath}")
            except Exception as e:
                self.log(f"ERROR: {str(e)}")
                messagebox.showerror("Error", f"Schema export failed: {str(e)}")
    
    def run(self):
        """Run the enhanced GUI"""
        self.window.mainloop()


def main():
    """Main entry point for the enhanced application"""
    app = EnhancedHistoricalAnalysisGUI()
    app.run()


if __name__ == "__main__":
    main()