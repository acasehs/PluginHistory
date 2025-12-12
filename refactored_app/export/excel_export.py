"""
Excel Export Module
Functions for exporting data to Excel workbooks with formatting.
"""

import pandas as pd
from datetime import datetime
from typing import Dict, List, Optional, Any

from ..config import EXCEL_MAX_COLUMN_WIDTH, SEVERITY_COLORS


def export_to_excel(historical_df: pd.DataFrame,
                   lifecycle_df: pd.DataFrame,
                   host_presence_df: pd.DataFrame,
                   scan_changes_df: pd.DataFrame,
                   opdir_df: pd.DataFrame,
                   filepath: str,
                   include_summary: bool = True) -> bool:
    """
    Export all analysis data to an Excel workbook.

    Args:
        historical_df: DataFrame with historical findings
        lifecycle_df: DataFrame from analyze_finding_lifecycle
        host_presence_df: DataFrame from create_host_presence_analysis
        scan_changes_df: DataFrame from analyze_scan_changes
        opdir_df: DataFrame with OPDIR mapping data
        filepath: Output Excel file path
        include_summary: Whether to include a summary sheet

    Returns:
        True if successful
    """
    try:
        with pd.ExcelWriter(filepath, engine='openpyxl') as writer:
            # Summary sheet
            if include_summary:
                summary_data = create_summary_data(historical_df, lifecycle_df, host_presence_df)
                summary_df = pd.DataFrame([summary_data])
                summary_df.to_excel(writer, sheet_name='Summary', index=False)

            # Main data sheets
            if not lifecycle_df.empty:
                lifecycle_df.to_excel(writer, sheet_name='Finding_Lifecycle', index=False)

            if not host_presence_df.empty:
                host_presence_df.to_excel(writer, sheet_name='Host_Presence', index=False)

            if not scan_changes_df.empty:
                scan_changes_df.to_excel(writer, sheet_name='Scan_Changes', index=False)

            if not historical_df.empty:
                # Limit historical data to most recent scan to avoid huge files
                historical_df_copy = historical_df.copy()
                if 'scan_date' in historical_df_copy.columns:
                    historical_df_copy['scan_date'] = pd.to_datetime(historical_df_copy['scan_date'])
                    latest_scan = historical_df_copy['scan_date'].max()
                    latest_data = historical_df_copy[historical_df_copy['scan_date'] == latest_scan]
                    latest_data.to_excel(writer, sheet_name='Latest_Findings', index=False)

                    # Also include all historical data (may be large)
                    if len(historical_df) <= 100000:
                        historical_df.to_excel(writer, sheet_name='All_Historical', index=False)
                else:
                    historical_df.to_excel(writer, sheet_name='Findings', index=False)

            if not opdir_df.empty:
                opdir_df.to_excel(writer, sheet_name='OPDIR_Mapping', index=False)

            # Severity breakdown
            if not historical_df.empty and 'severity_text' in historical_df.columns:
                severity_summary = create_severity_pivot(historical_df)
                if not severity_summary.empty:
                    severity_summary.to_excel(writer, sheet_name='Severity_Summary', index=False)

            # Auto-fit columns
            for sheet_name in writer.sheets:
                auto_fit_columns(writer.sheets[sheet_name])

        print(f"Excel workbook exported to: {filepath}")
        return True

    except Exception as e:
        print(f"Error exporting to Excel: {e}")
        import traceback
        traceback.print_exc()
        return False


def create_formatted_workbook(data_dict: Dict[str, pd.DataFrame],
                             filepath: str,
                             freeze_panes: bool = True) -> bool:
    """
    Create a formatted Excel workbook from multiple DataFrames.

    Args:
        data_dict: Dictionary mapping sheet names to DataFrames
        filepath: Output file path
        freeze_panes: Whether to freeze the header row

    Returns:
        True if successful
    """
    try:
        with pd.ExcelWriter(filepath, engine='openpyxl') as writer:
            for sheet_name, df in data_dict.items():
                if df.empty:
                    continue

                # Sanitize sheet name
                safe_name = sanitize_sheet_name(sheet_name)
                df.to_excel(writer, sheet_name=safe_name, index=False)

                # Get worksheet
                worksheet = writer.sheets[safe_name]

                # Freeze panes
                if freeze_panes:
                    worksheet.freeze_panes = 'A2'

                # Auto-fit columns
                auto_fit_columns(worksheet)

        print(f"Formatted workbook created: {filepath}")
        return True

    except Exception as e:
        print(f"Error creating workbook: {e}")
        return False


def auto_fit_columns(worksheet) -> None:
    """
    Auto-fit column widths in an openpyxl worksheet.

    Args:
        worksheet: openpyxl worksheet object
    """
    for column in worksheet.columns:
        max_length = 0
        column_letter = column[0].column_letter

        for cell in column:
            try:
                if cell.value:
                    cell_length = len(str(cell.value))
                    if cell_length > max_length:
                        max_length = cell_length
            except:
                pass

        adjusted_width = min(max_length + 2, EXCEL_MAX_COLUMN_WIDTH)
        worksheet.column_dimensions[column_letter].width = adjusted_width


def sanitize_sheet_name(name: str) -> str:
    """
    Sanitize a string for use as Excel sheet name.

    Args:
        name: Original sheet name

    Returns:
        Sanitized sheet name
    """
    # Remove invalid characters
    invalid_chars = ['\\', '/', '*', '[', ']', ':', '?']
    for char in invalid_chars:
        name = name.replace(char, '_')

    # Truncate to 31 characters (Excel limit)
    if len(name) > 31:
        name = name[:28] + '...'

    return name


def create_summary_data(historical_df: pd.DataFrame,
                       lifecycle_df: pd.DataFrame,
                       host_presence_df: pd.DataFrame) -> Dict[str, Any]:
    """
    Create summary data for the summary sheet.

    Args:
        historical_df: DataFrame with historical findings
        lifecycle_df: DataFrame from analyze_finding_lifecycle
        host_presence_df: DataFrame from create_host_presence_analysis

    Returns:
        Dictionary with summary metrics
    """
    summary = {
        'Report Generated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'Total Historical Findings': len(historical_df),
        'Unique Hosts': historical_df['hostname'].nunique() if 'hostname' in historical_df.columns else 0,
        'Unique Plugins': historical_df['plugin_id'].nunique() if 'plugin_id' in historical_df.columns else 0,
    }

    if not lifecycle_df.empty:
        summary['Active Findings'] = len(lifecycle_df[lifecycle_df['status'] == 'Active'])
        summary['Resolved Findings'] = len(lifecycle_df[lifecycle_df['status'] == 'Resolved'])
        summary['Reappearing Findings'] = len(lifecycle_df[lifecycle_df['reappearances'] > 0])

        active = lifecycle_df[lifecycle_df['status'] == 'Active']
        if not active.empty:
            summary['Avg Days Open (Active)'] = round(active['days_open'].mean(), 1)

    if not host_presence_df.empty:
        summary['Active Hosts'] = len(host_presence_df[host_presence_df['status'] == 'Active'])
        summary['Missing Hosts'] = len(host_presence_df[host_presence_df['status'] == 'Missing'])
        summary['Avg Host Presence %'] = round(host_presence_df['presence_percentage'].mean(), 1)

    # Severity breakdown
    if not historical_df.empty and 'severity_text' in historical_df.columns:
        historical_df_copy = historical_df.copy()
        if 'scan_date' in historical_df_copy.columns:
            historical_df_copy['scan_date'] = pd.to_datetime(historical_df_copy['scan_date'])
            latest = historical_df_copy[historical_df_copy['scan_date'] == historical_df_copy['scan_date'].max()]
        else:
            latest = historical_df_copy

        severity_counts = latest['severity_text'].value_counts().to_dict()
        for severity, count in severity_counts.items():
            summary[f'{severity} Findings'] = count

    return summary


def create_severity_pivot(historical_df: pd.DataFrame) -> pd.DataFrame:
    """
    Create a severity summary pivot table.

    Args:
        historical_df: DataFrame with historical findings

    Returns:
        DataFrame with severity summary
    """
    if historical_df.empty or 'severity_text' not in historical_df.columns:
        return pd.DataFrame()

    # Get latest scan data
    historical_df = historical_df.copy()
    if 'scan_date' in historical_df.columns:
        historical_df['scan_date'] = pd.to_datetime(historical_df['scan_date'])
        latest = historical_df[historical_df['scan_date'] == historical_df['scan_date'].max()]
    else:
        latest = historical_df

    if 'hostname' in latest.columns:
        pivot = pd.crosstab(latest['hostname'], latest['severity_text'], margins=True, margins_name='Total')
        return pivot.reset_index()

    return latest['severity_text'].value_counts().reset_index()
