"""
JSON Export Module
Functions for exporting data to JSON format.
"""

import json
import pandas as pd
from datetime import datetime
from typing import Dict, List, Optional, Any


class DateTimeEncoder(json.JSONEncoder):
    """Custom JSON encoder for datetime objects."""

    def default(self, obj):
        if isinstance(obj, (datetime, pd.Timestamp)):
            return obj.isoformat()
        if pd.isna(obj):
            return None
        return super().default(obj)


def export_to_json(historical_df: pd.DataFrame,
                  lifecycle_df: pd.DataFrame,
                  host_presence_df: pd.DataFrame,
                  scan_changes_df: pd.DataFrame,
                  filepath: str,
                  include_metadata: bool = True) -> bool:
    """
    Export all analysis data to a JSON file.

    Args:
        historical_df: DataFrame with historical findings
        lifecycle_df: DataFrame from analyze_finding_lifecycle
        host_presence_df: DataFrame from create_host_presence_analysis
        scan_changes_df: DataFrame from analyze_scan_changes
        filepath: Output JSON file path
        include_metadata: Whether to include export metadata

    Returns:
        True if successful
    """
    try:
        export_data = {}

        if include_metadata:
            export_data['metadata'] = {
                'export_timestamp': datetime.now().isoformat(),
                'version': '2.0',
                'record_counts': {
                    'historical_findings': len(historical_df),
                    'lifecycle_records': len(lifecycle_df),
                    'host_presence_records': len(host_presence_df),
                    'scan_changes_records': len(scan_changes_df)
                }
            }

        # Convert DataFrames to records, handling NaN values
        def df_to_records(df):
            if df.empty:
                return []
            df = df.copy()

            # Convert datetime columns
            for col in df.columns:
                if pd.api.types.is_datetime64_any_dtype(df[col]):
                    df[col] = df[col].dt.strftime('%Y-%m-%dT%H:%M:%S')

            # Replace NaN with None
            df = df.where(pd.notnull(df), None)

            return df.to_dict('records')

        export_data['historical_findings'] = df_to_records(historical_df)
        export_data['finding_lifecycle'] = df_to_records(lifecycle_df)
        export_data['host_presence'] = df_to_records(host_presence_df)
        export_data['scan_changes'] = df_to_records(scan_changes_df)

        # Add summary statistics
        if not lifecycle_df.empty:
            export_data['summary'] = {
                'active_findings': len(lifecycle_df[lifecycle_df['status'] == 'Active']),
                'resolved_findings': len(lifecycle_df[lifecycle_df['status'] == 'Resolved']),
                'unique_hosts': lifecycle_df['hostname'].nunique(),
                'unique_plugins': lifecycle_df['plugin_id'].nunique()
            }

            if 'severity_text' in lifecycle_df.columns:
                export_data['summary']['severity_breakdown'] = lifecycle_df['severity_text'].value_counts().to_dict()

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, cls=DateTimeEncoder)

        print(f"JSON exported to: {filepath}")
        return True

    except Exception as e:
        print(f"Error exporting to JSON: {e}")
        import traceback
        traceback.print_exc()
        return False


def export_to_json_lines(df: pd.DataFrame, filepath: str) -> bool:
    """
    Export DataFrame to JSON Lines format (one JSON object per line).

    Useful for large datasets that need to be processed line by line.

    Args:
        df: DataFrame to export
        filepath: Output file path

    Returns:
        True if successful
    """
    try:
        df = df.copy()

        # Convert datetime columns
        for col in df.columns:
            if pd.api.types.is_datetime64_any_dtype(df[col]):
                df[col] = df[col].dt.strftime('%Y-%m-%dT%H:%M:%S')

        # Replace NaN with None
        df = df.where(pd.notnull(df), None)

        with open(filepath, 'w', encoding='utf-8') as f:
            for _, row in df.iterrows():
                json.dump(row.to_dict(), f, cls=DateTimeEncoder)
                f.write('\n')

        print(f"JSON Lines exported to: {filepath}")
        return True

    except Exception as e:
        print(f"Error exporting to JSON Lines: {e}")
        return False


def load_from_json(filepath: str) -> Dict[str, Any]:
    """
    Load data from a JSON export file.

    Args:
        filepath: JSON file path

    Returns:
        Dictionary with loaded data
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Convert lists back to DataFrames
        result = {}

        for key in ['historical_findings', 'finding_lifecycle', 'host_presence', 'scan_changes']:
            if key in data and data[key]:
                df = pd.DataFrame(data[key])

                # Convert date columns
                date_columns = ['scan_date', 'first_seen', 'last_seen',
                               'opdir_release_date', 'opdir_final_due_date']
                for col in date_columns:
                    if col in df.columns:
                        df[col] = pd.to_datetime(df[col], errors='coerce')

                result[key] = df
            else:
                result[key] = pd.DataFrame()

        if 'metadata' in data:
            result['metadata'] = data['metadata']

        if 'summary' in data:
            result['summary'] = data['summary']

        return result

    except Exception as e:
        print(f"Error loading JSON: {e}")
        return {}


def export_findings_summary(historical_df: pd.DataFrame, filepath: str) -> bool:
    """
    Export a compact summary of findings.

    Args:
        historical_df: DataFrame with historical findings
        filepath: Output file path

    Returns:
        True if successful
    """
    if historical_df.empty:
        return False

    try:
        historical_df = historical_df.copy()
        if 'scan_date' in historical_df.columns:
            historical_df['scan_date'] = pd.to_datetime(historical_df['scan_date'])
            latest = historical_df[historical_df['scan_date'] == historical_df['scan_date'].max()]
        else:
            latest = historical_df

        summary = {
            'export_date': datetime.now().isoformat(),
            'total_findings': len(latest),
            'unique_hosts': latest['hostname'].nunique() if 'hostname' in latest.columns else 0,
            'unique_plugins': latest['plugin_id'].nunique() if 'plugin_id' in latest.columns else 0,
            'severity_breakdown': latest['severity_text'].value_counts().to_dict() if 'severity_text' in latest.columns else {},
            'top_plugins': [],
            'top_hosts': []
        }

        # Top plugins
        if 'plugin_id' in latest.columns and 'name' in latest.columns:
            top_plugins = latest.groupby(['plugin_id', 'name']).size().nlargest(10).reset_index(name='count')
            summary['top_plugins'] = top_plugins.to_dict('records')

        # Top hosts
        if 'hostname' in latest.columns:
            top_hosts = latest.groupby('hostname').size().nlargest(10).reset_index(name='finding_count')
            summary['top_hosts'] = top_hosts.to_dict('records')

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2)

        print(f"Summary exported to: {filepath}")
        return True

    except Exception as e:
        print(f"Error exporting summary: {e}")
        return False
