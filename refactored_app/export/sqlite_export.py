"""
SQLite Export Module
Functions for exporting data to SQLite databases.
"""

import sqlite3
import pandas as pd
from datetime import datetime
from typing import Dict, List, Optional, Any

from ..config import SQLITE_INDEXES


def export_to_sqlite(historical_df: pd.DataFrame,
                    lifecycle_df: pd.DataFrame,
                    host_presence_df: pd.DataFrame,
                    scan_changes_df: pd.DataFrame,
                    opdir_df: pd.DataFrame,
                    filepath: str) -> bool:
    """
    Export all analysis data to a SQLite database.

    Args:
        historical_df: DataFrame with historical findings
        lifecycle_df: DataFrame from analyze_finding_lifecycle
        host_presence_df: DataFrame from create_host_presence_analysis
        scan_changes_df: DataFrame from analyze_scan_changes
        opdir_df: DataFrame with OPDIR mapping data
        filepath: Output database file path

    Returns:
        True if successful
    """
    try:
        conn = sqlite3.connect(filepath)

        # Convert datetime columns to string for SQLite compatibility
        def prepare_df(df):
            if df.empty:
                return df
            df = df.copy()
            for col in df.columns:
                if pd.api.types.is_datetime64_any_dtype(df[col]):
                    df[col] = df[col].dt.strftime('%Y-%m-%d %H:%M:%S')
            return df

        # Export each DataFrame
        if not historical_df.empty:
            prepare_df(historical_df).to_sql('historical_findings', conn, if_exists='replace', index=False)
            print(f"Exported {len(historical_df)} rows to historical_findings")

        if not lifecycle_df.empty:
            prepare_df(lifecycle_df).to_sql('finding_lifecycle', conn, if_exists='replace', index=False)
            print(f"Exported {len(lifecycle_df)} rows to finding_lifecycle")

        if not host_presence_df.empty:
            prepare_df(host_presence_df).to_sql('host_presence', conn, if_exists='replace', index=False)
            print(f"Exported {len(host_presence_df)} rows to host_presence")

        if not scan_changes_df.empty:
            prepare_df(scan_changes_df).to_sql('scan_changes', conn, if_exists='replace', index=False)
            print(f"Exported {len(scan_changes_df)} rows to scan_changes")

        if not opdir_df.empty:
            prepare_df(opdir_df).to_sql('opdir_mapping', conn, if_exists='replace', index=False)
            print(f"Exported {len(opdir_df)} rows to opdir_mapping")

        # Create summary table
        summary_data = {
            'export_timestamp': [datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
            'total_historical_findings': [len(historical_df)],
            'total_lifecycle_records': [len(lifecycle_df)],
            'total_hosts': [len(host_presence_df)],
            'total_scans': [len(scan_changes_df) + 1 if not scan_changes_df.empty else 0]
        }
        pd.DataFrame(summary_data).to_sql('export_summary', conn, if_exists='replace', index=False)

        # Add indexes
        add_indexes_to_database(conn)

        conn.close()
        print(f"SQLite database exported to: {filepath}")
        return True

    except Exception as e:
        print(f"Error exporting to SQLite: {e}")
        import traceback
        traceback.print_exc()
        return False


def create_sqlite_database(filepath: str) -> sqlite3.Connection:
    """
    Create a new SQLite database with the required schema.

    Args:
        filepath: Database file path

    Returns:
        Database connection object
    """
    conn = sqlite3.connect(filepath)
    cursor = conn.cursor()

    # Create tables with proper schema
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS historical_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            plugin_id TEXT,
            hostname TEXT,
            ip_address TEXT,
            scan_date TEXT,
            scan_file TEXT,
            name TEXT,
            family TEXT,
            severity_text TEXT,
            severity_value INTEGER,
            cvss3_base_score REAL,
            cvss2_base_score REAL,
            cves TEXT,
            iavx TEXT,
            description TEXT,
            solution TEXT,
            output TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS finding_lifecycle (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname TEXT,
            ip_address TEXT,
            plugin_id TEXT,
            plugin_name TEXT,
            severity_text TEXT,
            severity_value INTEGER,
            first_seen TEXT,
            last_seen TEXT,
            days_open INTEGER,
            total_observations INTEGER,
            reappearances INTEGER,
            status TEXT,
            cvss3_base_score REAL,
            cves TEXT,
            iavx TEXT,
            opdir_number TEXT,
            opdir_status TEXT,
            opdir_days_until_due INTEGER
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS host_presence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname TEXT,
            ip_address TEXT,
            first_seen TEXT,
            last_seen TEXT,
            total_scans_available INTEGER,
            scans_present INTEGER,
            scans_missing INTEGER,
            presence_percentage REAL,
            status TEXT,
            missing_scan_dates TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_changes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_date TEXT,
            previous_scan TEXT,
            hosts_added INTEGER,
            hosts_removed INTEGER,
            hosts_unchanged INTEGER,
            total_hosts_current INTEGER,
            total_hosts_previous INTEGER,
            net_change INTEGER
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS opdir_mapping (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            opdir_number TEXT,
            opdir_subject TEXT,
            opdir_release_date TEXT,
            opdir_final_due_date TEXT,
            opdir_days_to_remediate INTEGER
        )
    ''')

    conn.commit()
    return conn


def add_indexes_to_database(conn: sqlite3.Connection) -> None:
    """
    Add performance indexes to the database.

    Args:
        conn: Database connection
    """
    cursor = conn.cursor()

    for table, columns in SQLITE_INDEXES.items():
        for column in columns:
            try:
                index_name = f"idx_{table}_{column}"
                cursor.execute(f"CREATE INDEX IF NOT EXISTS {index_name} ON {table}({column})")
            except Exception as e:
                print(f"Warning: Could not create index {index_name}: {e}")

    conn.commit()


def load_from_sqlite(filepath: str) -> Dict[str, pd.DataFrame]:
    """
    Load all tables from a SQLite database.

    Args:
        filepath: Database file path

    Returns:
        Dictionary mapping table names to DataFrames
    """
    conn = sqlite3.connect(filepath)

    tables = {}

    # Get list of tables
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    table_names = [row[0] for row in cursor.fetchall()]

    for table_name in table_names:
        try:
            df = pd.read_sql_query(f"SELECT * FROM {table_name}", conn)

            # Convert date columns back to datetime
            for col in df.columns:
                if 'date' in col.lower() or col in ['first_seen', 'last_seen']:
                    df[col] = pd.to_datetime(df[col], errors='coerce')

            tables[table_name] = df
            print(f"Loaded {len(df)} rows from {table_name}")

        except Exception as e:
            print(f"Error loading table {table_name}: {e}")

    conn.close()
    return tables


def query_database(filepath: str, query: str) -> pd.DataFrame:
    """
    Execute a custom SQL query on the database.

    Args:
        filepath: Database file path
        query: SQL query string

    Returns:
        DataFrame with query results
    """
    conn = sqlite3.connect(filepath)
    try:
        df = pd.read_sql_query(query, conn)
        return df
    except Exception as e:
        print(f"Error executing query: {e}")
        return pd.DataFrame()
    finally:
        conn.close()
