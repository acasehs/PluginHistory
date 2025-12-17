"""
SQLite Export Module
Functions for exporting data to SQLite databases.
"""

import sqlite3
import pandas as pd
from datetime import datetime
from typing import Dict, List, Optional, Any

from ..config import SQLITE_INDEXES


def migrate_database_schema(conn: sqlite3.Connection) -> List[str]:
    """
    Migrate database schema to add new columns if they don't exist.

    Args:
        conn: SQLite connection object

    Returns:
        List of migration messages
    """
    migrations = []
    cursor = conn.cursor()

    # Define columns to add to each table
    schema_updates = {
        'historical_findings': [
            ('source_file', 'TEXT'),
        ],
        'finding_lifecycle': [
            ('source_files', 'TEXT'),
        ],
        'info_findings': [
            ('source_file', 'TEXT'),
        ],
    }

    for table_name, columns in schema_updates.items():
        # Check if table exists
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (table_name,)
        )
        if not cursor.fetchone():
            continue  # Table doesn't exist, will be created with proper schema

        # Get existing columns
        cursor.execute(f"PRAGMA table_info({table_name})")
        existing_cols = {row[1] for row in cursor.fetchall()}

        # Add missing columns
        for col_name, col_type in columns:
            if col_name not in existing_cols:
                try:
                    cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_type}")
                    migrations.append(f"Added column '{col_name}' to table '{table_name}'")
                except sqlite3.OperationalError as e:
                    migrations.append(f"Failed to add '{col_name}' to '{table_name}': {e}")

    conn.commit()
    return migrations


def export_to_sqlite(historical_df: pd.DataFrame,
                    lifecycle_df: pd.DataFrame,
                    host_presence_df: pd.DataFrame,
                    scan_changes_df: pd.DataFrame,
                    opdir_df: pd.DataFrame,
                    filepath: str,
                    iavm_df: pd.DataFrame = None,
                    stig_df: pd.DataFrame = None,
                    poam_df: pd.DataFrame = None,
                    host_overrides: Dict[str, Any] = None) -> bool:
    """
    Export all analysis data to a SQLite database.

    Args:
        historical_df: DataFrame with historical findings
        lifecycle_df: DataFrame from analyze_finding_lifecycle
        host_presence_df: DataFrame from create_host_presence_analysis
        scan_changes_df: DataFrame from analyze_scan_changes
        opdir_df: DataFrame with OPDIR mapping data
        filepath: Output database file path
        iavm_df: DataFrame with IAVM notice summaries (optional)
        stig_df: DataFrame with STIG checklist findings (optional)
        poam_df: DataFrame with POAM entries (optional)
        host_overrides: Dict of hostname -> override properties (optional)

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
            # Remove duplicate columns (keep first occurrence)
            df = df.loc[:, ~df.columns.duplicated()]
            for col in df.columns:
                if pd.api.types.is_datetime64_any_dtype(df[col]):
                    df[col] = df[col].dt.strftime('%Y-%m-%d %H:%M:%S')
            return df

        # Filter out Info findings from historical data (saved separately to yearly DBs)
        info_excluded_count = 0
        if not historical_df.empty and 'severity_text' in historical_df.columns:
            info_excluded_count = len(historical_df[historical_df['severity_text'] == 'Info'])
            historical_df_export = historical_df[historical_df['severity_text'] != 'Info']
        else:
            historical_df_export = historical_df

        # Filter out Info from lifecycle data as well
        if not lifecycle_df.empty and 'severity_text' in lifecycle_df.columns:
            lifecycle_df_export = lifecycle_df[lifecycle_df['severity_text'] != 'Info']
        else:
            lifecycle_df_export = lifecycle_df

        # Export each DataFrame
        if not historical_df_export.empty:
            prepare_df(historical_df_export).to_sql('historical_findings', conn, if_exists='replace', index=False)
            print(f"Exported {len(historical_df_export)} rows to historical_findings (excluded {info_excluded_count} Info)")
        elif not historical_df.empty:
            # Original had data but all was Info
            prepare_df(historical_df_export).to_sql('historical_findings', conn, if_exists='replace', index=False)
            print(f"Exported 0 rows to historical_findings (excluded {info_excluded_count} Info)")

        if not lifecycle_df_export.empty:
            prepare_df(lifecycle_df_export).to_sql('finding_lifecycle', conn, if_exists='replace', index=False)
            print(f"Exported {len(lifecycle_df_export)} rows to finding_lifecycle")

        if not host_presence_df.empty:
            prepare_df(host_presence_df).to_sql('host_presence', conn, if_exists='replace', index=False)
            print(f"Exported {len(host_presence_df)} rows to host_presence")

        if not scan_changes_df.empty:
            prepare_df(scan_changes_df).to_sql('scan_changes', conn, if_exists='replace', index=False)
            print(f"Exported {len(scan_changes_df)} rows to scan_changes")

        if not opdir_df.empty:
            prepare_df(opdir_df).to_sql('opdir_mapping', conn, if_exists='replace', index=False)
            print(f"Exported {len(opdir_df)} rows to opdir_mapping")

        # Export IAVM notices if provided
        if iavm_df is not None and not iavm_df.empty:
            prepare_df(iavm_df).to_sql('iavm_notices', conn, if_exists='replace', index=False)
            print(f"Exported {len(iavm_df)} rows to iavm_notices")

        # Export STIG findings if provided
        if stig_df is not None and not stig_df.empty:
            prepare_df(stig_df).to_sql('stig_findings', conn, if_exists='replace', index=False)
            print(f"Exported {len(stig_df)} rows to stig_findings")

        # Export POAM entries if provided
        if poam_df is not None and not poam_df.empty:
            prepare_df(poam_df).to_sql('poam_entries', conn, if_exists='replace', index=False)
            print(f"Exported {len(poam_df)} rows to poam_entries")

        # Export host overrides if provided
        if host_overrides:
            override_rows = []
            for hostname, overrides in host_overrides.items():
                override_rows.append({
                    'hostname': hostname,
                    'host_type': overrides.get('host_type', ''),
                    'environment': overrides.get('environment', ''),
                    'location': overrides.get('location', ''),
                    'notes': overrides.get('notes', ''),
                    'override_date': overrides.get('override_date', '')
                })
            if override_rows:
                overrides_df = pd.DataFrame(override_rows)
                overrides_df.to_sql('host_overrides', conn, if_exists='replace', index=False)
                print(f"Exported {len(overrides_df)} rows to host_overrides")

        # Create summary table (counts exclude Info findings)
        summary_data = {
            'export_timestamp': [datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
            'total_historical_findings': [len(historical_df_export)],
            'total_lifecycle_records': [len(lifecycle_df_export)],
            'total_hosts': [len(host_presence_df)],
            'total_scans': [len(scan_changes_df) + 1 if not scan_changes_df.empty else 0],
            'total_opdir_entries': [len(opdir_df) if not opdir_df.empty else 0],
            'total_iavm_notices': [len(iavm_df) if iavm_df is not None and not iavm_df.empty else 0],
            'total_stig_findings': [len(stig_df) if stig_df is not None and not stig_df.empty else 0],
            'total_poam_entries': [len(poam_df) if poam_df is not None and not poam_df.empty else 0],
            'total_host_overrides': [len(host_overrides) if host_overrides else 0],
            'info_findings_excluded': [info_excluded_count]
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

    # Migrate existing database schema to add new columns
    migrations = migrate_database_schema(conn)
    if migrations:
        for msg in migrations:
            print(f"Schema migration: {msg}")

    # Create tables with proper schema
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS historical_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            plugin_id TEXT,
            hostname TEXT,
            ip_address TEXT,
            scan_date TEXT,
            scan_file TEXT,
            source_file TEXT,
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
            opdir_days_until_due INTEGER,
            source_files TEXT
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
            opdir_number_raw TEXT,
            opdir_year INTEGER,
            subject TEXT,
            iavab TEXT,
            iavab_full TEXT,
            iavab_suffix TEXT,
            poam_due_date TEXT,
            final_due_date TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS iavm_notices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            iavm_number TEXT,
            iavm_number_normalized TEXT,
            iavm_year INTEGER,
            iavm_type TEXT,
            stig_severity TEXT,
            stig_severity_normalized TEXT,
            stig_severity_value INTEGER,
            state TEXT,
            status TEXT,
            supersedes TEXT,
            superseded_by TEXT,
            title TEXT,
            last_saved TEXT,
            released_date TEXT,
            acknowledged_date TEXT,
            first_report_date TEXT,
            mitigation_date TEXT
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

    # Get existing tables and their columns
    table_columns = {}
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    for (table_name,) in cursor.fetchall():
        cursor.execute(f"PRAGMA table_info({table_name})")
        table_columns[table_name] = {row[1] for row in cursor.fetchall()}

    for table, columns in SQLITE_INDEXES.items():
        # Skip if table doesn't exist
        if table not in table_columns:
            continue

        for column in columns:
            # Skip if column doesn't exist in this table
            if column not in table_columns[table]:
                continue

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


def get_info_findings_db_path(base_dir: str, year: int) -> str:
    """
    Get the path for an informational findings database for a specific year.

    Args:
        base_dir: Base directory for storing databases
        year: Calendar year

    Returns:
        Path to the yearly info database
    """
    import os
    info_db_dir = os.path.join(base_dir, 'info_findings')
    os.makedirs(info_db_dir, exist_ok=True)
    return os.path.join(info_db_dir, f'info_findings_{year}.db')


def save_informational_findings_by_year(historical_df: pd.DataFrame, base_dir: str) -> Dict[int, int]:
    """
    Save informational findings to separate yearly databases.

    Automatically separates Info severity findings by calendar year and saves
    each year to its own database file.

    Args:
        historical_df: DataFrame with all historical findings
        base_dir: Base directory for storing databases

    Returns:
        Dictionary mapping year to count of findings saved
    """
    if historical_df.empty:
        return {}

    # Filter to only informational findings
    info_df = historical_df[historical_df['severity_text'] == 'Info'].copy()

    if info_df.empty:
        return {}

    # Ensure scan_date is datetime
    info_df['scan_date'] = pd.to_datetime(info_df['scan_date'])

    # Group by year
    info_df['year'] = info_df['scan_date'].dt.year

    results = {}

    for year, year_df in info_df.groupby('year'):
        db_path = get_info_findings_db_path(base_dir, int(year))

        try:
            conn = sqlite3.connect(db_path)

            # Migrate schema to add any new columns
            migrations = migrate_database_schema(conn)
            if migrations:
                for msg in migrations:
                    print(f"Schema migration: {msg}")

            # Prepare DataFrame for SQLite
            save_df = year_df.drop(columns=['year']).copy()
            for col in save_df.columns:
                if pd.api.types.is_datetime64_any_dtype(save_df[col]):
                    save_df[col] = save_df[col].dt.strftime('%Y-%m-%d %H:%M:%S')

            # Append to existing data (don't replace)
            existing_count = 0
            try:
                existing = pd.read_sql_query("SELECT COUNT(*) as cnt FROM info_findings", conn)
                existing_count = existing['cnt'].iloc[0]
            except:
                pass

            save_df.to_sql('info_findings', conn, if_exists='append', index=False)

            # Remove duplicates by keeping unique combinations
            conn.execute('''
                DELETE FROM info_findings
                WHERE rowid NOT IN (
                    SELECT MIN(rowid) FROM info_findings
                    GROUP BY plugin_id, hostname, ip_address, scan_date
                )
            ''')

            # Update summary
            final_count = pd.read_sql_query("SELECT COUNT(*) as cnt FROM info_findings", conn)['cnt'].iloc[0]

            summary_data = {
                'last_updated': [datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
                'year': [int(year)],
                'total_findings': [final_count]
            }
            pd.DataFrame(summary_data).to_sql('summary', conn, if_exists='replace', index=False)

            # Add indexes
            try:
                conn.execute("CREATE INDEX IF NOT EXISTS idx_info_plugin_id ON info_findings(plugin_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_info_hostname ON info_findings(hostname)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_info_scan_date ON info_findings(scan_date)")
            except:
                pass

            conn.commit()
            conn.close()

            new_added = final_count - existing_count
            results[int(year)] = new_added
            print(f"Saved {new_added} new info findings to {year} database (total: {final_count})")

        except Exception as e:
            print(f"Error saving info findings for year {year}: {e}")
            import traceback
            traceback.print_exc()

    return results


def list_available_info_databases(base_dir: str) -> List[Dict[str, Any]]:
    """
    List all available informational findings databases.

    Args:
        base_dir: Base directory for databases

    Returns:
        List of dictionaries with year, path, and count
    """
    import os
    info_db_dir = os.path.join(base_dir, 'info_findings')

    if not os.path.exists(info_db_dir):
        return []

    databases = []

    for filename in os.listdir(info_db_dir):
        if filename.startswith('info_findings_') and filename.endswith('.db'):
            try:
                year = int(filename.replace('info_findings_', '').replace('.db', ''))
                filepath = os.path.join(info_db_dir, filename)

                # Get count from database
                conn = sqlite3.connect(filepath)
                try:
                    count_df = pd.read_sql_query("SELECT COUNT(*) as cnt FROM info_findings", conn)
                    count = count_df['cnt'].iloc[0]
                except:
                    count = 0
                conn.close()

                databases.append({
                    'year': year,
                    'path': filepath,
                    'count': count,
                    'filename': filename
                })
            except:
                continue

    # Sort by year descending
    databases.sort(key=lambda x: x['year'], reverse=True)
    return databases


def load_informational_findings(filepaths: List[str]) -> pd.DataFrame:
    """
    Load informational findings from one or more yearly databases.

    Args:
        filepaths: List of database file paths

    Returns:
        Combined DataFrame of informational findings
    """
    all_dfs = []

    for filepath in filepaths:
        try:
            conn = sqlite3.connect(filepath)
            df = pd.read_sql_query("SELECT * FROM info_findings", conn)
            df['scan_date'] = pd.to_datetime(df['scan_date'], errors='coerce')
            all_dfs.append(df)
            conn.close()
            print(f"Loaded {len(df)} info findings from {filepath}")
        except Exception as e:
            print(f"Error loading info findings from {filepath}: {e}")

    if all_dfs:
        combined = pd.concat(all_dfs, ignore_index=True)
        # Remove duplicates
        combined = combined.drop_duplicates(subset=['plugin_id', 'hostname', 'ip_address', 'scan_date'])
        return combined

    return pd.DataFrame()


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
