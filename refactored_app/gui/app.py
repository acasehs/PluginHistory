"""
Main Application GUI Module
Tkinter-based GUI for the Nessus Historical Analysis application.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import pandas as pd
import os
from datetime import datetime
from typing import List, Optional, Dict, Any

# Import application modules
from ..config import GUI_WINDOW_SIZE, GUI_DARK_THEME, SEVERITY_ORDER
from ..core.archive_extraction import extract_nested_archives, find_files_by_extension, cleanup_temp_directory
from ..core.nessus_parser import parse_multiple_nessus_files
from ..core.plugin_database import load_plugins_database
from ..core.data_processing import enrich_findings_with_severity
from ..analysis.lifecycle import analyze_finding_lifecycle
from ..analysis.host_presence import create_host_presence_analysis
from ..analysis.scan_changes import analyze_scan_changes
from ..analysis.opdir_compliance import load_opdir_mapping, enrich_with_opdir
from ..filters.filter_engine import FilterEngine, apply_filters
from ..filters.hostname_parser import parse_hostname, HostType
from ..export.sqlite_export import export_to_sqlite
from ..export.excel_export import export_to_excel
from ..export.json_export import export_to_json


class NessusHistoryTrackerApp:
    """Main application class for the Nessus History Tracker."""

    def __init__(self):
        """Initialize the application."""
        self.window = tk.Tk()
        self.window.title("Nessus History Tracker v2.0")
        self.window.geometry(GUI_WINDOW_SIZE)
        self.window.configure(bg=GUI_DARK_THEME['bg'])

        # Data storage
        self.historical_df = pd.DataFrame()
        self.lifecycle_df = pd.DataFrame()
        self.host_presence_df = pd.DataFrame()
        self.scan_changes_df = pd.DataFrame()
        self.opdir_df = pd.DataFrame()
        self.plugins_dict = None

        # File paths
        self.archive_paths: List[str] = []
        self.plugins_db_path: Optional[str] = None
        self.existing_db_path: Optional[str] = None
        self.opdir_file_path: Optional[str] = None

        # Filter variables
        self.filter_include_info = tk.BooleanVar(value=True)
        self.filter_start_date = tk.StringVar()
        self.filter_end_date = tk.StringVar()
        self.filter_severity = tk.StringVar(value="All")
        self.filter_status = tk.StringVar(value="All")
        self.filter_host = tk.StringVar()
        self.filter_host_type = tk.StringVar(value="All")
        self.filter_location = tk.StringVar()
        self.filter_cvss_min = tk.StringVar(value="0.0")
        self.filter_cvss_max = tk.StringVar(value="10.0")
        self.filter_opdir_status = tk.StringVar(value="All")

        # Build UI
        self._setup_styles()
        self._build_ui()

    def _setup_styles(self):
        """Configure ttk styles for dark theme."""
        style = ttk.Style()
        style.theme_use('clam')

        # Base styles
        style.configure('TFrame', background=GUI_DARK_THEME['bg'])
        style.configure('TLabel', background=GUI_DARK_THEME['bg'], foreground=GUI_DARK_THEME['fg'])
        style.configure('TButton', background=GUI_DARK_THEME['button_bg'], foreground=GUI_DARK_THEME['fg'])
        style.configure('TEntry', fieldbackground=GUI_DARK_THEME['entry_bg'], foreground=GUI_DARK_THEME['fg'])
        style.configure('TCheckbutton', background=GUI_DARK_THEME['bg'], foreground=GUI_DARK_THEME['fg'])
        style.configure('TNotebook', background=GUI_DARK_THEME['bg'])
        style.configure('TNotebook.Tab', background=GUI_DARK_THEME['button_bg'], foreground=GUI_DARK_THEME['fg'])

        # Combobox dark theme
        style.configure('TCombobox',
                       fieldbackground=GUI_DARK_THEME['entry_bg'],
                       background=GUI_DARK_THEME['button_bg'],
                       foreground=GUI_DARK_THEME['fg'],
                       arrowcolor=GUI_DARK_THEME['fg'])
        style.map('TCombobox',
                 fieldbackground=[('readonly', GUI_DARK_THEME['entry_bg'])],
                 selectbackground=[('readonly', GUI_DARK_THEME['button_bg'])],
                 selectforeground=[('readonly', GUI_DARK_THEME['fg'])])

        # LabelFrame dark theme
        style.configure('TLabelframe', background=GUI_DARK_THEME['bg'])
        style.configure('TLabelframe.Label', background=GUI_DARK_THEME['bg'], foreground=GUI_DARK_THEME['fg'])

        # Separator
        style.configure('TSeparator', background=GUI_DARK_THEME['button_bg'])

    def _build_ui(self):
        """Build the main user interface."""
        # Main container
        main_frame = ttk.Frame(self.window)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Left panel - File selection and filters
        left_panel = ttk.Frame(main_frame, width=350)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        left_panel.pack_propagate(False)

        self._build_file_selection(left_panel)
        self._build_filter_panel(left_panel)
        self._build_action_buttons(left_panel)

        # Right panel - Notebook with tabs
        right_panel = ttk.Frame(main_frame)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self.notebook = ttk.Notebook(right_panel)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self._build_status_tab()
        self._build_dashboard_tab()
        self._build_lifecycle_tab()
        self._build_host_tab()

    def _build_file_selection(self, parent):
        """Build file selection section with compact layout."""
        file_frame = ttk.LabelFrame(parent, text="Data Sources", padding=5)
        file_frame.pack(fill=tk.X, pady=(0, 5))

        # Archives row
        archive_row = ttk.Frame(file_frame)
        archive_row.pack(fill=tk.X, pady=2)
        ttk.Label(archive_row, text="Archives:", width=9).pack(side=tk.LEFT)
        self.archives_label = ttk.Label(archive_row, text="None", foreground="gray", width=18, anchor=tk.W)
        self.archives_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(archive_row, text="...", command=self._select_archives, width=3).pack(side=tk.RIGHT)

        # Plugins DB row
        plugins_row = ttk.Frame(file_frame)
        plugins_row.pack(fill=tk.X, pady=2)
        ttk.Label(plugins_row, text="Plugins:", width=9).pack(side=tk.LEFT)
        self.plugins_label = ttk.Label(plugins_row, text="None", foreground="gray", width=18, anchor=tk.W)
        self.plugins_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(plugins_row, text="...", command=self._select_plugins_db, width=3).pack(side=tk.RIGHT)

        # Existing DB row
        db_row = ttk.Frame(file_frame)
        db_row.pack(fill=tk.X, pady=2)
        ttk.Label(db_row, text="Existing:", width=9).pack(side=tk.LEFT)
        self.existing_db_label = ttk.Label(db_row, text="None", foreground="gray", width=18, anchor=tk.W)
        self.existing_db_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(db_row, text="...", command=self._select_existing_db, width=3).pack(side=tk.RIGHT)

        # OPDIR row
        opdir_row = ttk.Frame(file_frame)
        opdir_row.pack(fill=tk.X, pady=2)
        ttk.Label(opdir_row, text="OPDIR:", width=9).pack(side=tk.LEFT)
        self.opdir_label = ttk.Label(opdir_row, text="None", foreground="gray", width=18, anchor=tk.W)
        self.opdir_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(opdir_row, text="...", command=self._select_opdir_file, width=3).pack(side=tk.RIGHT)

    def _build_filter_panel(self, parent):
        """Build filter controls section with compact inline layout."""
        filter_frame = ttk.LabelFrame(parent, text="Filters", padding=5)
        filter_frame.pack(fill=tk.X, pady=(0, 5))

        # Row 1: Include Info checkbox
        ttk.Checkbutton(filter_frame, text="Include Info Severity",
                       variable=self.filter_include_info).pack(anchor=tk.W)

        # Row 2: Date Range (inline)
        date_row = ttk.Frame(filter_frame)
        date_row.pack(fill=tk.X, pady=3)
        ttk.Label(date_row, text="Dates:", width=8).pack(side=tk.LEFT)
        ttk.Entry(date_row, textvariable=self.filter_start_date, width=10).pack(side=tk.LEFT, padx=1)
        ttk.Label(date_row, text="-").pack(side=tk.LEFT)
        ttk.Entry(date_row, textvariable=self.filter_end_date, width=10).pack(side=tk.LEFT, padx=1)

        # Row 3: Severity + Status (inline)
        sev_row = ttk.Frame(filter_frame)
        sev_row.pack(fill=tk.X, pady=3)
        ttk.Label(sev_row, text="Severity:", width=8).pack(side=tk.LEFT)
        severity_options = ["All", "Critical", "High", "Medium", "Low", "Info", "Crit+High"]
        ttk.Combobox(sev_row, textvariable=self.filter_severity,
                    values=severity_options, state="readonly", width=10).pack(side=tk.LEFT, padx=1)
        ttk.Label(sev_row, text="Status:").pack(side=tk.LEFT, padx=(5, 0))
        ttk.Combobox(sev_row, textvariable=self.filter_status,
                    values=["All", "Active", "Resolved"], state="readonly", width=8).pack(side=tk.LEFT, padx=1)

        # Row 4: Host Type + Location (inline)
        host_row = ttk.Frame(filter_frame)
        host_row.pack(fill=tk.X, pady=3)
        ttk.Label(host_row, text="Type:", width=8).pack(side=tk.LEFT)
        ttk.Combobox(host_row, textvariable=self.filter_host_type,
                    values=["All", "Physical", "Virtual", "ILOM"], state="readonly", width=10).pack(side=tk.LEFT, padx=1)
        ttk.Label(host_row, text="Loc:").pack(side=tk.LEFT, padx=(5, 0))
        ttk.Entry(host_row, textvariable=self.filter_location, width=8).pack(side=tk.LEFT, padx=1)

        # Row 5: Host Pattern (inline)
        pattern_row = ttk.Frame(filter_frame)
        pattern_row.pack(fill=tk.X, pady=3)
        ttk.Label(pattern_row, text="Host:", width=8).pack(side=tk.LEFT)
        ttk.Entry(pattern_row, textvariable=self.filter_host).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=1)

        # Row 6: CVSS Range (inline)
        cvss_row = ttk.Frame(filter_frame)
        cvss_row.pack(fill=tk.X, pady=3)
        ttk.Label(cvss_row, text="CVSS:", width=8).pack(side=tk.LEFT)
        ttk.Entry(cvss_row, textvariable=self.filter_cvss_min, width=5).pack(side=tk.LEFT, padx=1)
        ttk.Label(cvss_row, text="-").pack(side=tk.LEFT)
        ttk.Entry(cvss_row, textvariable=self.filter_cvss_max, width=5).pack(side=tk.LEFT, padx=1)
        ttk.Button(cvss_row, text="Apply", command=self._apply_filters, width=8).pack(side=tk.RIGHT)

    def _build_action_buttons(self, parent):
        """Build action buttons section with compact 2-per-row layout."""
        action_frame = ttk.LabelFrame(parent, text="Actions", padding=5)
        action_frame.pack(fill=tk.X)

        # Row 1: Process + Refresh
        row1 = ttk.Frame(action_frame)
        row1.pack(fill=tk.X, pady=2)
        ttk.Button(row1, text="Process", command=self._process_archives).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=1)
        ttk.Button(row1, text="Refresh", command=self._refresh_analysis).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=1)

        # Row 2: Excel + SQLite
        row2 = ttk.Frame(action_frame)
        row2.pack(fill=tk.X, pady=2)
        ttk.Button(row2, text="Excel", command=self._export_excel).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=1)
        ttk.Button(row2, text="SQLite", command=self._export_sqlite).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=1)

        # Row 3: JSON (centered)
        row3 = ttk.Frame(action_frame)
        row3.pack(fill=tk.X, pady=2)
        ttk.Button(row3, text="JSON", command=self._export_json).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=1)

    def _build_status_tab(self):
        """Build status/log tab."""
        status_frame = ttk.Frame(self.notebook)
        self.notebook.add(status_frame, text="Status")

        self.status_text = tk.Text(status_frame, wrap=tk.WORD,
                                   bg=GUI_DARK_THEME['text_bg'],
                                   fg=GUI_DARK_THEME['fg'],
                                   font=('Consolas', 10))
        self.status_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        scrollbar = ttk.Scrollbar(status_frame, command=self.status_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.status_text.config(yscrollcommand=scrollbar.set)

    def _build_dashboard_tab(self):
        """Build dashboard tab placeholder."""
        dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text="Dashboard")
        self.dashboard_frame = dashboard_frame

    def _build_lifecycle_tab(self):
        """Build lifecycle analysis tab."""
        lifecycle_frame = ttk.Frame(self.notebook)
        self.notebook.add(lifecycle_frame, text="Lifecycle")
        self.lifecycle_frame = lifecycle_frame

    def _build_host_tab(self):
        """Build host analysis tab."""
        host_frame = ttk.Frame(self.notebook)
        self.notebook.add(host_frame, text="Hosts")
        self.host_frame = host_frame

    # File selection methods
    def _truncate_filename(self, name: str, max_len: int = 20) -> str:
        """Truncate filename to fit in label."""
        if len(name) <= max_len:
            return name
        return name[:max_len-3] + "..."

    def _select_archives(self):
        """Select Nessus archive files."""
        filetypes = (('Archive files', '*.zip'), ('Nessus files', '*.nessus'), ('All files', '*.*'))
        paths = filedialog.askopenfilenames(title='Select Nessus Archives', filetypes=filetypes)

        if paths:
            self.archive_paths = list(paths)
            self.archives_label.config(text=f"{len(self.archive_paths)} file(s)", foreground="white")
            self._log(f"Selected {len(self.archive_paths)} archive(s)")

    def _select_plugins_db(self):
        """Select plugins database file."""
        filetypes = (('XML files', '*.xml'), ('JSON files', '*.json'), ('All files', '*.*'))
        path = filedialog.askopenfilename(title='Select Plugins Database', filetypes=filetypes)

        if path:
            self.plugins_db_path = path
            self.plugins_label.config(text=self._truncate_filename(os.path.basename(path)), foreground="white")
            self._log(f"Selected plugins DB: {os.path.basename(path)}")

    def _select_existing_db(self):
        """Select existing database file."""
        filetypes = (('SQLite database', '*.db'), ('All files', '*.*'))
        path = filedialog.askopenfilename(title='Select Existing Database', filetypes=filetypes)

        if path:
            self.existing_db_path = path
            self.existing_db_label.config(text=self._truncate_filename(os.path.basename(path)), foreground="white")
            self._log(f"Selected existing DB: {os.path.basename(path)}")

    def _select_opdir_file(self):
        """Select OPDIR mapping file."""
        filetypes = (('Excel files', '*.xlsx'), ('CSV files', '*.csv'), ('All files', '*.*'))
        path = filedialog.askopenfilename(title='Select OPDIR Mapping File', filetypes=filetypes)

        if path:
            self.opdir_file_path = path
            self.opdir_label.config(text=self._truncate_filename(os.path.basename(path)), foreground="white")
            self._log(f"Selected OPDIR file: {os.path.basename(path)}")

    # Processing methods
    def _process_archives(self):
        """Process selected archives."""
        if not self.archive_paths and not self.existing_db_path:
            messagebox.showwarning("No Data", "Please select archives or an existing database")
            return

        try:
            self._log("Starting processing...")

            # Load OPDIR if available
            if self.opdir_file_path:
                self._log("Loading OPDIR mapping...")
                self.opdir_df = load_opdir_mapping(self.opdir_file_path)

            # Load plugins database
            if self.plugins_db_path:
                self._log("Loading plugins database...")
                self.plugins_dict = load_plugins_database(self.plugins_db_path)

            # Process archives or load existing DB
            if self.existing_db_path and not self.archive_paths:
                self._load_existing_database()
            else:
                self._process_new_archives()

            # Set date filter defaults
            if not self.historical_df.empty:
                start_date = self.historical_df['scan_date'].min().strftime('%Y-%m-%d')
                end_date = self.historical_df['scan_date'].max().strftime('%Y-%m-%d')
                self.filter_start_date.set(start_date)
                self.filter_end_date.set(end_date)

            self._log("Processing complete!")
            messagebox.showinfo("Success", "Data processed successfully!")

        except Exception as e:
            self._log(f"ERROR: {str(e)}")
            messagebox.showerror("Error", f"Processing failed: {str(e)}")

    def _load_existing_database(self):
        """Load data from existing database."""
        import sqlite3

        self._log("Loading existing database...")

        conn = sqlite3.connect(self.existing_db_path)

        try:
            self.historical_df = pd.read_sql_query("SELECT * FROM historical_findings", conn)
            self.historical_df['scan_date'] = pd.to_datetime(self.historical_df['scan_date'])
            self._log(f"Loaded {len(self.historical_df)} historical findings")

            try:
                self.lifecycle_df = pd.read_sql_query("SELECT * FROM finding_lifecycle", conn)
            except:
                pass

            try:
                self.host_presence_df = pd.read_sql_query("SELECT * FROM host_presence", conn)
            except:
                pass

        finally:
            conn.close()

        self._refresh_analysis_internal()

    def _process_new_archives(self):
        """Process new archive files."""
        import tempfile

        self._log("Processing archives...")

        all_findings = []
        temp_dirs = []

        for archive_path in self.archive_paths:
            self._log(f"Processing: {os.path.basename(archive_path)}")

            if archive_path.endswith('.zip'):
                temp_dir = tempfile.mkdtemp()
                temp_dirs.append(temp_dir)
                extract_nested_archives(archive_path, temp_dir)
                nessus_files = find_files_by_extension(temp_dir, '.nessus')
            else:
                nessus_files = [archive_path]

            if nessus_files:
                findings_df, _ = parse_multiple_nessus_files(nessus_files, self.plugins_dict)
                if not findings_df.empty:
                    findings_df = enrich_findings_with_severity(findings_df)
                    all_findings.append(findings_df)

        # Cleanup temp directories
        for temp_dir in temp_dirs:
            cleanup_temp_directory(temp_dir)

        if all_findings:
            self.historical_df = pd.concat(all_findings, ignore_index=True)
            self._log(f"Total findings: {len(self.historical_df)}")

        self._refresh_analysis_internal()

    def _refresh_analysis(self):
        """User-triggered analysis refresh."""
        if self.historical_df.empty:
            messagebox.showwarning("No Data", "Please process archives first")
            return

        try:
            self._refresh_analysis_internal()
            messagebox.showinfo("Success", "Analysis refreshed!")
        except Exception as e:
            self._log(f"ERROR: {str(e)}")
            messagebox.showerror("Error", f"Refresh failed: {str(e)}")

    def _refresh_analysis_internal(self):
        """Internal analysis refresh."""
        self._log("Running analysis...")

        # Analyze lifecycle
        self.lifecycle_df = analyze_finding_lifecycle(self.historical_df)
        self._log(f"Lifecycle analysis: {len(self.lifecycle_df)} unique findings")

        # Enrich with OPDIR
        if not self.opdir_df.empty:
            self.lifecycle_df = enrich_with_opdir(self.lifecycle_df, self.opdir_df)
            self._log("Applied OPDIR enrichment")

        # Host presence
        self.host_presence_df = create_host_presence_analysis(self.historical_df)
        self._log(f"Host presence: {len(self.host_presence_df)} hosts")

        # Scan changes
        self.scan_changes_df = analyze_scan_changes(self.historical_df)
        self._log(f"Scan changes: {len(self.scan_changes_df)} transitions")

    def _apply_filters(self):
        """Apply current filters and refresh display."""
        if self.lifecycle_df.empty:
            return

        self._log("Applying filters...")
        # Filter implementation would go here
        self._log("Filters applied")

    # Export methods
    def _export_excel(self):
        """Export to Excel."""
        if self.historical_df.empty:
            messagebox.showwarning("No Data", "Please process archives first")
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".xlsx",
            filetypes=[("Excel files", "*.xlsx")],
            title="Save Excel File"
        )

        if filepath:
            success = export_to_excel(
                self.historical_df, self.lifecycle_df,
                self.host_presence_df, self.scan_changes_df,
                self.opdir_df, filepath
            )

            if success:
                self._log(f"Exported to: {filepath}")
                messagebox.showinfo("Success", f"Exported to:\n{filepath}")

    def _export_sqlite(self):
        """Export to SQLite."""
        if self.historical_df.empty:
            messagebox.showwarning("No Data", "Please process archives first")
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".db",
            filetypes=[("SQLite database", "*.db")],
            title="Save SQLite Database"
        )

        if filepath:
            success = export_to_sqlite(
                self.historical_df, self.lifecycle_df,
                self.host_presence_df, self.scan_changes_df,
                self.opdir_df, filepath
            )

            if success:
                self._log(f"Exported to: {filepath}")
                messagebox.showinfo("Success", f"Exported to:\n{filepath}")

    def _export_json(self):
        """Export to JSON."""
        if self.historical_df.empty:
            messagebox.showwarning("No Data", "Please process archives first")
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
            title="Save JSON File"
        )

        if filepath:
            success = export_to_json(
                self.historical_df, self.lifecycle_df,
                self.host_presence_df, self.scan_changes_df,
                filepath
            )

            if success:
                self._log(f"Exported to: {filepath}")
                messagebox.showinfo("Success", f"Exported to:\n{filepath}")

    def _log(self, message: str):
        """Add message to status log."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.status_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.status_text.see(tk.END)
        self.window.update()

    def run(self):
        """Run the application."""
        self._log("Nessus History Tracker v2.0 started")
        self._log("Select archives or load existing database to begin")
        self.window.mainloop()
