"""
Main Application GUI Module
Tkinter-based GUI for the Nessus Historical Analysis application.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import pandas as pd
import numpy as np
import os
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

# Matplotlib for charts (with Tk backend)
try:
    import matplotlib
    matplotlib.use('TkAgg')
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

# Import application modules
from ..config import (GUI_WINDOW_SIZE, GUI_DARK_THEME, SEVERITY_ORDER,
                       SLA_TARGETS_DAYS, SLA_WARNING_THRESHOLD, SLA_STATUS_COLORS,
                       SLA_STATUS_OVERDUE, SLA_STATUS_APPROACHING, SLA_STATUS_ON_TRACK, SLA_STATUS_NO_SLA)
from ..core.archive_extraction import extract_nested_archives, find_files_by_extension, cleanup_temp_directory
from ..core.nessus_parser import parse_multiple_nessus_files
from ..core.plugin_database import load_plugins_database
from ..core.data_processing import enrich_findings_with_severity
from ..analysis.lifecycle import analyze_finding_lifecycle
from ..analysis.host_presence import create_host_presence_analysis
from ..analysis.scan_changes import analyze_scan_changes
from ..analysis.opdir_compliance import load_opdir_mapping, enrich_with_opdir
from ..analysis.iavm_parser import load_iavm_summaries, enrich_findings_with_iavm
from ..analysis.advanced_metrics import (
    get_all_advanced_metrics, calculate_reopen_rate, calculate_coverage_metrics,
    calculate_remediation_rate, calculate_sla_breach_tracking, calculate_normalized_metrics,
    calculate_risk_reduction_trend
)
from ..filters.filter_engine import FilterEngine, apply_filters
from ..filters.hostname_parser import parse_hostname, HostType
from ..filters.custom_lists import FilterListManager, FilterList
from ..export.sqlite_export import (
    export_to_sqlite, save_informational_findings_by_year,
    list_available_info_databases, load_informational_findings
)
from ..export.excel_export import export_to_excel
from ..export.json_export import export_to_json
from ..settings import SettingsManager, UserSettings
from ..visualization.charts import (
    get_date_interval, get_interval_label, get_period_format,
    group_by_interval, get_period_labels, calculate_date_range_from_df,
    DATE_INTERVAL_WEEKLY, DATE_INTERVAL_MONTHLY, DATE_INTERVAL_QUARTERLY, DATE_INTERVAL_YEARLY
)
from .chart_utils import (
    add_data_labels, add_horizontal_data_labels, add_line_data_labels,
    ChartPopoutModal
)
from .menu_bar import create_menu_bar
from .package_impact_dialog import show_package_impact_dialog


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
        self.iavm_df = pd.DataFrame()
        self.plugins_dict = None

        # Filtered data for display
        self.filtered_lifecycle_df = pd.DataFrame()
        self.filtered_host_df = pd.DataFrame()
        self.filtered_historical_df = pd.DataFrame()
        self.filtered_scan_changes_df = pd.DataFrame()

        # File paths
        self.archive_paths: List[str] = []
        self.plugins_db_path: Optional[str] = None
        self.existing_db_path: Optional[str] = None
        self.opdir_file_path: Optional[str] = None
        self.iavm_file_path: Optional[str] = None

        # Filter variables
        self.filter_include_info = tk.BooleanVar(value=True)
        self.filter_start_date = tk.StringVar()
        self.filter_end_date = tk.StringVar()
        self.filter_severity = tk.StringVar(value="All")
        # Individual severity toggles for highlight/toggle behavior
        self.severity_toggles = {
            'Critical': tk.BooleanVar(value=True),
            'High': tk.BooleanVar(value=True),
            'Medium': tk.BooleanVar(value=True),
            'Low': tk.BooleanVar(value=True),
            'Info': tk.BooleanVar(value=False),  # Off by default
        }
        self.severity_buttons = {}  # Will hold button widgets
        self.filter_status = tk.StringVar(value="All")
        self.filter_host = tk.StringVar()
        self.filter_host_type = tk.StringVar(value="All")
        self.filter_location = tk.StringVar()
        self.filter_cvss_min = tk.StringVar(value="0.0")
        self.filter_cvss_max = tk.StringVar(value="10.0")
        self.filter_opdir_status = tk.StringVar(value="All")
        self.filter_env_type = tk.StringVar(value="All Combined")  # All Combined, All Separate, or specific env
        self.show_env_breakdown = False  # Flag for visualizations to group by environment
        self.filter_cve = tk.StringVar()  # CVE filter (e.g., CVE-2024-1234)
        self.filter_iavx = tk.StringVar()  # IAVA/B/T filter (e.g., 2024-A-0001)

        # Advanced host filtering
        self.filter_host_list: List[str] = []  # Specific hostnames selected
        self.filter_list_manager = FilterListManager()  # Saved filter lists

        # Lifecycle navigation state
        self.lifecycle_page_size = tk.IntVar(value=100)
        self.lifecycle_current_start = 0  # Starting index for pagination
        self.lifecycle_jump_to = tk.StringVar()

        # Lifecycle display toggles (Active only by default)
        self.lifecycle_show_active = tk.BooleanVar(value=True)
        self.lifecycle_show_resolved = tk.BooleanVar(value=False)

        # Host display toggles (Active only by default)
        self.host_show_active = tk.BooleanVar(value=True)
        self.host_show_missing = tk.BooleanVar(value=False)
        self.host_missing_threshold = 6  # Missing from > 6 scans = "missing"

        # Chart pop-out redraw functions (populated after UI build)
        self.chart_redraw_funcs: Dict[str, Any] = {}

        # Settings manager
        self.settings_manager = SettingsManager()

        # Build UI
        self._setup_styles()
        self._build_ui()

        # Apply settings after UI is built
        self._apply_settings_to_ui()

        # Add menu bar
        self.menu_bar = create_menu_bar(self)

        # Initialize AI client asynchronously if configured
        self._init_ai_client_async()

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
        style.configure('TNotebook.Tab',
                       background=GUI_DARK_THEME['text_bg'],  # Darker unselected tabs
                       foreground=GUI_DARK_THEME['fg'],
                       padding=[10, 5])
        style.map('TNotebook.Tab',
                 background=[('selected', GUI_DARK_THEME['button_bg']),  # Slightly lighter when selected
                            ('active', GUI_DARK_THEME['entry_bg'])],     # Hover state
                 foreground=[('selected', GUI_DARK_THEME['fg']),
                            ('active', GUI_DARK_THEME['fg'])])

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
        # Status bar at bottom (create first, pack last)
        self.status_bar = tk.Frame(self.window, bg='#1a1a2e', height=24)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.status_bar.pack_propagate(False)

        self.status_label = tk.Label(self.status_bar, text="Ready", bg='#1a1a2e', fg='#888888',
                                     anchor='w', padx=10, font=('Arial', 9))
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.progress_label = tk.Label(self.status_bar, text="", bg='#1a1a2e', fg='#17a2b8',
                                       anchor='e', padx=10, font=('Arial', 9))
        self.progress_label.pack(side=tk.RIGHT)

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

        # Build tabs - Logging tab last
        self._build_dashboard_tab()
        self._build_lifecycle_tab()
        self._build_host_tab()
        self._build_timeline_tab()
        self._build_risk_tab()
        self._build_opdir_tab()
        self._build_efficiency_tab()
        self._build_network_tab()
        self._build_plugin_tab()
        self._build_priority_tab()
        self._build_sla_tab()
        self._build_metrics_tab()
        self._build_host_tracking_tab()
        self._build_advanced_tab()
        self._build_logging_tab()  # Moved to last

    def _build_file_selection(self, parent):
        """Build file selection section with compact layout."""
        file_frame = ttk.LabelFrame(parent, text="Data Sources", padding=5)
        file_frame.pack(fill=tk.X, pady=(0, 5))

        # Load order hint
        hint_label = ttk.Label(file_frame, text="Load order: DB → Archives → Plugins → OPDIR → IAVM",
                              font=('TkDefaultFont', 8), foreground='#888888')
        hint_label.pack(anchor=tk.W, pady=(0, 3))

        # Existing DB row (FIRST - recommended to load existing data first)
        db_row = ttk.Frame(file_frame)
        db_row.pack(fill=tk.X, pady=2)
        ttk.Label(db_row, text="1. Existing:", width=11).pack(side=tk.LEFT)
        self.existing_db_label = ttk.Label(db_row, text="None", foreground="gray", width=16, anchor=tk.W)
        self.existing_db_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(db_row, text="...", command=self._select_existing_db, width=3).pack(side=tk.RIGHT)

        # Archives row
        archive_row = ttk.Frame(file_frame)
        archive_row.pack(fill=tk.X, pady=2)
        ttk.Label(archive_row, text="2. Archives:", width=11).pack(side=tk.LEFT)
        self.archives_label = ttk.Label(archive_row, text="None", foreground="gray", width=16, anchor=tk.W)
        self.archives_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(archive_row, text="...", command=self._select_archives, width=3).pack(side=tk.RIGHT)

        # Plugins DB row
        plugins_row = ttk.Frame(file_frame)
        plugins_row.pack(fill=tk.X, pady=2)
        ttk.Label(plugins_row, text="3. Plugins:", width=11).pack(side=tk.LEFT)
        self.plugins_label = ttk.Label(plugins_row, text="None", foreground="gray", width=16, anchor=tk.W)
        self.plugins_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(plugins_row, text="...", command=self._select_plugins_db, width=3).pack(side=tk.RIGHT)

        # OPDIR row
        opdir_row = ttk.Frame(file_frame)
        opdir_row.pack(fill=tk.X, pady=2)
        ttk.Label(opdir_row, text="4. OPDIR:", width=11).pack(side=tk.LEFT)
        self.opdir_label = ttk.Label(opdir_row, text="None", foreground="gray", width=16, anchor=tk.W)
        self.opdir_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(opdir_row, text="...", command=self._select_opdir_file, width=3).pack(side=tk.RIGHT)

        # IAVM Notices row
        iavm_row = ttk.Frame(file_frame)
        iavm_row.pack(fill=tk.X, pady=2)
        ttk.Label(iavm_row, text="5. IAVM:", width=11).pack(side=tk.LEFT)
        self.iavm_label = ttk.Label(iavm_row, text="None", foreground="gray", width=16, anchor=tk.W)
        self.iavm_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(iavm_row, text="...", command=self._select_iavm_file, width=3).pack(side=tk.RIGHT)

    def _build_filter_panel(self, parent):
        """Build filter controls section with 2-column layout."""
        filter_frame = ttk.LabelFrame(parent, text="Filters", padding=5)
        filter_frame.pack(fill=tk.X, pady=(0, 5))

        # Store references to filter labels for color updating
        self.filter_labels = {}

        # Default label colors
        self.filter_label_default_bg = GUI_DARK_THEME['button_bg']
        self.filter_label_active_bg = '#1a3a5c'

        # Calculate default 180-day date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=self.settings_manager.settings.default_date_range_days)
        self.filter_start_date.set(start_date.strftime('%Y-%m-%d'))
        self.filter_end_date.set(end_date.strftime('%Y-%m-%d'))

        # Row 1: Date Range (full width)
        date_row = ttk.Frame(filter_frame)
        date_row.pack(fill=tk.X, pady=3)
        date_label = tk.Label(date_row, text="Dates:", width=8, bg=self.filter_label_default_bg, fg='white', anchor='w')
        date_label.pack(side=tk.LEFT)
        self.filter_labels['dates'] = date_label

        # Date entry with picker button
        start_entry = ttk.Entry(date_row, textvariable=self.filter_start_date, width=10)
        start_entry.pack(side=tk.LEFT, padx=1)
        tk.Button(date_row, text="📅", command=lambda: self._show_date_picker(self.filter_start_date),
                 bg=GUI_DARK_THEME['button_bg'], fg='white', relief='flat', width=2).pack(side=tk.LEFT)

        ttk.Label(date_row, text="to").pack(side=tk.LEFT, padx=2)

        end_entry = ttk.Entry(date_row, textvariable=self.filter_end_date, width=10)
        end_entry.pack(side=tk.LEFT, padx=1)
        tk.Button(date_row, text="📅", command=lambda: self._show_date_picker(self.filter_end_date),
                 bg=GUI_DARK_THEME['button_bg'], fg='white', relief='flat', width=2).pack(side=tk.LEFT)

        # Row 2: Severity toggle buttons (full width)
        sev_row = ttk.Frame(filter_frame)
        sev_row.pack(fill=tk.X, pady=3)
        sev_label = tk.Label(sev_row, text="Severity:", width=8, bg=self.filter_label_default_bg, fg='white', anchor='w')
        sev_label.pack(side=tk.LEFT)
        self.filter_labels['severity'] = sev_label

        # Severity colors (from settings or defaults)
        sev_colors = self.settings_manager.settings.get_severity_colors()

        # Create toggle buttons for each severity
        for sev in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            color = sev_colors.get(sev, '#6c757d')
            btn = tk.Button(
                sev_row, text=sev[0], width=2,  # Single letter: C, H, M, L, I
                relief=tk.RAISED if self.severity_toggles[sev].get() else tk.FLAT,
                bg=color if self.severity_toggles[sev].get() else GUI_DARK_THEME['button_bg'],
                fg='white',
                activebackground=color,
                command=lambda s=sev: self._toggle_severity(s)
            )
            btn.pack(side=tk.LEFT, padx=1)
            self.severity_buttons[sev] = btn

        # Quick select buttons
        ttk.Button(sev_row, text="All", width=3,
                  command=self._select_all_severities).pack(side=tk.LEFT, padx=(3, 1))
        ttk.Button(sev_row, text="None", width=4,
                  command=self._select_no_severities).pack(side=tk.LEFT, padx=1)

        # Two-column layout frame
        two_col_frame = ttk.Frame(filter_frame)
        two_col_frame.pack(fill=tk.X, pady=3)
        two_col_frame.columnconfigure(0, weight=1)
        two_col_frame.columnconfigure(1, weight=1)

        # Left column
        left_col = ttk.Frame(two_col_frame)
        left_col.grid(row=0, column=0, sticky='ew', padx=(0, 5))

        # Right column
        right_col = ttk.Frame(two_col_frame)
        right_col.grid(row=0, column=1, sticky='ew', padx=(5, 0))

        # Left Column Row 1: Status filter
        status_row = ttk.Frame(left_col)
        status_row.pack(fill=tk.X, pady=2)
        status_label = tk.Label(status_row, text="Status:", width=8, bg=self.filter_label_default_bg, fg='white', anchor='w')
        status_label.pack(side=tk.LEFT)
        self.filter_labels['status'] = status_label
        ttk.Combobox(status_row, textvariable=self.filter_status,
                    values=["All", "Active", "Resolved"], state="readonly", width=10).pack(side=tk.LEFT, padx=1, fill=tk.X, expand=True)

        # Right Column Row 1: Host Type
        type_row = ttk.Frame(right_col)
        type_row.pack(fill=tk.X, pady=2)
        type_label = tk.Label(type_row, text="Type:", width=8, bg=self.filter_label_default_bg, fg='white', anchor='w')
        type_label.pack(side=tk.LEFT)
        self.filter_labels['type'] = type_label
        ttk.Combobox(type_row, textvariable=self.filter_host_type,
                    values=["All", "Physical", "Virtual", "ILOM"], state="readonly", width=10).pack(side=tk.LEFT, padx=1, fill=tk.X, expand=True)

        # Left Column Row 2: Environment
        env_row = ttk.Frame(left_col)
        env_row.pack(fill=tk.X, pady=2)
        env_label = tk.Label(env_row, text="Env:", width=8, bg=self.filter_label_default_bg, fg='white', anchor='w')
        env_label.pack(side=tk.LEFT)
        self.filter_labels['env'] = env_label
        # Get environment types from settings
        # "All Combined" = show all environments as single dataset
        # "All Separate" = show all environments but grouped/broken down by environment
        env_types = ["All Combined", "All Separate"] + self.settings_manager.settings.environment_types
        self.env_combo = ttk.Combobox(env_row, textvariable=self.filter_env_type,
                    values=env_types, state="readonly", width=12)
        self.env_combo.pack(side=tk.LEFT, padx=1, fill=tk.X, expand=True)
        # Gear button with proper sizing
        tk.Button(env_row, text="⚙", command=self._show_environment_config,
                 bg=GUI_DARK_THEME['button_bg'], fg='white', relief='flat',
                 font=('Arial', 10), padx=4, pady=0).pack(side=tk.LEFT, padx=1)

        # Right Column Row 2: Location
        loc_row = ttk.Frame(right_col)
        loc_row.pack(fill=tk.X, pady=2)
        loc_label = tk.Label(loc_row, text="Loc:", width=8, bg=self.filter_label_default_bg, fg='white', anchor='w')
        loc_label.pack(side=tk.LEFT)
        self.filter_labels['location'] = loc_label
        ttk.Entry(loc_row, textvariable=self.filter_location, width=10).pack(side=tk.LEFT, padx=1, fill=tk.X, expand=True)

        # Left Column Row 3: Host Pattern
        host_row = ttk.Frame(left_col)
        host_row.pack(fill=tk.X, pady=2)
        host_label = tk.Label(host_row, text="Host:", width=8, bg=self.filter_label_default_bg, fg='white', anchor='w')
        host_label.pack(side=tk.LEFT)
        self.filter_labels['host'] = host_label
        ttk.Entry(host_row, textvariable=self.filter_host, width=10).pack(side=tk.LEFT, padx=1, fill=tk.X, expand=True)
        ttk.Button(host_row, text="...", command=self._show_host_selector, width=2).pack(side=tk.LEFT, padx=1)

        # Right Column Row 3: CVSS Range
        cvss_row = ttk.Frame(right_col)
        cvss_row.pack(fill=tk.X, pady=2)
        cvss_label = tk.Label(cvss_row, text="CVSS:", width=8, bg=self.filter_label_default_bg, fg='white', anchor='w')
        cvss_label.pack(side=tk.LEFT)
        self.filter_labels['cvss'] = cvss_label
        ttk.Entry(cvss_row, textvariable=self.filter_cvss_min, width=5).pack(side=tk.LEFT, padx=1)
        ttk.Label(cvss_row, text="-").pack(side=tk.LEFT)
        ttk.Entry(cvss_row, textvariable=self.filter_cvss_max, width=5).pack(side=tk.LEFT, padx=1, fill=tk.X, expand=True)

        # Left Column Row 4: OPDIR Status
        opdir_row = ttk.Frame(left_col)
        opdir_row.pack(fill=tk.X, pady=2)
        opdir_label = tk.Label(opdir_row, text="OPDIR:", width=8, bg=self.filter_label_default_bg, fg='white', anchor='w')
        opdir_label.pack(side=tk.LEFT)
        self.filter_labels['opdir'] = opdir_label
        opdir_options = ["All", "Overdue", "Due Soon", "On Track", "OPDIR Mapped", "No OPDIR"]
        ttk.Combobox(opdir_row, textvariable=self.filter_opdir_status,
                    values=opdir_options, state="readonly", width=10).pack(side=tk.LEFT, padx=1, fill=tk.X, expand=True)

        # Right Column Row 4: CVE filter
        cve_row = ttk.Frame(right_col)
        cve_row.pack(fill=tk.X, pady=2)
        cve_label = tk.Label(cve_row, text="CVE:", width=8, bg=self.filter_label_default_bg, fg='white', anchor='w')
        cve_label.pack(side=tk.LEFT)
        self.filter_labels['cve'] = cve_label
        ttk.Entry(cve_row, textvariable=self.filter_cve, width=15).pack(side=tk.LEFT, padx=1, fill=tk.X, expand=True)

        # Full width: IAVX filter
        iavx_row = ttk.Frame(filter_frame)
        iavx_row.pack(fill=tk.X, pady=2)
        iavx_label = tk.Label(iavx_row, text="IAVx:", width=8, bg=self.filter_label_default_bg, fg='white', anchor='w')
        iavx_label.pack(side=tk.LEFT)
        self.filter_labels['iavx'] = iavx_label
        ttk.Entry(iavx_row, textvariable=self.filter_iavx, width=15).pack(side=tk.LEFT, padx=1, fill=tk.X, expand=True)

        # Host count display
        self.host_count_label = ttk.Label(filter_frame, text="", foreground="cyan")
        self.host_count_label.pack(anchor=tk.W, pady=2)

        # Apply and Reset buttons
        btn_row = ttk.Frame(filter_frame)
        btn_row.pack(fill=tk.X, pady=3)
        ttk.Button(btn_row, text="Apply", command=self._apply_filters, width=10).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=1)
        ttk.Button(btn_row, text="Reset", command=self._reset_filters, width=10).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=1)

    def _build_action_buttons(self, parent):
        """Build action buttons section with compact 2-per-row layout."""
        action_frame = ttk.LabelFrame(parent, text="Actions", padding=5)
        action_frame.pack(fill=tk.X)

        # Row 1: Process + Refresh
        row1 = ttk.Frame(action_frame)
        row1.pack(fill=tk.X, pady=2)
        ttk.Button(row1, text="Process", command=self._process_archives).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=1)
        ttk.Button(row1, text="Refresh", command=self._refresh_analysis).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=1)

        # Row 2: Export Excel + Save SQLite
        row2 = ttk.Frame(action_frame)
        row2.pack(fill=tk.X, pady=2)
        ttk.Button(row2, text="Export Excel", command=self._export_excel).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=1)
        ttk.Button(row2, text="Save SQLite", command=self._export_sqlite).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=1)

        # Row 3: Save JSON + Settings
        row3 = ttk.Frame(action_frame)
        row3.pack(fill=tk.X, pady=2)
        ttk.Button(row3, text="Save JSON", command=self._export_json).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=1)
        ttk.Button(row3, text="Settings", command=self._show_settings_dialog).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=1)

        # Row 4: Package Impact Analysis
        row4 = ttk.Frame(action_frame)
        row4.pack(fill=tk.X, pady=2)
        ttk.Button(row4, text="Package Impact", command=self._show_package_impact).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=1)
        ttk.Button(row4, text="Filter Defaults", command=self._show_filter_defaults).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=1)

        # AI Predictions section
        ai_frame = ttk.LabelFrame(parent, text="AI Predictions", padding=5)
        ai_frame.pack(fill=tk.X, pady=(5, 0))

        # AI status indicator
        self.ai_status_frame = ttk.Frame(ai_frame)
        self.ai_status_frame.pack(fill=tk.X, pady=(0, 2))
        self.ai_status_label = ttk.Label(self.ai_status_frame, text="AI: Not configured", foreground="gray")
        self.ai_status_label.pack(side=tk.LEFT)

        # Row AI-1: AI Analysis + Configure
        ai_row1 = ttk.Frame(ai_frame)
        ai_row1.pack(fill=tk.X, pady=2)
        self.ai_analyze_btn = ttk.Button(ai_row1, text="AI Analysis", command=self._run_ai_analysis)
        self.ai_analyze_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=1)
        ttk.Button(ai_row1, text="Configure", command=self._show_ai_settings).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=1)

        # Row AI-2: Threat Intel
        ai_row2 = ttk.Frame(ai_frame)
        ai_row2.pack(fill=tk.X, pady=2)
        ttk.Button(ai_row2, text="Threat Feeds", command=self._show_threat_intel_dialog).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=1)
        ttk.Button(ai_row2, text="Sync Intel", command=self._quick_sync_threat_intel).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=1)

    def _build_logging_tab(self):
        """Build logging tab (formerly Status tab)."""
        logging_frame = ttk.Frame(self.notebook)
        self.notebook.add(logging_frame, text="Logging")

        self.status_text = tk.Text(logging_frame, wrap=tk.WORD,
                                   bg=GUI_DARK_THEME['text_bg'],
                                   fg=GUI_DARK_THEME['fg'],
                                   font=('Consolas', 10))
        self.status_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        scrollbar = ttk.Scrollbar(logging_frame, command=self.status_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.status_text.config(yscrollcommand=scrollbar.set)

    def _build_dashboard_tab(self):
        """Build dashboard tab with summary statistics."""
        dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text="Dashboard")
        self.dashboard_frame = dashboard_frame

        # Summary statistics frame
        stats_frame = ttk.LabelFrame(dashboard_frame, text="Summary Statistics", padding=10)
        stats_frame.pack(fill=tk.X, padx=10, pady=10)

        # Create grid of stat labels
        self.stat_labels = {}
        stats_config = [
            ('total_findings', 'Total Findings:', 0, 0),
            ('active_findings', 'Active:', 0, 1),
            ('resolved_findings', 'Resolved:', 0, 2),
            ('unique_hosts', 'Unique Hosts:', 1, 0),
            ('unique_plugins', 'Unique Plugins:', 1, 1),
            ('avg_days_open', 'Avg Days Open:', 1, 2),
        ]

        for key, label_text, row, col in stats_config:
            frame = ttk.Frame(stats_frame)
            frame.grid(row=row, column=col, padx=10, pady=5, sticky='w')
            ttk.Label(frame, text=label_text).pack(side=tk.LEFT)
            value_label = ttk.Label(frame, text="0", foreground="#00ff00")
            value_label.pack(side=tk.LEFT, padx=(5, 0))
            self.stat_labels[key] = value_label

        # Severity breakdown frame
        severity_frame = ttk.LabelFrame(dashboard_frame, text="Severity Breakdown", padding=10)
        severity_frame.pack(fill=tk.X, padx=10, pady=5)

        self.severity_labels = {}
        severity_colors = {'Critical': '#dc3545', 'High': '#fd7e14', 'Medium': '#ffc107', 'Low': '#007bff', 'Info': '#6c757d'}
        for i, sev in enumerate(['Critical', 'High', 'Medium', 'Low', 'Info']):
            frame = ttk.Frame(severity_frame)
            frame.grid(row=0, column=i, padx=15, pady=5)
            ttk.Label(frame, text=f"{sev}:").pack(side=tk.LEFT)
            value_label = ttk.Label(frame, text="0", foreground=severity_colors[sev])
            value_label.pack(side=tk.LEFT, padx=(5, 0))
            self.severity_labels[sev] = value_label

        # Host type breakdown frame
        host_type_frame = ttk.LabelFrame(dashboard_frame, text="Host Type Breakdown", padding=10)
        host_type_frame.pack(fill=tk.X, padx=10, pady=5)

        self.host_type_labels = {}
        for i, htype in enumerate(['Physical', 'Virtual', 'ILOM', 'Unknown']):
            frame = ttk.Frame(host_type_frame)
            frame.grid(row=0, column=i, padx=15, pady=5)
            ttk.Label(frame, text=f"{htype}:").pack(side=tk.LEFT)
            value_label = ttk.Label(frame, text="0", foreground="#00ff00")
            value_label.pack(side=tk.LEFT, padx=(5, 0))
            self.host_type_labels[htype] = value_label

        # Environment breakdown frame
        env_frame = ttk.LabelFrame(dashboard_frame, text="Environment Breakdown", padding=10)
        env_frame.pack(fill=tk.X, padx=10, pady=5)

        self.env_type_labels = {}
        env_colors = {'Production': '#28a745', 'PSS': '#007bff', 'Shared': '#ffc107', 'Unknown': '#6c757d'}
        for i, env in enumerate(['Production', 'PSS', 'Shared', 'Unknown']):
            frame = ttk.Frame(env_frame)
            frame.grid(row=0, column=i, padx=15, pady=5)
            ttk.Label(frame, text=f"{env}:").pack(side=tk.LEFT)
            value_label = ttk.Label(frame, text="0", foreground=env_colors.get(env, '#00ff00'))
            value_label.pack(side=tk.LEFT, padx=(5, 0))
            self.env_type_labels[env] = value_label

        # Filter status label
        filter_frame = ttk.Frame(dashboard_frame)
        filter_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(filter_frame, text="Filter Status:").pack(side=tk.LEFT)
        self.filter_status_label = ttk.Label(filter_frame, text="No filters applied", foreground="gray")
        self.filter_status_label.pack(side=tk.LEFT, padx=(5, 0))

        # Trends chart frame
        chart_frame = ttk.LabelFrame(dashboard_frame, text="Findings Trend Over Time", padding=5)
        chart_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        if HAS_MATPLOTLIB:
            # Create matplotlib figure for dark theme
            self.trends_fig = Figure(figsize=(8, 3), dpi=100, facecolor=GUI_DARK_THEME['bg'])
            self.trends_ax = self.trends_fig.add_subplot(111)
            self.trends_ax.set_facecolor(GUI_DARK_THEME['entry_bg'])
            self.trends_ax.tick_params(colors=GUI_DARK_THEME['fg'])
            for spine in self.trends_ax.spines.values():
                spine.set_color(GUI_DARK_THEME['fg'])

            self.trends_canvas = FigureCanvasTkAgg(self.trends_fig, master=chart_frame)
            self.trends_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        else:
            ttk.Label(chart_frame, text="Install matplotlib for trend charts: pip install matplotlib").pack(pady=20)

    def _build_lifecycle_tab(self):
        """Build lifecycle analysis tab with treeview."""
        lifecycle_frame = ttk.Frame(self.notebook)
        self.notebook.add(lifecycle_frame, text="Lifecycle")
        self.lifecycle_frame = lifecycle_frame

        # Navigation controls frame
        nav_frame = ttk.Frame(lifecycle_frame)
        nav_frame.pack(fill=tk.X, padx=5, pady=5)

        # Left side: count label and status toggles
        left_frame = ttk.Frame(nav_frame)
        left_frame.pack(side=tk.LEFT)

        self.lifecycle_count_label = ttk.Label(left_frame, text="Showing 0 findings")
        self.lifecycle_count_label.pack(side=tk.LEFT, padx=(0, 15))

        # Status toggle buttons
        ttk.Checkbutton(left_frame, text="Active", variable=self.lifecycle_show_active,
                       command=self._lifecycle_status_changed).pack(side=tk.LEFT, padx=2)
        ttk.Checkbutton(left_frame, text="Resolved", variable=self.lifecycle_show_resolved,
                       command=self._lifecycle_status_changed).pack(side=tk.LEFT, padx=2)

        # Right side: navigation controls
        nav_controls = ttk.Frame(nav_frame)
        nav_controls.pack(side=tk.RIGHT)

        # Page size dropdown
        ttk.Label(nav_controls, text="Show:").pack(side=tk.LEFT, padx=(0, 2))
        page_sizes = [50, 100, 250, 500, 1000, 0]  # 0 = All
        page_combo = ttk.Combobox(nav_controls, textvariable=self.lifecycle_page_size,
                                   values=page_sizes, width=5, state="readonly")
        page_combo.pack(side=tk.LEFT, padx=(0, 10))
        page_combo.bind("<<ComboboxSelected>>", lambda e: self._lifecycle_page_changed())

        # Navigation buttons: |< < > >|
        ttk.Button(nav_controls, text="|<", width=2,
                   command=self._lifecycle_first_page).pack(side=tk.LEFT, padx=1)
        ttk.Button(nav_controls, text="<", width=2,
                   command=self._lifecycle_prev_page).pack(side=tk.LEFT, padx=1)
        ttk.Button(nav_controls, text=">", width=2,
                   command=self._lifecycle_next_page).pack(side=tk.LEFT, padx=1)
        ttk.Button(nav_controls, text=">|", width=2,
                   command=self._lifecycle_last_page).pack(side=tk.LEFT, padx=(1, 10))

        # Jump to row
        ttk.Label(nav_controls, text="Jump to:").pack(side=tk.LEFT, padx=(0, 2))
        jump_entry = ttk.Entry(nav_controls, textvariable=self.lifecycle_jump_to, width=6)
        jump_entry.pack(side=tk.LEFT, padx=(0, 2))
        jump_entry.bind("<Return>", lambda e: self._lifecycle_jump())
        ttk.Button(nav_controls, text="Go", width=3,
                   command=self._lifecycle_jump).pack(side=tk.LEFT)

        # Treeview with scrollbars
        tree_frame = ttk.Frame(lifecycle_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Define columns
        columns = ('hostname', 'plugin_id', 'name', 'severity', 'status', 'first_seen', 'last_seen', 'days_open')
        self.lifecycle_tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=20)

        # Configure columns
        col_config = {
            'hostname': ('Hostname', 100),
            'plugin_id': ('Plugin ID', 70),
            'name': ('Name', 250),
            'severity': ('Severity', 70),
            'status': ('Status', 70),
            'first_seen': ('First Seen', 90),
            'last_seen': ('Last Seen', 90),
            'days_open': ('Days Open', 70)
        }

        for col, (heading, width) in col_config.items():
            self.lifecycle_tree.heading(col, text=heading, command=lambda c=col: self._sort_lifecycle_tree(c))
            self.lifecycle_tree.column(col, width=width, minwidth=50)

        # Scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.lifecycle_tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.lifecycle_tree.xview)
        self.lifecycle_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        # Grid layout
        self.lifecycle_tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        # Bind double-click to show finding details
        self.lifecycle_tree.bind('<Double-1>', self._show_finding_detail)

        # Configure treeview colors for dark theme
        style = ttk.Style()
        style.configure("Treeview",
                       background=GUI_DARK_THEME['entry_bg'],
                       foreground=GUI_DARK_THEME['fg'],
                       fieldbackground=GUI_DARK_THEME['entry_bg'])
        style.configure("Treeview.Heading",
                       background=GUI_DARK_THEME['button_bg'],
                       foreground=GUI_DARK_THEME['fg'])

    def _build_host_tab(self):
        """Build host analysis tab with treeview."""
        host_frame = ttk.Frame(self.notebook)
        self.notebook.add(host_frame, text="Hosts")
        self.host_frame = host_frame

        # Info and toggle frame
        info_frame = ttk.Frame(host_frame)
        info_frame.pack(fill=tk.X, padx=5, pady=5)

        self.host_count_label = ttk.Label(info_frame, text="Showing 0 hosts")
        self.host_count_label.pack(side=tk.LEFT, padx=(0, 15))

        # Host status toggle buttons
        ttk.Checkbutton(info_frame, text="Active", variable=self.host_show_active,
                       command=self._host_status_changed).pack(side=tk.LEFT, padx=2)
        ttk.Checkbutton(info_frame, text="Missing", variable=self.host_show_missing,
                       command=self._host_status_changed).pack(side=tk.LEFT, padx=2)

        # Treeview with scrollbars
        tree_frame = ttk.Frame(host_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Define columns
        columns = ('hostname', 'ip_address', 'status', 'first_seen', 'last_seen', 'scan_count', 'presence_pct', 'host_type')
        self.host_tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=20)

        # Configure columns
        col_config = {
            'hostname': ('Hostname', 120),
            'ip_address': ('IP Address', 100),
            'status': ('Status', 70),
            'first_seen': ('First Seen', 90),
            'last_seen': ('Last Seen', 90),
            'scan_count': ('Scans', 60),
            'presence_pct': ('Presence %', 80),
            'host_type': ('Type', 70)
        }

        for col, (heading, width) in col_config.items():
            self.host_tree.heading(col, text=heading, command=lambda c=col: self._sort_host_tree(c))
            self.host_tree.column(col, width=width, minwidth=50)

        # Scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.host_tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.host_tree.xview)
        self.host_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        # Grid layout
        self.host_tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

    def _build_timeline_tab(self):
        """Build timeline analysis visualization tab."""
        timeline_frame = ttk.Frame(self.notebook)
        self.notebook.add(timeline_frame, text="Timeline")
        self.timeline_frame = timeline_frame

        if HAS_MATPLOTLIB:
            # Create 2x2 grid of charts
            self.timeline_fig = Figure(figsize=(10, 8), dpi=100, facecolor=GUI_DARK_THEME['bg'])

            # Total findings over time
            self.timeline_ax1 = self.timeline_fig.add_subplot(221)
            self.timeline_ax1.set_title('Total Findings Over Time', color=GUI_DARK_THEME['fg'])

            # Severity breakdown over time
            self.timeline_ax2 = self.timeline_fig.add_subplot(222)
            self.timeline_ax2.set_title('Findings by Severity', color=GUI_DARK_THEME['fg'])

            # New vs Resolved by month
            self.timeline_ax3 = self.timeline_fig.add_subplot(223)
            self.timeline_ax3.set_title('New vs Resolved', color=GUI_DARK_THEME['fg'])

            # Cumulative risk
            self.timeline_ax4 = self.timeline_fig.add_subplot(224)
            self.timeline_ax4.set_title('Cumulative Risk Exposure', color=GUI_DARK_THEME['fg'])

            for ax in [self.timeline_ax1, self.timeline_ax2, self.timeline_ax3, self.timeline_ax4]:
                ax.set_facecolor(GUI_DARK_THEME['entry_bg'])
                ax.tick_params(colors=GUI_DARK_THEME['fg'])
                for spine in ax.spines.values():
                    spine.set_color(GUI_DARK_THEME['fg'])

            self.timeline_canvas = FigureCanvasTkAgg(self.timeline_fig, master=timeline_frame)
            self.timeline_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

            # Bind double-click for pop-out
            hint = ttk.Label(timeline_frame, text="Double-click chart to pop-out",
                            font=('Arial', 8), foreground='gray')
            hint.pack(anchor=tk.SE, padx=5)
            self._bind_chart_popouts_timeline()
        else:
            ttk.Label(timeline_frame, text="Install matplotlib for visualizations").pack(pady=50)

    def _build_risk_tab(self):
        """Build risk analysis visualization tab."""
        risk_frame = ttk.Frame(self.notebook)
        self.notebook.add(risk_frame, text="Risk")
        self.risk_frame = risk_frame

        if HAS_MATPLOTLIB:
            self.risk_fig = Figure(figsize=(10, 8), dpi=100, facecolor=GUI_DARK_THEME['bg'])

            # CVSS distribution histogram
            self.risk_ax1 = self.risk_fig.add_subplot(221)
            self.risk_ax1.set_title('CVSS Score Distribution', color=GUI_DARK_THEME['fg'])

            # Mean time to remediation by severity
            self.risk_ax2 = self.risk_fig.add_subplot(222)
            self.risk_ax2.set_title('Mean Time to Remediation', color=GUI_DARK_THEME['fg'])

            # Risk by age bucket
            self.risk_ax3 = self.risk_fig.add_subplot(223)
            self.risk_ax3.set_title('Findings by Age', color=GUI_DARK_THEME['fg'])

            # Top risky hosts by environment
            self.risk_ax4 = self.risk_fig.add_subplot(224)
            self.risk_ax4.set_title('Top Risky Hosts by Environment', color=GUI_DARK_THEME['fg'])

            for ax in [self.risk_ax1, self.risk_ax2, self.risk_ax3, self.risk_ax4]:
                ax.set_facecolor(GUI_DARK_THEME['entry_bg'])
                ax.tick_params(colors=GUI_DARK_THEME['fg'])
                for spine in ax.spines.values():
                    spine.set_color(GUI_DARK_THEME['fg'])

            self.risk_canvas = FigureCanvasTkAgg(self.risk_fig, master=risk_frame)
            self.risk_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

            # Bind double-click for pop-out (hint label)
            hint = ttk.Label(risk_frame, text="Double-click chart to pop-out",
                            font=('Arial', 8), foreground='gray')
            hint.pack(anchor=tk.SE, padx=5)
            self._bind_chart_popouts_risk()
        else:
            ttk.Label(risk_frame, text="Install matplotlib for visualizations").pack(pady=50)

    def _build_opdir_tab(self):
        """Build OPDIR compliance visualization tab."""
        opdir_frame = ttk.Frame(self.notebook)
        self.notebook.add(opdir_frame, text="OPDIR")
        self.opdir_frame = opdir_frame

        if HAS_MATPLOTLIB:
            self.opdir_fig = Figure(figsize=(10, 8), dpi=100, facecolor=GUI_DARK_THEME['bg'])

            # OPDIR coverage pie
            self.opdir_ax1 = self.opdir_fig.add_subplot(221)
            self.opdir_ax1.set_title('OPDIR Mapping Coverage', color=GUI_DARK_THEME['fg'])

            # OPDIR status distribution
            self.opdir_ax2 = self.opdir_fig.add_subplot(222)
            self.opdir_ax2.set_title('OPDIR Status Distribution', color=GUI_DARK_THEME['fg'])

            # Timeline vs age scatter
            self.opdir_ax3 = self.opdir_fig.add_subplot(223)
            self.opdir_ax3.set_title('OPDIR Timeline vs Finding Age', color=GUI_DARK_THEME['fg'])

            # Compliance by year
            self.opdir_ax4 = self.opdir_fig.add_subplot(224)
            self.opdir_ax4.set_title('Compliance by OPDIR Year', color=GUI_DARK_THEME['fg'])

            for ax in [self.opdir_ax1, self.opdir_ax2, self.opdir_ax3, self.opdir_ax4]:
                ax.set_facecolor(GUI_DARK_THEME['entry_bg'])
                ax.tick_params(colors=GUI_DARK_THEME['fg'])
                for spine in ax.spines.values():
                    spine.set_color(GUI_DARK_THEME['fg'])

            self.opdir_canvas = FigureCanvasTkAgg(self.opdir_fig, master=opdir_frame)
            self.opdir_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

            # Bind double-click for pop-out
            hint = ttk.Label(opdir_frame, text="Double-click chart to pop-out",
                            font=('Arial', 8), foreground='gray')
            hint.pack(anchor=tk.SE, padx=5)
            self._bind_chart_popouts_opdir()
        else:
            ttk.Label(opdir_frame, text="Install matplotlib for visualizations").pack(pady=50)

    def _build_efficiency_tab(self):
        """Build operational efficiency visualization tab."""
        efficiency_frame = ttk.Frame(self.notebook)
        self.notebook.add(efficiency_frame, text="Efficiency")
        self.efficiency_frame = efficiency_frame

        if HAS_MATPLOTLIB:
            self.efficiency_fig = Figure(figsize=(10, 8), dpi=100, facecolor=GUI_DARK_THEME['bg'])

            # Scan coverage consistency
            self.efficiency_ax1 = self.efficiency_fig.add_subplot(221)
            self.efficiency_ax1.set_title('Scan Coverage Consistency', color=GUI_DARK_THEME['fg'])

            # False positive analysis (reappearances)
            self.efficiency_ax2 = self.efficiency_fig.add_subplot(222)
            self.efficiency_ax2.set_title('Reappearance Analysis', color=GUI_DARK_THEME['fg'])

            # Host vulnerability burden
            self.efficiency_ax3 = self.efficiency_fig.add_subplot(223)
            self.efficiency_ax3.set_title('Host Vulnerability Burden', color=GUI_DARK_THEME['fg'])

            # Scan quality
            self.efficiency_ax4 = self.efficiency_fig.add_subplot(224)
            self.efficiency_ax4.set_title('Resolution Velocity', color=GUI_DARK_THEME['fg'])

            for ax in [self.efficiency_ax1, self.efficiency_ax2, self.efficiency_ax3, self.efficiency_ax4]:
                ax.set_facecolor(GUI_DARK_THEME['entry_bg'])
                ax.tick_params(colors=GUI_DARK_THEME['fg'])
                for spine in ax.spines.values():
                    spine.set_color(GUI_DARK_THEME['fg'])

            self.efficiency_canvas = FigureCanvasTkAgg(self.efficiency_fig, master=efficiency_frame)
            self.efficiency_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

            # Bind double-click for pop-out
            hint = ttk.Label(efficiency_frame, text="Double-click chart to pop-out",
                            font=('Arial', 8), foreground='gray')
            hint.pack(anchor=tk.SE, padx=5)
            self._bind_chart_popouts_efficiency()
        else:
            ttk.Label(efficiency_frame, text="Install matplotlib for visualizations").pack(pady=50)

    def _build_network_tab(self):
        """Build network analysis visualization tab."""
        network_frame = ttk.Frame(self.notebook)
        self.notebook.add(network_frame, text="Network")
        self.network_frame = network_frame

        if HAS_MATPLOTLIB:
            self.network_fig = Figure(figsize=(10, 8), dpi=100, facecolor=GUI_DARK_THEME['bg'])

            # Top subnets
            self.network_ax1 = self.network_fig.add_subplot(221)
            self.network_ax1.set_title('Top Subnets by Vulnerability', color=GUI_DARK_THEME['fg'])

            # Subnet risk heat map
            self.network_ax2 = self.network_fig.add_subplot(222)
            self.network_ax2.set_title('Subnet Risk Scores', color=GUI_DARK_THEME['fg'])

            # Host criticality
            self.network_ax3 = self.network_fig.add_subplot(223)
            self.network_ax3.set_title('Host Criticality Distribution', color=GUI_DARK_THEME['fg'])

            # Network segments
            self.network_ax4 = self.network_fig.add_subplot(224)
            self.network_ax4.set_title('Network Segment Analysis', color=GUI_DARK_THEME['fg'])

            for ax in [self.network_ax1, self.network_ax2, self.network_ax3, self.network_ax4]:
                ax.set_facecolor(GUI_DARK_THEME['entry_bg'])
                ax.tick_params(colors=GUI_DARK_THEME['fg'])
                for spine in ax.spines.values():
                    spine.set_color(GUI_DARK_THEME['fg'])

            self.network_canvas = FigureCanvasTkAgg(self.network_fig, master=network_frame)
            self.network_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

            # Bind double-click for pop-out
            hint = ttk.Label(network_frame, text="Double-click chart to pop-out",
                            font=('Arial', 8), foreground='gray')
            hint.pack(anchor=tk.SE, padx=5)
            self._bind_chart_popouts_network()
        else:
            ttk.Label(network_frame, text="Install matplotlib for visualizations").pack(pady=50)

    def _build_plugin_tab(self):
        """Build plugin analysis visualization tab."""
        plugin_frame = ttk.Frame(self.notebook)
        self.notebook.add(plugin_frame, text="Plugins")
        self.plugin_frame = plugin_frame

        if HAS_MATPLOTLIB:
            self.plugin_fig = Figure(figsize=(10, 8), dpi=100, facecolor=GUI_DARK_THEME['bg'])

            # Top recurring plugins by environment
            self.plugin_ax1 = self.plugin_fig.add_subplot(221)
            self.plugin_ax1.set_title('Top Plugins by Environment', color=GUI_DARK_THEME['fg'])

            # Plugin severity distribution
            self.plugin_ax2 = self.plugin_fig.add_subplot(222)
            self.plugin_ax2.set_title('Plugin Severity Distribution', color=GUI_DARK_THEME['fg'])

            # Plugins by host count
            self.plugin_ax3 = self.plugin_fig.add_subplot(223)
            self.plugin_ax3.set_title('Plugins Affecting Most Hosts', color=GUI_DARK_THEME['fg'])

            # Plugin age analysis
            self.plugin_ax4 = self.plugin_fig.add_subplot(224)
            self.plugin_ax4.set_title('Plugin Avg Age (Days Open)', color=GUI_DARK_THEME['fg'])

            for ax in [self.plugin_ax1, self.plugin_ax2, self.plugin_ax3, self.plugin_ax4]:
                ax.set_facecolor(GUI_DARK_THEME['entry_bg'])
                ax.tick_params(colors=GUI_DARK_THEME['fg'])
                for spine in ax.spines.values():
                    spine.set_color(GUI_DARK_THEME['fg'])

            self.plugin_canvas = FigureCanvasTkAgg(self.plugin_fig, master=plugin_frame)
            self.plugin_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

            # Create tooltip label for plugin hover
            self._plugin_tooltip = None
            self._plugin_name_map = {}

            # Bind mouse motion for plugin name tooltip
            def on_plugin_hover(event):
                if not hasattr(self, '_plugin_name_map') or not self._plugin_name_map:
                    return
                # Check if mouse is over any of the plugin chart axes
                for ax in [self.plugin_ax1, self.plugin_ax3, self.plugin_ax4]:
                    if event.inaxes == ax:
                        # Check if we're near a y-tick label
                        y_data = event.ydata
                        if y_data is not None:
                            y_idx = int(round(y_data))
                            labels = [t.get_text() for t in ax.get_yticklabels()]
                            if 0 <= y_idx < len(labels):
                                plugin_id = labels[y_idx]
                                if plugin_id in self._plugin_name_map:
                                    name = self._plugin_name_map[plugin_id]
                                    self._show_plugin_tooltip(event, f"ID: {plugin_id}\n{name}")
                                    return
                self._hide_plugin_tooltip()

            self.plugin_fig.canvas.mpl_connect('motion_notify_event', on_plugin_hover)

            # Bind double-click for pop-out
            hint = ttk.Label(plugin_frame, text="Double-click chart to pop-out | Hover over bars for plugin names",
                            font=('Arial', 8), foreground='gray')
            hint.pack(anchor=tk.SE, padx=5)
            self._bind_chart_popouts_plugin()
        else:
            ttk.Label(plugin_frame, text="Install matplotlib for visualizations").pack(pady=50)

    def _build_priority_tab(self):
        """Build remediation priority visualization tab (CVSS vs Age quadrant)."""
        priority_frame = ttk.Frame(self.notebook)
        self.notebook.add(priority_frame, text="Priority")
        self.priority_frame = priority_frame

        if HAS_MATPLOTLIB:
            self.priority_fig = Figure(figsize=(10, 8), dpi=100, facecolor=GUI_DARK_THEME['bg'])

            # Main quadrant chart - CVSS vs Days Open
            self.priority_ax1 = self.priority_fig.add_subplot(221)
            self.priority_ax1.set_title('Remediation Priority Matrix', color=GUI_DARK_THEME['fg'])

            # Priority distribution pie
            self.priority_ax2 = self.priority_fig.add_subplot(222)
            self.priority_ax2.set_title('Priority Distribution', color=GUI_DARK_THEME['fg'])

            # Top priority findings
            self.priority_ax3 = self.priority_fig.add_subplot(223)
            self.priority_ax3.set_title('Top 10 Priority Findings', color=GUI_DARK_THEME['fg'])

            # Priority by severity
            self.priority_ax4 = self.priority_fig.add_subplot(224)
            self.priority_ax4.set_title('Priority Score by Severity', color=GUI_DARK_THEME['fg'])

            for ax in [self.priority_ax1, self.priority_ax2, self.priority_ax3, self.priority_ax4]:
                ax.set_facecolor(GUI_DARK_THEME['entry_bg'])
                ax.tick_params(colors=GUI_DARK_THEME['fg'])
                for spine in ax.spines.values():
                    spine.set_color(GUI_DARK_THEME['fg'])

            self.priority_canvas = FigureCanvasTkAgg(self.priority_fig, master=priority_frame)
            self.priority_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

            # Bind double-click for pop-out
            hint = ttk.Label(priority_frame, text="Double-click chart to pop-out",
                            font=('Arial', 8), foreground='gray')
            hint.pack(anchor=tk.SE, padx=5)
            self._bind_chart_popouts_priority()
        else:
            ttk.Label(priority_frame, text="Install matplotlib for visualizations").pack(pady=50)

    def _build_sla_tab(self):
        """Build SLA compliance visualization tab."""
        sla_frame = ttk.Frame(self.notebook)
        self.notebook.add(sla_frame, text="SLA")
        self.sla_frame = sla_frame

        # SLA Targets info at top
        info_frame = ttk.LabelFrame(sla_frame, text="SLA Targets (Days)", padding=5)
        info_frame.pack(fill=tk.X, padx=10, pady=5)

        sla_info = ttk.Frame(info_frame)
        sla_info.pack(fill=tk.X)
        for i, (sev, days) in enumerate(SLA_TARGETS_DAYS.items()):
            if days is not None:
                color = {'Critical': '#dc3545', 'High': '#fd7e14', 'Medium': '#ffc107', 'Low': '#007bff'}.get(sev, 'white')
                ttk.Label(sla_info, text=f"{sev}: {days}d", foreground=color).grid(row=0, column=i, padx=10)

        if HAS_MATPLOTLIB:
            chart_frame = ttk.Frame(sla_frame)
            chart_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

            self.sla_fig = Figure(figsize=(10, 7), dpi=100, facecolor=GUI_DARK_THEME['bg'])

            # SLA Status overview
            self.sla_ax1 = self.sla_fig.add_subplot(221)
            self.sla_ax1.set_title('SLA Compliance Status', color=GUI_DARK_THEME['fg'])

            # Overdue by severity
            self.sla_ax2 = self.sla_fig.add_subplot(222)
            self.sla_ax2.set_title('Overdue Findings by Severity', color=GUI_DARK_THEME['fg'])

            # Approaching deadline
            self.sla_ax3 = self.sla_fig.add_subplot(223)
            self.sla_ax3.set_title('Approaching SLA Deadline', color=GUI_DARK_THEME['fg'])

            # SLA breach trend
            self.sla_ax4 = self.sla_fig.add_subplot(224)
            self.sla_ax4.set_title('Days Until/Past SLA by Finding', color=GUI_DARK_THEME['fg'])

            for ax in [self.sla_ax1, self.sla_ax2, self.sla_ax3, self.sla_ax4]:
                ax.set_facecolor(GUI_DARK_THEME['entry_bg'])
                ax.tick_params(colors=GUI_DARK_THEME['fg'])
                for spine in ax.spines.values():
                    spine.set_color(GUI_DARK_THEME['fg'])

            self.sla_canvas = FigureCanvasTkAgg(self.sla_fig, master=chart_frame)
            self.sla_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

            # Bind double-click for pop-out
            hint = ttk.Label(chart_frame, text="Double-click chart to pop-out",
                            font=('Arial', 8), foreground='gray')
            hint.pack(anchor=tk.SE, padx=5)
            self._bind_chart_popouts_sla()
        else:
            ttk.Label(sla_frame, text="Install matplotlib for visualizations").pack(pady=50)

    def _build_metrics_tab(self):
        """Build advanced metrics visualization tab with industry best practices."""
        metrics_frame = ttk.Frame(self.notebook)
        self.notebook.add(metrics_frame, text="Metrics")
        self.metrics_frame = metrics_frame

        # Summary stats panel at top
        summary_frame = ttk.LabelFrame(metrics_frame, text="Key Performance Indicators", padding=5)
        summary_frame.pack(fill=tk.X, padx=10, pady=5)

        # KPI labels - will be updated with real data
        kpi_row = ttk.Frame(summary_frame)
        kpi_row.pack(fill=tk.X)

        self.kpi_labels = {}
        kpi_defs = [
            ('reopen_rate', 'Reopen Rate', '#ffc107'),
            ('remediation_rate', 'Remediation Rate', '#28a745'),
            ('breach_rate', 'SLA Breach Rate', '#dc3545'),
            ('vulns_per_host', 'Vulns/Host', '#007bff'),
            ('coverage', 'Scan Coverage', '#17a2b8')
        ]

        for i, (key, label, color) in enumerate(kpi_defs):
            frame = ttk.Frame(kpi_row)
            frame.grid(row=0, column=i, padx=10, pady=2)
            ttk.Label(frame, text=label, font=('Arial', 8)).pack()
            self.kpi_labels[key] = ttk.Label(frame, text="--", font=('Arial', 14, 'bold'), foreground=color)
            self.kpi_labels[key].pack()

        if HAS_MATPLOTLIB:
            chart_frame = ttk.Frame(metrics_frame)
            chart_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

            self.metrics_fig = Figure(figsize=(10, 8), dpi=100, facecolor=GUI_DARK_THEME['bg'])

            # Remediation Rate by Severity
            self.metrics_ax1 = self.metrics_fig.add_subplot(221)
            self.metrics_ax1.set_title('Remediation Rate by Severity', color=GUI_DARK_THEME['fg'])

            # Risk Trend Over Time
            self.metrics_ax2 = self.metrics_fig.add_subplot(222)
            self.metrics_ax2.set_title('Risk Score Trend', color=GUI_DARK_THEME['fg'])

            # SLA Breach by Severity
            self.metrics_ax3 = self.metrics_fig.add_subplot(223)
            self.metrics_ax3.set_title('SLA Status by Severity', color=GUI_DARK_THEME['fg'])

            # Normalized Metrics Trend (vulns per host)
            self.metrics_ax4 = self.metrics_fig.add_subplot(224)
            self.metrics_ax4.set_title('Vulnerabilities per Host Trend', color=GUI_DARK_THEME['fg'])

            for ax in [self.metrics_ax1, self.metrics_ax2, self.metrics_ax3, self.metrics_ax4]:
                ax.set_facecolor(GUI_DARK_THEME['entry_bg'])
                ax.tick_params(colors=GUI_DARK_THEME['fg'])
                for spine in ax.spines.values():
                    spine.set_color(GUI_DARK_THEME['fg'])

            self.metrics_canvas = FigureCanvasTkAgg(self.metrics_fig, master=chart_frame)
            self.metrics_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

            # Bind double-click for pop-out
            hint = ttk.Label(metrics_frame, text="Double-click chart to pop-out",
                            font=('Arial', 8), foreground='gray')
            hint.pack(anchor=tk.SE, padx=5)
            self._bind_chart_popouts_metrics()
        else:
            ttk.Label(metrics_frame, text="Install matplotlib for visualizations").pack(pady=50)

    def _build_host_tracking_tab(self):
        """Build host tracking visualization tab."""
        host_tracking_frame = ttk.Frame(self.notebook)
        self.notebook.add(host_tracking_frame, text="Host Track")
        self.host_tracking_frame = host_tracking_frame

        if HAS_MATPLOTLIB:
            self.host_tracking_fig = Figure(figsize=(10, 8), dpi=100, facecolor=GUI_DARK_THEME['bg'])

            # Missing hosts (dropped from recent scans)
            self.host_tracking_ax1 = self.host_tracking_fig.add_subplot(221)
            self.host_tracking_ax1.set_title('Hosts Missing from Recent Scans', color=GUI_DARK_THEME['fg'])

            # Host presence trend
            self.host_tracking_ax2 = self.host_tracking_fig.add_subplot(222)
            self.host_tracking_ax2.set_title('Host Presence Over Time', color=GUI_DARK_THEME['fg'])

            # Declining presence hosts
            self.host_tracking_ax3 = self.host_tracking_fig.add_subplot(223)
            self.host_tracking_ax3.set_title('Hosts with Declining Presence', color=GUI_DARK_THEME['fg'])

            # Host status distribution
            self.host_tracking_ax4 = self.host_tracking_fig.add_subplot(224)
            self.host_tracking_ax4.set_title('Host Status Distribution', color=GUI_DARK_THEME['fg'])

            for ax in [self.host_tracking_ax1, self.host_tracking_ax2, self.host_tracking_ax3, self.host_tracking_ax4]:
                ax.set_facecolor(GUI_DARK_THEME['entry_bg'])
                ax.tick_params(colors=GUI_DARK_THEME['fg'])
                for spine in ax.spines.values():
                    spine.set_color(GUI_DARK_THEME['fg'])

            self.host_tracking_canvas = FigureCanvasTkAgg(self.host_tracking_fig, master=host_tracking_frame)
            self.host_tracking_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

            # Bind double-click for pop-out
            hint = ttk.Label(host_tracking_frame, text="Double-click chart to pop-out",
                            font=('Arial', 8), foreground='gray')
            hint.pack(anchor=tk.SE, padx=5)
            self._bind_chart_popouts_host_tracking()
        else:
            ttk.Label(host_tracking_frame, text="Install matplotlib for visualizations").pack(pady=50)

    def _build_advanced_tab(self):
        """Build advanced analytics visualization tab with 8 advanced charts."""
        advanced_frame = ttk.Frame(self.notebook)
        self.notebook.add(advanced_frame, text="Advanced")
        self.advanced_frame = advanced_frame

        if HAS_MATPLOTLIB:
            # Create sub-notebook for different visualization categories
            self.advanced_notebook = ttk.Notebook(advanced_frame)
            self.advanced_notebook.pack(fill=tk.BOTH, expand=True)

            # Page 1: Heatmap & Bubble Chart (Risk Analysis)
            risk_page = ttk.Frame(self.advanced_notebook)
            self.advanced_notebook.add(risk_page, text="Risk Analysis")

            self.advanced_fig1 = Figure(figsize=(12, 5), dpi=100, facecolor=GUI_DARK_THEME['bg'])
            self.heatmap_ax = self.advanced_fig1.add_subplot(121)
            self.heatmap_ax.set_title('Risk Heatmap by Subnet/Time', color=GUI_DARK_THEME['fg'])
            self.bubble_ax = self.advanced_fig1.add_subplot(122)
            self.bubble_ax.set_title('CVSS vs Age vs Impact', color=GUI_DARK_THEME['fg'])
            for ax in [self.heatmap_ax, self.bubble_ax]:
                ax.set_facecolor(GUI_DARK_THEME['entry_bg'])
                ax.tick_params(colors=GUI_DARK_THEME['fg'])
                for spine in ax.spines.values():
                    spine.set_color(GUI_DARK_THEME['fg'])
            self.advanced_canvas1 = FigureCanvasTkAgg(self.advanced_fig1, master=risk_page)
            self.advanced_canvas1.get_tk_widget().pack(fill=tk.BOTH, expand=True)

            hint1 = ttk.Label(risk_page, text="Double-click chart to pop-out",
                             font=('Arial', 8), foreground='gray')
            hint1.pack(anchor=tk.SE, padx=5)
            self._bind_chart_popouts_advanced_risk()

            # Page 2: Sankey & Treemap (Composition)
            comp_page = ttk.Frame(self.advanced_notebook)
            self.advanced_notebook.add(comp_page, text="Composition")

            self.advanced_fig2 = Figure(figsize=(12, 5), dpi=100, facecolor=GUI_DARK_THEME['bg'])
            self.sankey_ax = self.advanced_fig2.add_subplot(121)
            self.sankey_ax.set_title('Vulnerability Lifecycle Flow', color=GUI_DARK_THEME['fg'])
            self.treemap_ax = self.advanced_fig2.add_subplot(122)
            self.treemap_ax.set_title('Plugin Family Treemap', color=GUI_DARK_THEME['fg'])
            for ax in [self.sankey_ax, self.treemap_ax]:
                ax.set_facecolor(GUI_DARK_THEME['entry_bg'])
                ax.tick_params(colors=GUI_DARK_THEME['fg'])
                for spine in ax.spines.values():
                    spine.set_color(GUI_DARK_THEME['fg'])
            self.advanced_canvas2 = FigureCanvasTkAgg(self.advanced_fig2, master=comp_page)
            self.advanced_canvas2.get_tk_widget().pack(fill=tk.BOTH, expand=True)

            hint2 = ttk.Label(comp_page, text="Double-click chart to pop-out",
                             font=('Arial', 8), foreground='gray')
            hint2.pack(anchor=tk.SE, padx=5)
            self._bind_chart_popouts_advanced_comp()

            # Page 3: Radar & Gauge (Health Indicators)
            health_page = ttk.Frame(self.advanced_notebook)
            self.advanced_notebook.add(health_page, text="Health Indicators")

            self.advanced_fig3 = Figure(figsize=(12, 5), dpi=100, facecolor=GUI_DARK_THEME['bg'])
            self.radar_ax = self.advanced_fig3.add_subplot(121, projection='polar')
            self.radar_ax.set_title('Subnet Risk Profile', color=GUI_DARK_THEME['fg'], pad=20)
            self.radar_ax.set_facecolor(GUI_DARK_THEME['entry_bg'])
            self.gauge_ax = self.advanced_fig3.add_subplot(122)
            self.gauge_ax.set_title('Remediation Velocity', color=GUI_DARK_THEME['fg'])
            self.gauge_ax.set_facecolor(GUI_DARK_THEME['entry_bg'])
            self.gauge_ax.tick_params(colors=GUI_DARK_THEME['fg'])
            for spine in self.gauge_ax.spines.values():
                spine.set_color(GUI_DARK_THEME['fg'])
            self.advanced_canvas3 = FigureCanvasTkAgg(self.advanced_fig3, master=health_page)
            self.advanced_canvas3.get_tk_widget().pack(fill=tk.BOTH, expand=True)

            hint3 = ttk.Label(health_page, text="Double-click chart to pop-out",
                             font=('Arial', 8), foreground='gray')
            hint3.pack(anchor=tk.SE, padx=5)
            self._bind_chart_popouts_advanced_health()

            # Page 4: Prediction & Comparison (Trends)
            trend_page = ttk.Frame(self.advanced_notebook)
            self.advanced_notebook.add(trend_page, text="Trends & Prediction")

            self.advanced_fig4 = Figure(figsize=(12, 5), dpi=100, facecolor=GUI_DARK_THEME['bg'])
            self.prediction_ax = self.advanced_fig4.add_subplot(121)
            self.prediction_ax.set_title('SLA Breach Prediction', color=GUI_DARK_THEME['fg'])
            self.comparison_ax = self.advanced_fig4.add_subplot(122)
            self.comparison_ax.set_title('Period Comparison', color=GUI_DARK_THEME['fg'])
            for ax in [self.prediction_ax, self.comparison_ax]:
                ax.set_facecolor(GUI_DARK_THEME['entry_bg'])
                ax.tick_params(colors=GUI_DARK_THEME['fg'])
                for spine in ax.spines.values():
                    spine.set_color(GUI_DARK_THEME['fg'])
            self.advanced_canvas4 = FigureCanvasTkAgg(self.advanced_fig4, master=trend_page)
            self.advanced_canvas4.get_tk_widget().pack(fill=tk.BOTH, expand=True)

            hint4 = ttk.Label(trend_page, text="Double-click chart to pop-out",
                             font=('Arial', 8), foreground='gray')
            hint4.pack(anchor=tk.SE, padx=5)
            self._bind_chart_popouts_advanced_trends()

            hint = ttk.Label(advanced_frame, text="Advanced analytics - switch tabs for different visualizations",
                            font=('Arial', 8), foreground='gray')
            hint.pack(anchor=tk.SE, padx=5)
        else:
            ttk.Label(advanced_frame, text="Install matplotlib for advanced visualizations").pack(pady=50)

    # Helper methods
    def _get_current_date_interval(self) -> str:
        """
        Get the appropriate date interval for visualizations based on current filter settings.

        Returns:
            Interval type: 'weekly', 'monthly', 'quarterly', or 'yearly'
        """
        # Try to get dates from filter settings first
        start_str = self.filter_start_date.get().strip()
        end_str = self.filter_end_date.get().strip()

        if start_str and end_str:
            try:
                start_date = pd.to_datetime(start_str)
                end_date = pd.to_datetime(end_str)
                return get_date_interval(start_date, end_date)
            except:
                pass

        # Fall back to actual data range
        if not self.historical_df.empty and 'scan_date' in self.historical_df.columns:
            start_date, end_date = calculate_date_range_from_df(self.historical_df, 'scan_date')
            if start_date and end_date:
                return get_date_interval(start_date, end_date)

        # Default to monthly
        return DATE_INTERVAL_MONTHLY

    def _get_chart_data(self, data_type: str = 'lifecycle', smart_filter: str = None) -> pd.DataFrame:
        """
        Get the appropriate data for charts, with optional smart filtering.

        Smart filtering allows certain visualizations to override the UI status filter
        when they need specific data regardless of user selection:
        - 'all_statuses': Include both Active and Remediated (for remediation rate, comparison charts)
        - 'remediated_only': Only Remediated findings (for MTTR, resolution velocity)
        - 'active_only': Only Active findings (for current risk metrics)
        - None: Use regular filtered data (respects all UI filters)

        Args:
            data_type: Type of data to get - 'lifecycle', 'historical', 'scan_changes', 'host'
            smart_filter: Smart filter mode to override status filter

        Returns:
            DataFrame with the requested data
        """
        # Get base data
        if data_type == 'lifecycle':
            if smart_filter and hasattr(self, 'lifecycle_df') and not self.lifecycle_df.empty:
                # Use unfiltered base data for smart filtering
                df = self.lifecycle_df.copy()
            elif hasattr(self, 'filtered_lifecycle_df') and not self.filtered_lifecycle_df.empty:
                return self.filtered_lifecycle_df
            elif hasattr(self, 'lifecycle_df') and not self.lifecycle_df.empty:
                return self.lifecycle_df
            else:
                return pd.DataFrame()
        elif data_type == 'historical':
            if smart_filter and hasattr(self, 'historical_df') and not self.historical_df.empty:
                df = self.historical_df.copy()
            elif hasattr(self, 'filtered_historical_df') and not self.filtered_historical_df.empty:
                return self.filtered_historical_df
            elif hasattr(self, 'historical_df') and not self.historical_df.empty:
                return self.historical_df
            else:
                return pd.DataFrame()
        elif data_type == 'scan_changes':
            if hasattr(self, 'filtered_scan_changes_df') and not self.filtered_scan_changes_df.empty:
                return self.filtered_scan_changes_df
            elif hasattr(self, 'scan_changes_df') and not self.scan_changes_df.empty:
                return self.scan_changes_df
            else:
                return pd.DataFrame()
        elif data_type == 'host':
            if hasattr(self, 'filtered_host_df') and not self.filtered_host_df.empty:
                return self.filtered_host_df
            elif hasattr(self, 'host_presence_df') and not self.host_presence_df.empty:
                return self.host_presence_df
            else:
                return pd.DataFrame()
        else:
            return pd.DataFrame()

        # Apply smart filtering (only for lifecycle and historical)
        if smart_filter and not df.empty:
            # Apply date filter (still respect date range)
            start_date = self.filter_start_date.get()
            end_date = self.filter_end_date.get()
            if start_date and end_date and 'first_seen' in df.columns:
                df['first_seen_dt'] = pd.to_datetime(df['first_seen'], errors='coerce')
                mask = (df['first_seen_dt'] >= pd.to_datetime(start_date)) & \
                       (df['first_seen_dt'] <= pd.to_datetime(end_date))
                df = df[mask]
                df = df.drop(columns=['first_seen_dt'], errors='ignore')

            # Apply severity filter (still respect severity)
            severity_filter = self.filter_severity.get() if hasattr(self, 'filter_severity') else 'All'
            if severity_filter != 'All' and 'severity_text' in df.columns:
                df = df[df['severity_text'] == severity_filter]

            # Apply environment filter (still respect environment)
            env_filter = self.filter_environment.get() if hasattr(self, 'filter_environment') else 'All'
            if env_filter != 'All' and 'hostname' in df.columns:
                df = df[df['hostname'].apply(self._get_environment_type) == env_filter]

            # Apply smart status filter
            if 'status' in df.columns:
                if smart_filter == 'all_statuses':
                    # Keep both Active and Remediated
                    df = df[df['status'].isin(['Active', 'Remediated'])]
                elif smart_filter == 'remediated_only':
                    # Only Remediated
                    df = df[df['status'] == 'Remediated']
                elif smart_filter == 'active_only':
                    # Only Active
                    df = df[df['status'] == 'Active']

        return df

    def _get_environment_type(self, hostname: str) -> str:
        """
        Classify hostname by environment type using settings-based mappings.

        Detection priority:
        1. Explicit hostname mappings from settings
        2. Pattern matching from settings
        3. Auto-detection from hostname_structure module

        Args:
            hostname: The hostname to classify

        Returns:
            Environment label string
        """
        if not isinstance(hostname, str) or not hostname:
            return 'Unknown'

        hostname_lower = hostname.lower().strip()
        settings = self.settings_manager.settings

        # Priority 1: Check explicit hostname mappings from settings
        if hostname_lower in settings.environment_mappings:
            return settings.environment_mappings[hostname_lower]

        # Priority 2: Check pattern mappings from settings
        import re
        for pattern, env_type in settings.environment_patterns.items():
            try:
                if re.match(pattern, hostname_lower, re.IGNORECASE):
                    return env_type
            except re.error:
                continue  # Skip invalid regex patterns

        # Priority 3: Use auto-detection from hostname_structure module
        from ..models.hostname_structure import parse_hostname, EnvironmentType
        parsed = parse_hostname(hostname)

        if parsed.environment_type == EnvironmentType.PRODUCTION:
            return 'Production'
        elif parsed.environment_type == EnvironmentType.PRE_PRODUCTION:
            return 'PSS'
        elif parsed.environment_type == EnvironmentType.SHARED:
            return 'Shared'
        return 'Unknown'

    def _add_environment_column(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Add environment_type column to DataFrame based on hostname classification.

        Args:
            df: DataFrame with 'hostname' column

        Returns:
            DataFrame with 'environment_type' column added
        """
        if df.empty or 'hostname' not in df.columns:
            return df

        df = df.copy()
        df['environment_type'] = df['hostname'].apply(self._get_environment_type)
        return df

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
            self.settings_manager.update_recent_file('plugins_db', path)

    def _select_existing_db(self):
        """Select existing database file."""
        filetypes = (('SQLite database', '*.db'), ('All files', '*.*'))
        path = filedialog.askopenfilename(title='Select Existing Database', filetypes=filetypes)

        if path:
            self.existing_db_path = path
            self.existing_db_label.config(text=self._truncate_filename(os.path.basename(path)), foreground="white")
            self._log(f"Selected existing DB: {os.path.basename(path)}")
            self.settings_manager.update_recent_file('sqlite', path)

    def _select_opdir_file(self):
        """Select OPDIR mapping file."""
        filetypes = (('Excel files', '*.xlsx'), ('CSV files', '*.csv'), ('All files', '*.*'))
        path = filedialog.askopenfilename(title='Select OPDIR Mapping File', filetypes=filetypes)

        if path:
            self.opdir_file_path = path
            self.opdir_label.config(text=self._truncate_filename(os.path.basename(path)), foreground="white")
            self._log(f"Selected OPDIR file: {os.path.basename(path)}")
            self.settings_manager.update_recent_file('opdir', path)

    def _select_iavm_file(self):
        """Select IAVM Notice Summaries file."""
        filetypes = (('Excel files', '*.xlsx;*.xls'), ('CSV files', '*.csv'), ('All files', '*.*'))
        path = filedialog.askopenfilename(title='Select IAVM Notice Summaries', filetypes=filetypes)

        if path:
            self.iavm_file_path = path
            self.iavm_label.config(text=self._truncate_filename(os.path.basename(path)), foreground="white")
            self._log(f"Selected IAVM file: {os.path.basename(path)}")
            self.settings_manager.update_recent_file('iavm', path)

    # Processing methods
    def _process_archives(self):
        """Process selected archives in a background thread."""
        if not self.archive_paths and not self.existing_db_path:
            messagebox.showwarning("No Data", "Please select archives or an existing database")
            return

        # Check if already processing
        if hasattr(self, '_is_processing') and self._is_processing:
            messagebox.showinfo("Processing", "Processing is already in progress")
            return

        self._is_processing = True
        self._set_processing(True, "Starting processing...")

        import threading

        def process_thread():
            """Background processing thread."""
            try:
                self._log_safe("Starting processing...")

                # Load plugins database first (needed for processing new archives)
                if self.plugins_db_path:
                    self._log_safe("Loading plugins database...")
                    self.plugins_dict = load_plugins_database(self.plugins_db_path)

                # Process archives or load existing DB FIRST
                if self.existing_db_path and not self.archive_paths:
                    self._load_existing_database_thread()
                else:
                    self._process_new_archives_thread()

                # After loading database, check if we need to load OPDIR from file
                if self.opdir_file_path:
                    if self.opdir_df.empty:
                        self._log_safe("Loading OPDIR mapping from file...")
                        self.opdir_df = load_opdir_mapping(self.opdir_file_path)
                        if not self.opdir_df.empty:
                            self._log_safe(f"Loaded {len(self.opdir_df)} OPDIR mappings from file")
                    else:
                        self._log_safe(f"Using {len(self.opdir_df)} OPDIR mappings from database")

                # Same for IAVM notices
                if self.iavm_file_path:
                    if self.iavm_df.empty:
                        self._log_safe("Loading IAVM notice summaries from file...")
                        self.iavm_df = load_iavm_summaries(self.iavm_file_path)
                        if not self.iavm_df.empty:
                            self._log_safe(f"Loaded {len(self.iavm_df)} IAVM notices from file")
                    else:
                        self._log_safe(f"Using {len(self.iavm_df)} IAVM notices from database")

                # Apply default 180-day date filter (must be on main thread)
                self.window.after(0, self._apply_default_date_filter)

                # Auto-save informational findings
                self._auto_save_info_findings()

                self._log_safe("Processing complete!")
                self.window.after(0, lambda: self._on_processing_complete(True))

            except Exception as e:
                self._log_safe(f"ERROR: {str(e)}")
                self.window.after(0, lambda: self._on_processing_complete(False, str(e)))

        # Start background thread
        thread = threading.Thread(target=process_thread, daemon=True)
        thread.start()

    def _on_processing_complete(self, success: bool, error_msg: str = ""):
        """Called when processing completes (on main thread)."""
        self._is_processing = False
        if success:
            self._set_processing(False, "Processing complete")
            messagebox.showinfo("Success", "Data processed successfully!")
        else:
            self._set_processing(False, "Processing failed")
            messagebox.showerror("Error", f"Processing failed: {error_msg}")

    def _log_safe(self, message: str):
        """Thread-safe logging - schedules log on main thread."""
        self.window.after(0, lambda: self._log(message))

    def _load_existing_database_thread(self):
        """Load data from existing database (called from thread)."""
        import sqlite3

        self._log_safe("Loading existing database...")

        conn = sqlite3.connect(self.existing_db_path)

        try:
            self.historical_df = pd.read_sql_query("SELECT * FROM historical_findings", conn)
            self.historical_df['scan_date'] = pd.to_datetime(self.historical_df['scan_date'])
            self._log_safe(f"Loaded {len(self.historical_df)} historical findings")

            try:
                self.lifecycle_df = pd.read_sql_query("SELECT * FROM finding_lifecycle", conn)
                self._log_safe(f"Loaded {len(self.lifecycle_df)} lifecycle records")
            except:
                pass

            try:
                self.host_presence_df = pd.read_sql_query("SELECT * FROM host_presence", conn)
                self._log_safe(f"Loaded {len(self.host_presence_df)} host presence records")
            except:
                pass

            try:
                self.scan_changes_df = pd.read_sql_query("SELECT * FROM scan_changes", conn)
                self._log_safe(f"Loaded {len(self.scan_changes_df)} scan change records")
            except:
                pass

            # Load OPDIR mapping if present
            try:
                self.opdir_df = pd.read_sql_query("SELECT * FROM opdir_mapping", conn)
                if not self.opdir_df.empty:
                    # Standardize legacy column names to match load_opdir_mapping output
                    column_renames = {
                        'opdir_final_due_date': 'final_due_date',
                        'opdir_release_date': 'release_date',
                        'opdir_subject': 'subject',
                        'opdir_number_normalized': 'opdir_number_raw',
                        'opdir_year_from_number': 'opdir_year',
                        'iava/b': 'iavab',
                        'poa&m due date': 'poam_due_date',
                        'acknowledge date': 'acknowledge_date',
                    }
                    self.opdir_df = self.opdir_df.rename(columns=column_renames)

                    # Create opdir_number_raw if missing (copy from opdir_number)
                    if 'opdir_number_raw' not in self.opdir_df.columns and 'opdir_number' in self.opdir_df.columns:
                        self.opdir_df['opdir_number_raw'] = self.opdir_df['opdir_number']

                    # Convert date columns from string to datetime
                    for date_col in ['poam_due_date', 'final_due_date', 'release_date']:
                        if date_col in self.opdir_df.columns:
                            self.opdir_df[date_col] = pd.to_datetime(
                                self.opdir_df[date_col], errors='coerce'
                            )
                    self._log_safe(f"Loaded {len(self.opdir_df)} OPDIR mappings from database")
            except:
                pass

            # Load IAVM notices if present
            try:
                self.iavm_df = pd.read_sql_query("SELECT * FROM iavm_notices", conn)
                if not self.iavm_df.empty:
                    self._log_safe(f"Loaded {len(self.iavm_df)} IAVM notices from database")
            except:
                pass

        finally:
            conn.close()

        # Run analysis refresh on main thread
        self.window.after(0, self._refresh_analysis_internal)

    def _process_new_archives_thread(self):
        """Process new archive files (called from thread)."""
        import tempfile

        self._log_safe("Processing archives...")

        all_findings = []
        temp_dirs = []

        for archive_path in self.archive_paths:
            self._log_safe(f"Processing: {os.path.basename(archive_path)}")

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
            self._log_safe(f"Total findings: {len(self.historical_df)}")

        # Run analysis refresh on main thread
        self.window.after(0, self._refresh_analysis_internal)

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
                self._log(f"Loaded {len(self.lifecycle_df)} lifecycle records")
            except:
                pass

            try:
                self.host_presence_df = pd.read_sql_query("SELECT * FROM host_presence", conn)
                self._log(f"Loaded {len(self.host_presence_df)} host presence records")
            except:
                pass

            try:
                self.scan_changes_df = pd.read_sql_query("SELECT * FROM scan_changes", conn)
                self._log(f"Loaded {len(self.scan_changes_df)} scan change records")
            except:
                pass

            # Load OPDIR mapping if present
            try:
                self.opdir_df = pd.read_sql_query("SELECT * FROM opdir_mapping", conn)
                if not self.opdir_df.empty:
                    # Standardize legacy column names to match load_opdir_mapping output
                    column_renames = {
                        'opdir_final_due_date': 'final_due_date',
                        'opdir_release_date': 'release_date',
                        'opdir_subject': 'subject',
                        'opdir_number_normalized': 'opdir_number_raw',
                        'opdir_year_from_number': 'opdir_year',
                        'iava/b': 'iavab',
                        'poa&m due date': 'poam_due_date',
                        'acknowledge date': 'acknowledge_date',
                    }
                    self.opdir_df = self.opdir_df.rename(columns=column_renames)

                    # Create opdir_number_raw if missing (copy from opdir_number)
                    if 'opdir_number_raw' not in self.opdir_df.columns and 'opdir_number' in self.opdir_df.columns:
                        self.opdir_df['opdir_number_raw'] = self.opdir_df['opdir_number']

                    # Convert date columns from string to datetime
                    for date_col in ['poam_due_date', 'final_due_date', 'release_date']:
                        if date_col in self.opdir_df.columns:
                            self.opdir_df[date_col] = pd.to_datetime(
                                self.opdir_df[date_col], errors='coerce'
                            )
                    self._log(f"Loaded {len(self.opdir_df)} OPDIR mappings from database")
            except:
                pass

            # Load IAVM notices if present
            try:
                self.iavm_df = pd.read_sql_query("SELECT * FROM iavm_notices", conn)
                if not self.iavm_df.empty:
                    self._log(f"Loaded {len(self.iavm_df)} IAVM notices from database")
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

    def _reenrich_from_plugins(self):
        """Re-enrich existing findings with data from plugins database."""
        if self.historical_df.empty:
            messagebox.showwarning("No Data", "Please load a database first")
            return

        if not self.plugins_dict:
            # Try to load plugins if path is set
            if self.plugins_db_path:
                self._log("Loading plugins database...")
                from ..core.plugin_database import load_plugins_database
                self.plugins_dict = load_plugins_database(self.plugins_db_path)

            if not self.plugins_dict:
                messagebox.showwarning("No Plugins", "Please select a plugins database first")
                return

        self._log("Re-enriching findings from plugins database...")

        # Track stats
        enriched_count = 0
        cve_added = 0
        iavx_added = 0
        total = len(self.historical_df)

        # Enrichment mappings
        enrichment_fields = [
            'cves', 'iavx', 'description', 'solution', 'synopsis',
            'cvss3_base_score', 'cvss2_base_score', 'risk_factor',
            'stig_severity', 'exploit_ease', 'exploit_available',
            'exploit_frameworks', 'cpe', 'vuln_publication_date',
            'patch_publication_date', 'plugin_publication_date',
            'plugin_modification_date'
        ]

        # Ensure columns exist
        for col in enrichment_fields:
            if col not in self.historical_df.columns:
                self.historical_df[col] = ''

        # Process each unique plugin_id
        unique_plugins = self.historical_df['plugin_id'].unique()
        self._log(f"Processing {len(unique_plugins)} unique plugins across {total} findings...")

        for plugin_id in unique_plugins:
            plugin_id_str = str(plugin_id)
            if plugin_id_str not in self.plugins_dict:
                continue

            plugin_info = self.plugins_dict[plugin_id_str]
            mask = self.historical_df['plugin_id'] == plugin_id

            # Track if we're adding new data
            had_cve = self.historical_df.loc[mask, 'cves'].fillna('').str.len().sum() > 0
            had_iavx = self.historical_df.loc[mask, 'iavx'].fillna('').str.len().sum() > 0

            # Enrich CVEs
            if 'cves' in plugin_info and plugin_info['cves']:
                current_cves = self.historical_df.loc[mask, 'cves'].fillna('')
                for idx in self.historical_df[mask].index:
                    existing = str(self.historical_df.at[idx, 'cves']) if pd.notna(self.historical_df.at[idx, 'cves']) else ''
                    plugin_cves = str(plugin_info['cves'])
                    if not existing:
                        self.historical_df.at[idx, 'cves'] = plugin_cves
                    else:
                        # Merge CVEs
                        existing_set = set(existing.split('\n'))
                        plugin_set = set(plugin_cves.split('\n'))
                        merged = sorted(existing_set | plugin_set)
                        self.historical_df.at[idx, 'cves'] = '\n'.join(merged)

            # Enrich IAVX
            if 'iavx' in plugin_info and plugin_info['iavx']:
                for idx in self.historical_df[mask].index:
                    existing = str(self.historical_df.at[idx, 'iavx']) if pd.notna(self.historical_df.at[idx, 'iavx']) else ''
                    plugin_iavx = str(plugin_info['iavx'])
                    if not existing:
                        self.historical_df.at[idx, 'iavx'] = plugin_iavx
                    else:
                        # Merge IAVX
                        existing_set = set(existing.split('\n'))
                        plugin_set = set(plugin_iavx.split('\n'))
                        merged = sorted(existing_set | plugin_set)
                        self.historical_df.at[idx, 'iavx'] = '\n'.join(merged)

            # Enrich other fields (only if empty)
            other_mappings = {
                'description': 'description',
                'solution': 'solution',
                'synopsis': 'synopsis',
                'cvss3_base_score': 'cvss3_base_score',
                'cvss2_base_score': 'cvss_base_score',
                'risk_factor': 'risk_factor',
                'stig_severity': 'stig_severity',
                'exploit_ease': 'exploit_ease',
                'exploit_available': 'exploit_available',
                'exploit_frameworks': 'exploit_frameworks',
                'cpe': 'cpe',
                'vuln_publication_date': 'vuln_publication_date',
                'patch_publication_date': 'patch_publication_date',
                'plugin_publication_date': 'plugin_publication_date',
                'plugin_modification_date': 'plugin_modification_date',
            }

            for df_col, plugin_key in other_mappings.items():
                if plugin_key in plugin_info and plugin_info[plugin_key]:
                    # Only fill where empty
                    empty_mask = mask & (self.historical_df[df_col].isna() | (self.historical_df[df_col] == ''))
                    if empty_mask.any():
                        self.historical_df.loc[empty_mask, df_col] = str(plugin_info[plugin_key])

            # Check if we added new data
            now_has_cve = self.historical_df.loc[mask, 'cves'].fillna('').str.len().sum() > 0
            now_has_iavx = self.historical_df.loc[mask, 'iavx'].fillna('').str.len().sum() > 0

            if not had_cve and now_has_cve:
                cve_added += mask.sum()
            if not had_iavx and now_has_iavx:
                iavx_added += mask.sum()

            enriched_count += 1

        self._log(f"Enriched {enriched_count} plugins")
        self._log(f"Added CVEs to {cve_added} findings")
        self._log(f"Added IAVX to {iavx_added} findings")

        # Refresh analysis to update lifecycle with new data
        self._refresh_analysis_internal()

        # Show summary
        messagebox.showinfo("Re-enrichment Complete",
            f"Enriched data from {enriched_count} plugins:\n"
            f"• CVEs added to {cve_added} findings\n"
            f"• IAVX added to {iavx_added} findings\n\n"
            f"Analysis has been refreshed.")

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

        # Enrich with IAVM notices
        if not self.iavm_df.empty:
            self.lifecycle_df = enrich_findings_with_iavm(self.lifecycle_df, self.iavm_df)
            self._log("Applied IAVM enrichment")

        # Host presence
        self.host_presence_df = create_host_presence_analysis(self.historical_df)
        self._log(f"Host presence: {len(self.host_presence_df)} hosts")

        # Scan changes
        self.scan_changes_df = analyze_scan_changes(self.historical_df)
        self._log(f"Scan changes: {len(self.scan_changes_df)} transitions")

        # Initialize filtered data and update displays
        self.filtered_lifecycle_df = self.lifecycle_df.copy()
        self.filtered_host_df = self.host_presence_df.copy()
        self.filtered_historical_df = self.historical_df.copy()
        self.filtered_scan_changes_df = self.scan_changes_df.copy()

        # Add environment type to lifecycle data for grouping
        if not self.filtered_lifecycle_df.empty and 'hostname' in self.filtered_lifecycle_df.columns:
            self.filtered_lifecycle_df['environment_type'] = self.filtered_lifecycle_df['hostname'].apply(
                self._get_environment_type
            )
            self.lifecycle_df['environment_type'] = self.lifecycle_df['hostname'].apply(
                self._get_environment_type
            )

        # Apply default 180-day filter after loading data
        self._apply_default_date_filter()

        self._update_dashboard()
        self._update_lifecycle_tree()
        self._update_host_tree()
        self._update_all_visualizations()

    def _apply_default_date_filter(self):
        """Apply the default 180-day date filter after data loading."""
        if self.historical_df.empty or 'scan_date' not in self.historical_df.columns:
            return

        scan_dates = pd.to_datetime(self.historical_df['scan_date'])
        data_max = scan_dates.max()
        data_min = scan_dates.min()

        # Default to last 180 days
        default_start = data_max - pd.Timedelta(days=180)
        # But don't go before actual data start
        if default_start < data_min:
            default_start = data_min

        self.filter_start_date.set(default_start.strftime('%Y-%m-%d'))
        self.filter_end_date.set(data_max.strftime('%Y-%m-%d'))

        # Calculate actual days in range
        days_range = (data_max - default_start).days

        self._log(f"Default filter applied: Last {days_range} days ({default_start.strftime('%Y-%m-%d')} to {data_max.strftime('%Y-%m-%d')})")

        # Apply the filters to the data
        self._apply_filters()

    def _auto_save_info_findings(self):
        """Auto-save informational findings to yearly databases."""
        if self.historical_df.empty:
            return

        # Check if there are any Info findings
        info_count = len(self.historical_df[self.historical_df['severity_text'] == 'Info'])
        if info_count == 0:
            return

        try:
            # Get base directory for info databases
            base_dir = os.path.join(os.path.expanduser('~'), '.nessus_tracker')

            # Save info findings by year
            results = save_informational_findings_by_year(self.historical_df, base_dir)

            if results:
                years_saved = ', '.join([str(y) for y in sorted(results.keys())])
                total_saved = sum(results.values())
                self._log(f"Auto-saved {total_saved} info findings to yearly databases: {years_saved}")
        except Exception as e:
            self._log(f"Warning: Could not auto-save info findings: {str(e)}")

    def _show_load_info_dialog(self):
        """Show dialog to load informational findings from yearly databases."""
        base_dir = os.path.join(os.path.expanduser('~'), '.nessus_tracker')
        available = list_available_info_databases(base_dir)

        if not available:
            messagebox.showinfo("No Info Databases",
                              "No informational findings databases found.\n\n"
                              "Info findings are auto-saved by calendar year when you process data.")
            return

        # Create selection dialog
        dialog = tk.Toplevel(self.window)
        dialog.title("Load Informational Findings")
        dialog.geometry("500x400")
        dialog.transient(self.window)
        dialog.grab_set()

        # Center on parent
        dialog.update_idletasks()
        x = self.window.winfo_x() + (self.window.winfo_width() - 500) // 2
        y = self.window.winfo_y() + (self.window.winfo_height() - 400) // 2
        dialog.geometry(f"+{x}+{y}")

        main_frame = ttk.Frame(dialog, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text="Select years to load:").pack(anchor=tk.W)

        # Listbox with checkboxes (using Treeview)
        tree_frame = ttk.Frame(main_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        tree = ttk.Treeview(tree_frame, columns=('year', 'count'), show='headings', height=10)
        tree.heading('year', text='Year')
        tree.heading('count', text='Findings Count')
        tree.column('year', width=100)
        tree.column('count', width=150)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        tree.config(yscrollcommand=scrollbar.set)

        # Store paths for selection
        db_paths = {}
        for db in available:
            item_id = tree.insert('', tk.END, values=(db['year'], f"{db['count']:,}"))
            db_paths[item_id] = db['path']

        # Enable multi-selection
        tree.config(selectmode='extended')

        # Select all by default
        for item in tree.get_children():
            tree.selection_add(item)

        def load_selected():
            selected_items = tree.selection()
            if not selected_items:
                messagebox.showwarning("No Selection", "Please select at least one year")
                return

            selected_paths = [db_paths[item] for item in selected_items]

            # Load the info findings
            info_df = load_informational_findings(selected_paths)

            if info_df.empty:
                messagebox.showwarning("No Data", "No informational findings found in selected databases")
                dialog.destroy()
                return

            # Merge with existing data
            if not self.historical_df.empty:
                # Append and remove duplicates
                combined = pd.concat([self.historical_df, info_df], ignore_index=True)
                combined = combined.drop_duplicates(
                    subset=['plugin_id', 'hostname', 'ip_address', 'scan_date'],
                    keep='first'
                )
                new_count = len(combined) - len(self.historical_df)
                self.historical_df = combined
                self._log(f"Added {new_count} info findings from yearly databases")
            else:
                self.historical_df = info_df
                self._log(f"Loaded {len(info_df)} info findings from yearly databases")

            dialog.destroy()

            # Refresh analysis if we have data
            if not self.historical_df.empty:
                self._refresh_analysis_internal()
                messagebox.showinfo("Success",
                                  f"Loaded informational findings.\n"
                                  f"Total findings: {len(self.historical_df):,}")

        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))

        ttk.Button(button_frame, text="Load Selected", command=load_selected).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT)

        # Select All / Clear buttons
        def select_all():
            for item in tree.get_children():
                tree.selection_add(item)

        def clear_selection():
            tree.selection_remove(*tree.get_children())

        ttk.Button(button_frame, text="Select All", command=select_all).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear", command=clear_selection).pack(side=tk.LEFT)

    def _apply_filters(self):
        """Apply current filters and refresh display."""
        if self.lifecycle_df.empty:
            self._log("No data to filter")
            return

        self._log("Applying filters...")

        # Start with full data
        filtered = self.lifecycle_df.copy()
        filter_descriptions = []

        # Filter: Include Info
        if not self.filter_include_info.get():
            if 'severity_text' in filtered.columns:
                filtered = filtered[filtered['severity_text'] != 'Info']
                filter_descriptions.append("Excluding Info")

        # Filter: Date range
        start_date = self.filter_start_date.get().strip()
        end_date = self.filter_end_date.get().strip()
        if start_date and 'first_seen' in filtered.columns:
            try:
                start_dt = pd.to_datetime(start_date)
                filtered = filtered[pd.to_datetime(filtered['first_seen']) >= start_dt]
                filter_descriptions.append(f"From {start_date}")
            except:
                pass
        if end_date and 'last_seen' in filtered.columns:
            try:
                end_dt = pd.to_datetime(end_date)
                filtered = filtered[pd.to_datetime(filtered['last_seen']) <= end_dt]
                filter_descriptions.append(f"To {end_date}")
            except:
                pass

        # Filter: Severity
        # Severity filter: use toggle buttons
        selected_severities = self._get_selected_severities()
        if 'severity_text' in filtered.columns:
            # If all are selected or none, don't filter by severity
            all_severities = ['Critical', 'High', 'Medium', 'Low', 'Info']
            if selected_severities and set(selected_severities) != set(all_severities):
                filtered = filtered[filtered['severity_text'].isin(selected_severities)]
                if len(selected_severities) <= 3:
                    filter_descriptions.append(f"Severity: {', '.join(selected_severities)}")
                else:
                    filter_descriptions.append(f"Severity: {len(selected_severities)} selected")

        # Filter: Status
        status = self.filter_status.get()
        if status != "All" and 'status' in filtered.columns:
            filtered = filtered[filtered['status'] == status]
            filter_descriptions.append(f"Status: {status}")

        # Filter: Host Type
        host_type = self.filter_host_type.get()
        if host_type != "All" and 'hostname' in filtered.columns:
            def check_host_type(hostname):
                if not isinstance(hostname, str):
                    return False
                hostname_lower = hostname.lower()
                if host_type == "Physical":
                    return hostname_lower.endswith('p') and 'ilom' not in hostname_lower
                elif host_type == "Virtual":
                    return hostname_lower.endswith('v') and 'ilom' not in hostname_lower
                elif host_type == "ILOM":
                    return 'ilom' in hostname_lower
                return True
            filtered = filtered[filtered['hostname'].apply(check_host_type)]
            filter_descriptions.append(f"Type: {host_type}")

        # Filter: Environment Type (Production/PSS/Shared)
        # Uses hostname parser which checks: 1) Explicit mappings, 2) Shared patterns, 3) Auto-detection
        # "All Combined" = show all, combined in visualizations
        # "All Separate" = show all, but grouped by environment in visualizations
        env_type = self.filter_env_type.get()
        self.show_env_breakdown = (env_type == "All Separate")  # Flag for visualizations

        if env_type not in ["All Combined", "All Separate", "All", ""] and 'hostname' in filtered.columns:
            from ..models.hostname_structure import parse_hostname, EnvironmentType
            def check_env_type(hostname):
                if not isinstance(hostname, str):
                    return False
                parsed = parse_hostname(hostname)
                if env_type == "Production":
                    return parsed.environment_type == EnvironmentType.PRODUCTION
                elif env_type == "PSS":
                    return parsed.environment_type == EnvironmentType.PRE_PRODUCTION
                elif env_type == "Shared":
                    return parsed.environment_type == EnvironmentType.SHARED
                return False
            filtered = filtered[filtered['hostname'].apply(check_env_type)]
            filter_descriptions.append(f"Env: {env_type}")
        elif env_type == "All Separate":
            filter_descriptions.append("Env: By Environment")

        # Filter: Location
        location = self.filter_location.get().strip().upper()
        if location and 'hostname' in filtered.columns:
            filtered = filtered[filtered['hostname'].str.upper().str.startswith(location)]
            filter_descriptions.append(f"Location: {location}")

        # Filter: Host Pattern (supports comma-separated multiple patterns)
        host_pattern = self.filter_host.get().strip()
        if host_pattern and 'hostname' in filtered.columns:
            patterns = [p.strip() for p in host_pattern.split(',') if p.strip()]
            if len(patterns) == 1:
                # Single pattern - simple contains
                filtered = filtered[filtered['hostname'].str.contains(patterns[0], case=False, na=False)]
                filter_descriptions.append(f"Host: *{patterns[0]}*")
            elif len(patterns) > 1:
                # Multiple patterns - OR logic
                mask = filtered['hostname'].str.contains(patterns[0], case=False, na=False)
                for pattern in patterns[1:]:
                    mask = mask | filtered['hostname'].str.contains(pattern, case=False, na=False)
                filtered = filtered[mask]
                filter_descriptions.append(f"Host: {len(patterns)} patterns")

        # Filter: Specific Hostname List (from selector dialog)
        if self.filter_host_list and 'hostname' in filtered.columns:
            filtered = filtered[filtered['hostname'].isin(self.filter_host_list)]
            filter_descriptions.append(f"Hosts: {len(self.filter_host_list)} selected")

        # Filter: CVSS Range
        try:
            cvss_min = float(self.filter_cvss_min.get() or 0)
            cvss_max = float(self.filter_cvss_max.get() or 10)
            if 'cvss_score' in filtered.columns and (cvss_min > 0 or cvss_max < 10):
                filtered = filtered[(filtered['cvss_score'] >= cvss_min) & (filtered['cvss_score'] <= cvss_max)]
                filter_descriptions.append(f"CVSS: {cvss_min}-{cvss_max}")
        except ValueError:
            pass

        # Filter: OPDIR Status
        opdir_status = self.filter_opdir_status.get()
        if opdir_status != "All":
            if opdir_status == "OPDIR Mapped" and 'opdir_number' in filtered.columns:
                filtered = filtered[filtered['opdir_number'].notna() & (filtered['opdir_number'] != '')]
                filter_descriptions.append("OPDIR Mapped")
            elif opdir_status == "No OPDIR" and 'opdir_number' in filtered.columns:
                filtered = filtered[filtered['opdir_number'].isna() | (filtered['opdir_number'] == '')]
                filter_descriptions.append("No OPDIR")
            elif 'opdir_status' in filtered.columns:
                filtered = filtered[filtered['opdir_status'] == opdir_status]
                filter_descriptions.append(f"OPDIR: {opdir_status}")

        # Filter: CVE
        cve_filter = self.filter_cve.get().strip().upper()
        if cve_filter and 'cves' in filtered.columns:
            # Support partial matching (e.g., "2024-1234" matches "CVE-2024-1234")
            filtered = filtered[filtered['cves'].str.contains(cve_filter, case=False, na=False)]
            filter_descriptions.append(f"CVE: {cve_filter}")

        # Filter: IAVX (IAVA/IAVB/IAVT)
        iavx_filter = self.filter_iavx.get().strip().upper()
        if iavx_filter and 'iavx' in filtered.columns:
            # Support partial matching (e.g., "2024-A-0001" matches "IAVA:2024-A-0001")
            filtered = filtered[filtered['iavx'].str.contains(iavx_filter, case=False, na=False)]
            filter_descriptions.append(f"IAV: {iavx_filter}")

        # Store filtered data
        self.filtered_lifecycle_df = filtered

        # Filter host presence data
        if not self.host_presence_df.empty and 'hostname' in filtered.columns:
            filtered_hosts = filtered['hostname'].unique()
            self.filtered_host_df = self.host_presence_df[
                self.host_presence_df['hostname'].isin(filtered_hosts)
            ]
        else:
            self.filtered_host_df = self.host_presence_df.copy()

        # Filter historical data based on filtered lifecycle (for charts that use historical_df)
        # Use vectorized operations for performance with large datasets
        if not self.historical_df.empty and not filtered.empty:
            if 'hostname' in filtered.columns and 'plugin_id' in filtered.columns:
                if 'hostname' in self.historical_df.columns and 'plugin_id' in self.historical_df.columns:
                    # Create composite key for vectorized filtering (much faster than .apply())
                    filter_keys = filtered['hostname'].astype(str) + '|' + filtered['plugin_id'].astype(str)
                    filter_key_set = set(filter_keys.unique())
                    hist_keys = self.historical_df['hostname'].astype(str) + '|' + self.historical_df['plugin_id'].astype(str)
                    self.filtered_historical_df = self.historical_df[hist_keys.isin(filter_key_set)]
                else:
                    self.filtered_historical_df = self.historical_df.copy()
            else:
                self.filtered_historical_df = self.historical_df.copy()
        else:
            self.filtered_historical_df = self.historical_df.copy()

        # Filter scan changes based on filtered findings
        if not self.scan_changes_df.empty and not filtered.empty:
            if 'hostname' in filtered.columns and 'plugin_id' in filtered.columns:
                if 'hostname' in self.scan_changes_df.columns and 'plugin_id' in self.scan_changes_df.columns:
                    # Reuse filter key set if already computed, otherwise create
                    if 'filter_key_set' not in dir():
                        filter_keys = filtered['hostname'].astype(str) + '|' + filtered['plugin_id'].astype(str)
                        filter_key_set = set(filter_keys.unique())
                    scan_keys = self.scan_changes_df['hostname'].astype(str) + '|' + self.scan_changes_df['plugin_id'].astype(str)
                    self.filtered_scan_changes_df = self.scan_changes_df[scan_keys.isin(filter_key_set)]
                else:
                    self.filtered_scan_changes_df = self.scan_changes_df.copy()
            else:
                self.filtered_scan_changes_df = self.scan_changes_df.copy()
        else:
            self.filtered_scan_changes_df = self.scan_changes_df.copy()

        # Update filter status label
        if filter_descriptions:
            status_text = " | ".join(filter_descriptions)
            self.filter_status_label.config(text=status_text, foreground="#00ff00")
        else:
            self.filter_status_label.config(text="No filters applied", foreground="gray")

        # Update filter label colors (highlight active filters)
        self._update_filter_label_colors()

        # Update all displays
        self._update_dashboard()
        self._update_lifecycle_tree()
        self._update_host_tree()
        self._update_all_visualizations()

        self._log(f"Filters applied: {len(filtered)} findings, {len(self.filtered_host_df)} hosts")

    def _toggle_severity(self, severity: str):
        """Toggle a severity filter and update button appearance."""
        current = self.severity_toggles[severity].get()
        self.severity_toggles[severity].set(not current)
        self._update_severity_button(severity)

    def _update_severity_button(self, severity: str):
        """Update button appearance based on toggle state."""
        if severity not in self.severity_buttons:
            return

        btn = self.severity_buttons[severity]
        is_active = self.severity_toggles[severity].get()
        sev_colors = self.settings_manager.settings.get_severity_colors()
        color = sev_colors.get(severity, '#6c757d')

        if is_active:
            btn.config(relief=tk.RAISED, bg=color)
        else:
            btn.config(relief=tk.FLAT, bg=GUI_DARK_THEME['button_bg'])

    def _select_all_severities(self):
        """Select all severity levels."""
        for sev in self.severity_toggles:
            self.severity_toggles[sev].set(True)
            self._update_severity_button(sev)

    def _select_no_severities(self):
        """Deselect all severity levels."""
        for sev in self.severity_toggles:
            self.severity_toggles[sev].set(False)
            self._update_severity_button(sev)

    def _get_selected_severities(self) -> list:
        """Get list of currently selected severity levels."""
        return [sev for sev, var in self.severity_toggles.items() if var.get()]

    def _reset_filters(self):
        """Reset all filters to default values."""
        self.filter_include_info.set(True)
        self.filter_severity.set("All")
        # Reset severity toggles to defaults
        for sev in ['Critical', 'High', 'Medium', 'Low']:
            self.severity_toggles[sev].set(True)
            self._update_severity_button(sev)
        self.severity_toggles['Info'].set(False)
        self._update_severity_button('Info')
        self.filter_status.set("All")
        self.filter_host_type.set("All")
        self.filter_env_type.set("All Combined")
        self.filter_host.set("")
        self.filter_location.set("")
        self.filter_cvss_min.set("0.0")
        self.filter_cvss_max.set("10.0")
        self.filter_opdir_status.set("All")
        self.filter_cve.set("")
        self.filter_iavx.set("")

        # Reset host list filter
        self.filter_host_list = []
        self._update_host_count_label()

        # Reset date filters to last 180 days (or data range if smaller)
        if not self.historical_df.empty and 'scan_date' in self.historical_df.columns:
            scan_dates = pd.to_datetime(self.historical_df['scan_date'])
            data_max = scan_dates.max()
            data_min = scan_dates.min()

            # Default to last 180 days
            default_start = data_max - pd.Timedelta(days=180)
            # But don't go before actual data start
            if default_start < data_min:
                default_start = data_min

            self.filter_start_date.set(default_start.strftime('%Y-%m-%d'))
            self.filter_end_date.set(data_max.strftime('%Y-%m-%d'))
        else:
            self.filter_start_date.set("")
            self.filter_end_date.set("")

        # Apply the reset filters
        self._apply_filters()
        self._log("Filters reset to defaults")

    def _update_filter_label_colors(self):
        """Update filter label colors based on whether filters are applied."""
        if not hasattr(self, 'filter_labels'):
            return

        # Check each filter and update its label color
        active_bg = self.filter_label_active_bg
        default_bg = self.filter_label_default_bg

        # Dates - always applied if set
        if self.filter_start_date.get() or self.filter_end_date.get():
            self.filter_labels.get('dates', tk.Label()).config(bg=active_bg)
        else:
            self.filter_labels.get('dates', tk.Label()).config(bg=default_bg)

        # Severity - check if not all selected
        selected = [s for s in ['Critical', 'High', 'Medium', 'Low', 'Info'] if self.severity_toggles[s].get()]
        if len(selected) < 5:
            self.filter_labels.get('severity', tk.Label()).config(bg=active_bg)
        else:
            self.filter_labels.get('severity', tk.Label()).config(bg=default_bg)

        # Status
        if self.filter_status.get() != "All":
            self.filter_labels.get('status', tk.Label()).config(bg=active_bg)
        else:
            self.filter_labels.get('status', tk.Label()).config(bg=default_bg)

        # Host Type
        if self.filter_host_type.get() != "All":
            self.filter_labels.get('type', tk.Label()).config(bg=active_bg)
        else:
            self.filter_labels.get('type', tk.Label()).config(bg=default_bg)

        # Environment
        env_filter = self.filter_env_type.get()
        if env_filter not in ["All Combined", "All Separate", ""]:
            self.filter_labels.get('env', tk.Label()).config(bg=active_bg)
        else:
            self.filter_labels.get('env', tk.Label()).config(bg=default_bg)

        # Location
        if self.filter_location.get().strip():
            self.filter_labels.get('location', tk.Label()).config(bg=active_bg)
        else:
            self.filter_labels.get('location', tk.Label()).config(bg=default_bg)

        # Host
        if self.filter_host.get().strip() or self.filter_host_list:
            self.filter_labels.get('host', tk.Label()).config(bg=active_bg)
        else:
            self.filter_labels.get('host', tk.Label()).config(bg=default_bg)

        # CVSS
        cvss_min = self.filter_cvss_min.get()
        cvss_max = self.filter_cvss_max.get()
        if (cvss_min and cvss_min != "0.0" and cvss_min != "0") or (cvss_max and cvss_max != "10.0" and cvss_max != "10"):
            self.filter_labels.get('cvss', tk.Label()).config(bg=active_bg)
        else:
            self.filter_labels.get('cvss', tk.Label()).config(bg=default_bg)

        # OPDIR
        if self.filter_opdir_status.get() != "All":
            self.filter_labels.get('opdir', tk.Label()).config(bg=active_bg)
        else:
            self.filter_labels.get('opdir', tk.Label()).config(bg=default_bg)

        # CVE
        if self.filter_cve.get().strip():
            self.filter_labels.get('cve', tk.Label()).config(bg=active_bg)
        else:
            self.filter_labels.get('cve', tk.Label()).config(bg=default_bg)

        # IAVX
        if self.filter_iavx.get().strip():
            self.filter_labels.get('iavx', tk.Label()).config(bg=active_bg)
        else:
            self.filter_labels.get('iavx', tk.Label()).config(bg=default_bg)

    def _show_date_picker(self, date_var):
        """Show a date picker popup for selecting dates."""
        picker = tk.Toplevel(self.window)
        picker.title("Select Date")
        picker.configure(bg=GUI_DARK_THEME['bg'])
        picker.transient(self.window)
        picker.grab_set()

        # Get current date or default to today
        try:
            current = datetime.strptime(date_var.get(), '%Y-%m-%d')
        except:
            current = datetime.now()

        # Calendar state
        cal_state = {'year': current.year, 'month': current.month}

        # Color definitions
        today_bg = '#8B0000'  # Burgundy for today
        selected_bg = '#1a3a5c'  # Dark blue for selected range
        normal_bg = GUI_DARK_THEME['entry_bg']
        header_bg = GUI_DARK_THEME['button_bg']

        # Main frame
        main_frame = ttk.Frame(picker, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Month/Year navigation
        nav_frame = ttk.Frame(main_frame)
        nav_frame.pack(fill=tk.X, pady=(0, 10))

        def prev_month():
            cal_state['month'] -= 1
            if cal_state['month'] < 1:
                cal_state['month'] = 12
                cal_state['year'] -= 1
            draw_calendar()

        def next_month():
            cal_state['month'] += 1
            if cal_state['month'] > 12:
                cal_state['month'] = 1
                cal_state['year'] += 1
            draw_calendar()

        ttk.Button(nav_frame, text="<", width=3, command=prev_month).pack(side=tk.LEFT)
        month_label = ttk.Label(nav_frame, text="", font=('Arial', 11, 'bold'))
        month_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(nav_frame, text=">", width=3, command=next_month).pack(side=tk.RIGHT)

        # Calendar grid frame
        cal_frame = ttk.Frame(main_frame)
        cal_frame.pack(fill=tk.BOTH, expand=True)

        # Day headers
        days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
        for i, day in enumerate(days):
            lbl = tk.Label(cal_frame, text=day, width=4, bg=header_bg, fg='white',
                          font=('Arial', 9, 'bold'))
            lbl.grid(row=0, column=i, padx=1, pady=1)

        # Day buttons
        day_buttons = []

        def select_date(day):
            if day > 0:
                selected = datetime(cal_state['year'], cal_state['month'], day)
                date_var.set(selected.strftime('%Y-%m-%d'))
                picker.destroy()

        def draw_calendar():
            import calendar as cal_module  # Import at start to avoid scoping issues

            # Clear existing buttons
            for btn in day_buttons:
                btn.destroy()
            day_buttons.clear()

            # Update month label
            month_label.config(text=f"{cal_module.month_name[cal_state['month']]} {cal_state['year']}")

            # Get calendar for month
            cal = cal_module.Calendar(firstweekday=0)
            month_days = cal.monthdayscalendar(cal_state['year'], cal_state['month'])

            today = datetime.now().date()

            # Get selected date range for highlighting
            try:
                start = datetime.strptime(self.filter_start_date.get(), '%Y-%m-%d').date()
            except:
                start = None
            try:
                end = datetime.strptime(self.filter_end_date.get(), '%Y-%m-%d').date()
            except:
                end = None

            for row_idx, week in enumerate(month_days):
                for col_idx, day in enumerate(week):
                    if day == 0:
                        # Empty cell
                        btn = tk.Label(cal_frame, text="", width=4, bg=normal_bg, fg=GUI_DARK_THEME['fg'])
                    else:
                        current_date = datetime(cal_state['year'], cal_state['month'], day).date()

                        # Determine background color
                        if current_date == today:
                            bg = today_bg
                        elif start and end and start <= current_date <= end:
                            bg = selected_bg
                        else:
                            bg = normal_bg

                        btn = tk.Button(cal_frame, text=str(day), width=4,
                                       bg=bg, fg='white', relief='flat',
                                       activebackground='#3a5a7c',
                                       command=lambda d=day: select_date(d))
                    btn.grid(row=row_idx + 1, column=col_idx, padx=1, pady=1)
                    day_buttons.append(btn)

        draw_calendar()

        # Quick select buttons
        quick_frame = ttk.Frame(main_frame)
        quick_frame.pack(fill=tk.X, pady=(10, 0))

        def set_today():
            date_var.set(datetime.now().strftime('%Y-%m-%d'))
            picker.destroy()

        def set_days_ago(days):
            date_var.set((datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d'))
            picker.destroy()

        ttk.Button(quick_frame, text="Today", command=set_today, width=8).pack(side=tk.LEFT, padx=2)
        ttk.Button(quick_frame, text="-30d", command=lambda: set_days_ago(30), width=5).pack(side=tk.LEFT, padx=2)
        ttk.Button(quick_frame, text="-90d", command=lambda: set_days_ago(90), width=5).pack(side=tk.LEFT, padx=2)
        ttk.Button(quick_frame, text="-180d", command=lambda: set_days_ago(180), width=6).pack(side=tk.LEFT, padx=2)

        # Close button
        ttk.Button(main_frame, text="Cancel", command=picker.destroy).pack(pady=(10, 0))

        # Center the picker
        picker.update_idletasks()
        x = self.window.winfo_x() + (self.window.winfo_width() // 2) - (picker.winfo_width() // 2)
        y = self.window.winfo_y() + (self.window.winfo_height() // 2) - (picker.winfo_height() // 2)
        picker.geometry(f"+{x}+{y}")

    def _update_host_count_label(self):
        """Update the host count label next to the host filter."""
        if self.filter_host_list:
            self.host_count_label.config(text=f"[{len(self.filter_host_list)}]")
        else:
            self.host_count_label.config(text="")

    def _show_host_selector(self):
        """Show the host selection dialog for advanced filtering."""
        dialog = tk.Toplevel(self.window)
        dialog.title("Host Selector")
        dialog.geometry("700x550")
        dialog.configure(bg=GUI_DARK_THEME['bg'])
        dialog.transient(self.window)
        dialog.grab_set()

        # Main container with panes
        main_frame = ttk.Frame(dialog, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Top section: Available hosts from data + selection
        top_frame = ttk.LabelFrame(main_frame, text="Select from Available Hosts", padding=5)
        top_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))

        # Search filter for available hosts
        search_frame = ttk.Frame(top_frame)
        search_frame.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=5)

        # Two listboxes side by side: available and selected
        lists_frame = ttk.Frame(top_frame)
        lists_frame.pack(fill=tk.BOTH, expand=True)

        # Available hosts
        avail_frame = ttk.Frame(lists_frame)
        avail_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        ttk.Label(avail_frame, text="Available:").pack(anchor=tk.W)
        avail_scroll = ttk.Scrollbar(avail_frame)
        avail_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        avail_listbox = tk.Listbox(avail_frame, selectmode=tk.EXTENDED,
                                    bg=GUI_DARK_THEME['entry_bg'], fg=GUI_DARK_THEME['fg'],
                                    yscrollcommand=avail_scroll.set, height=10)
        avail_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        avail_scroll.config(command=avail_listbox.yview)

        # Buttons between lists
        btn_frame = ttk.Frame(lists_frame)
        btn_frame.pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text=">>", width=3,
                   command=lambda: self._move_hosts(avail_listbox, selected_listbox, 'add')).pack(pady=2)
        ttk.Button(btn_frame, text="<<", width=3,
                   command=lambda: self._move_hosts(avail_listbox, selected_listbox, 'remove')).pack(pady=2)
        ttk.Button(btn_frame, text="All >>", width=5,
                   command=lambda: self._move_all_hosts(avail_listbox, selected_listbox, 'add')).pack(pady=2)
        ttk.Button(btn_frame, text="Clear", width=5,
                   command=lambda: self._move_all_hosts(avail_listbox, selected_listbox, 'clear')).pack(pady=2)

        # Selected hosts
        sel_frame = ttk.Frame(lists_frame)
        sel_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 0))
        ttk.Label(sel_frame, text="Selected:").pack(anchor=tk.W)
        sel_scroll = ttk.Scrollbar(sel_frame)
        sel_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        selected_listbox = tk.Listbox(sel_frame, selectmode=tk.EXTENDED,
                                       bg=GUI_DARK_THEME['entry_bg'], fg=GUI_DARK_THEME['fg'],
                                       yscrollcommand=sel_scroll.set, height=10)
        selected_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sel_scroll.config(command=selected_listbox.yview)

        # Middle section: Paste hostnames
        paste_frame = ttk.LabelFrame(main_frame, text="Paste Hostnames (one per line or comma-separated)", padding=5)
        paste_frame.pack(fill=tk.X, pady=5)
        paste_text = tk.Text(paste_frame, height=3, bg=GUI_DARK_THEME['entry_bg'], fg=GUI_DARK_THEME['fg'])
        paste_text.pack(fill=tk.X, pady=(0, 5))
        ttk.Button(paste_frame, text="Add Pasted Hosts",
                   command=lambda: self._add_pasted_hosts(paste_text, selected_listbox)).pack(anchor=tk.W)

        # Bottom section: Saved filter lists
        saved_frame = ttk.LabelFrame(main_frame, text="Saved Filter Lists", padding=5)
        saved_frame.pack(fill=tk.X, pady=5)

        saved_row = ttk.Frame(saved_frame)
        saved_row.pack(fill=tk.X)

        # Dropdown for saved lists
        saved_lists = self.filter_list_manager.get_lists_by_type('hostname')
        list_names = [""] + [fl.name for fl in saved_lists]
        saved_list_var = tk.StringVar()
        saved_combo = ttk.Combobox(saved_row, textvariable=saved_list_var, values=list_names, width=20)
        saved_combo.pack(side=tk.LEFT, padx=(0, 5))

        ttk.Button(saved_row, text="Load",
                   command=lambda: self._load_saved_list(saved_list_var.get(), selected_listbox)).pack(side=tk.LEFT, padx=2)
        ttk.Button(saved_row, text="Save As...",
                   command=lambda: self._save_host_list(selected_listbox, saved_combo)).pack(side=tk.LEFT, padx=2)
        ttk.Button(saved_row, text="Delete",
                   command=lambda: self._delete_saved_list(saved_list_var.get(), saved_combo)).pack(side=tk.LEFT, padx=2)

        # Action buttons
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill=tk.X, pady=(10, 0))
        ttk.Button(action_frame, text="Apply", width=10,
                   command=lambda: self._apply_host_selection(selected_listbox, dialog)).pack(side=tk.RIGHT, padx=2)
        ttk.Button(action_frame, text="Cancel", width=10,
                   command=dialog.destroy).pack(side=tk.RIGHT, padx=2)

        # Populate available hosts from data
        all_hosts = self._get_all_hostnames()
        for host in sorted(all_hosts):
            avail_listbox.insert(tk.END, host)

        # Populate already selected hosts
        for host in self.filter_host_list:
            selected_listbox.insert(tk.END, host)

        # Search filter functionality
        def filter_available(*args):
            search_term = search_var.get().lower()
            avail_listbox.delete(0, tk.END)
            for host in sorted(all_hosts):
                if search_term in host.lower():
                    avail_listbox.insert(tk.END, host)

        search_var.trace('w', filter_available)

    def _get_all_hostnames(self) -> List[str]:
        """Get all unique hostnames from loaded data."""
        hostnames = set()
        if not self.lifecycle_df.empty and 'hostname' in self.lifecycle_df.columns:
            hostnames.update(self.lifecycle_df['hostname'].dropna().unique())
        if not self.host_presence_df.empty and 'hostname' in self.host_presence_df.columns:
            hostnames.update(self.host_presence_df['hostname'].dropna().unique())
        return list(hostnames)

    def _move_hosts(self, avail_listbox: tk.Listbox, selected_listbox: tk.Listbox, action: str):
        """Move hosts between available and selected listboxes."""
        if action == 'add':
            selected_indices = avail_listbox.curselection()
            for idx in selected_indices:
                host = avail_listbox.get(idx)
                if host not in selected_listbox.get(0, tk.END):
                    selected_listbox.insert(tk.END, host)
        elif action == 'remove':
            selected_indices = list(selected_listbox.curselection())
            for idx in reversed(selected_indices):
                selected_listbox.delete(idx)

    def _move_all_hosts(self, avail_listbox: tk.Listbox, selected_listbox: tk.Listbox, action: str):
        """Move all hosts or clear selection."""
        if action == 'add':
            for idx in range(avail_listbox.size()):
                host = avail_listbox.get(idx)
                if host not in selected_listbox.get(0, tk.END):
                    selected_listbox.insert(tk.END, host)
        elif action == 'clear':
            selected_listbox.delete(0, tk.END)

    def _add_pasted_hosts(self, paste_text: tk.Text, selected_listbox: tk.Listbox):
        """Add pasted hostnames to selected list."""
        text = paste_text.get("1.0", tk.END).strip()
        if not text:
            return

        # Split by newlines or commas
        hosts = []
        for line in text.split('\n'):
            for part in line.split(','):
                host = part.strip()
                if host:
                    hosts.append(host)

        # Add to selected listbox
        current = set(selected_listbox.get(0, tk.END))
        for host in hosts:
            if host not in current:
                selected_listbox.insert(tk.END, host)

        # Clear paste area
        paste_text.delete("1.0", tk.END)
        self._log(f"Added {len(hosts)} hosts from paste")

    def _load_saved_list(self, list_name: str, selected_listbox: tk.Listbox):
        """Load a saved filter list into the selected hosts."""
        if not list_name:
            return

        filter_list = self.filter_list_manager.get_list(list_name)
        if filter_list:
            selected_listbox.delete(0, tk.END)
            for host in filter_list.items:
                selected_listbox.insert(tk.END, host)
            self._log(f"Loaded filter list '{list_name}' with {filter_list.count} hosts")

    def _save_host_list(self, selected_listbox: tk.Listbox, saved_combo: ttk.Combobox):
        """Save current selection as a named filter list."""
        hosts = list(selected_listbox.get(0, tk.END))
        if not hosts:
            messagebox.showwarning("Save Filter List", "No hosts selected to save.")
            return

        # Ask for name
        from tkinter import simpledialog
        name = simpledialog.askstring("Save Filter List", "Enter a name for this filter list:",
                                       parent=self.window)
        if not name:
            return

        # Create or update list
        if self.filter_list_manager.list_exists(name):
            existing = self.filter_list_manager.get_list(name)
            existing.items = hosts
            self.filter_list_manager.save_list(name)
        else:
            self.filter_list_manager.create_list(
                name=name,
                filter_type='hostname',
                description=f"Saved from host selector with {len(hosts)} hosts",
                items=hosts
            )

        # Update dropdown
        saved_lists = self.filter_list_manager.get_lists_by_type('hostname')
        list_names = [""] + [fl.name for fl in saved_lists]
        saved_combo['values'] = list_names
        saved_combo.set(name)

        self._log(f"Saved filter list '{name}' with {len(hosts)} hosts")

    def _delete_saved_list(self, list_name: str, saved_combo: ttk.Combobox):
        """Delete a saved filter list."""
        if not list_name:
            return

        if messagebox.askyesno("Delete Filter List", f"Delete filter list '{list_name}'?"):
            self.filter_list_manager.delete_list(list_name)

            # Update dropdown
            saved_lists = self.filter_list_manager.get_lists_by_type('hostname')
            list_names = [""] + [fl.name for fl in saved_lists]
            saved_combo['values'] = list_names
            saved_combo.set("")

            self._log(f"Deleted filter list '{list_name}'")

    def _apply_host_selection(self, selected_listbox: tk.Listbox, dialog: tk.Toplevel):
        """Apply the host selection and close dialog."""
        self.filter_host_list = list(selected_listbox.get(0, tk.END))
        self._update_host_count_label()
        dialog.destroy()
        self._log(f"Selected {len(self.filter_host_list)} specific hosts for filtering")

    def _update_dashboard(self):
        """Update dashboard statistics from filtered data."""
        df = self._get_chart_data('lifecycle')

        if df.empty:
            return

        # Update main stats
        self.stat_labels['total_findings'].config(text=str(len(df)))

        if 'status' in df.columns:
            active = len(df[df['status'] == 'Active'])
            resolved = len(df[df['status'] == 'Resolved'])
            self.stat_labels['active_findings'].config(text=str(active))
            self.stat_labels['resolved_findings'].config(text=str(resolved))

        if 'hostname' in df.columns:
            self.stat_labels['unique_hosts'].config(text=str(df['hostname'].nunique()))

        if 'plugin_id' in df.columns:
            self.stat_labels['unique_plugins'].config(text=str(df['plugin_id'].nunique()))

        if 'days_open' in df.columns:
            days_numeric = pd.to_numeric(df['days_open'], errors='coerce')
            avg_days = days_numeric.mean()
            self.stat_labels['avg_days_open'].config(text=f"{avg_days:.1f}" if pd.notna(avg_days) else "N/A")

        # Update severity breakdown
        if 'severity_text' in df.columns:
            severity_counts = df['severity_text'].value_counts()
            for sev in ['Critical', 'High', 'Medium', 'Low', 'Info']:
                count = severity_counts.get(sev, 0)
                self.severity_labels[sev].config(text=str(count))

        # Update host type breakdown
        if 'hostname' in df.columns:
            hostnames = df['hostname'].unique()
            type_counts = {'Physical': 0, 'Virtual': 0, 'ILOM': 0, 'Unknown': 0}
            for h in hostnames:
                if not isinstance(h, str):
                    type_counts['Unknown'] += 1
                    continue
                h_lower = h.lower()
                if 'ilom' in h_lower:
                    type_counts['ILOM'] += 1
                elif h_lower.endswith('p'):
                    type_counts['Physical'] += 1
                elif h_lower.endswith('v'):
                    type_counts['Virtual'] += 1
                else:
                    type_counts['Unknown'] += 1
            for htype, count in type_counts.items():
                self.host_type_labels[htype].config(text=str(count))

        # Update environment breakdown
        if 'hostname' in df.columns:
            hostnames = df['hostname'].unique()
            env_counts = {'Production': 0, 'PSS': 0, 'Shared': 0, 'Unknown': 0}
            for h in hostnames:
                env_type = self._get_environment_type(h)
                if env_type in env_counts:
                    env_counts[env_type] += 1
                else:
                    env_counts['Unknown'] += 1
            for env, count in env_counts.items():
                self.env_type_labels[env].config(text=str(count))

    def _update_lifecycle_tree(self):
        """Update lifecycle treeview with filtered data and pagination."""
        # Clear existing items
        for item in self.lifecycle_tree.get_children():
            self.lifecycle_tree.delete(item)

        df = self._get_chart_data('lifecycle')

        if df.empty:
            self.lifecycle_count_label.config(text="Showing 0 findings")
            return

        # Apply status filter based on toggles
        show_active = self.lifecycle_show_active.get()
        show_resolved = self.lifecycle_show_resolved.get()

        if 'status' in df.columns:
            if show_active and show_resolved:
                # Show both
                pass
            elif show_active:
                df = df[df['status'] == 'Active']
            elif show_resolved:
                df = df[df['status'] == 'Resolved']
            else:
                # Neither selected - show nothing
                df = df.head(0)

        total = len(df)
        page_size = self.lifecycle_page_size.get()
        start = self.lifecycle_current_start

        # Ensure start is within bounds
        if start >= total:
            start = max(0, total - page_size) if page_size > 0 else 0
            self.lifecycle_current_start = start

        # Get page of data (0 = show all)
        if page_size == 0:
            display_df = df
            end = total
        else:
            end = min(start + page_size, total)
            display_df = df.iloc[start:end]

        for _, row in display_df.iterrows():
            # Use plugin_name field (from lifecycle analysis), fallback to name
            plugin_name = row.get('plugin_name', row.get('name', ''))
            values = (
                row.get('hostname', ''),
                row.get('plugin_id', ''),
                str(plugin_name) if plugin_name else '',  # Full plugin name, no truncation
                row.get('severity_text', row.get('severity', '')),
                row.get('status', ''),
                str(row.get('first_seen', ''))[:10],
                str(row.get('last_seen', ''))[:10],
                row.get('days_open', '')
            )
            self.lifecycle_tree.insert('', tk.END, values=values)

        # Update count label with range info
        status_filter = ""
        if show_active and not show_resolved:
            status_filter = " (Active only)"
        elif show_resolved and not show_active:
            status_filter = " (Resolved only)"

        if page_size == 0:
            label_text = f"Showing all {total} findings{status_filter}"
        else:
            label_text = f"Showing {start + 1}-{end} of {total} findings{status_filter}"
        self.lifecycle_count_label.config(text=label_text)

    def _lifecycle_status_changed(self):
        """Handle lifecycle status toggle change."""
        self.lifecycle_current_start = 0  # Reset to first page
        self._update_lifecycle_tree()

    def _update_host_tree(self):
        """Update host treeview with filtered data."""
        # Clear existing items
        for item in self.host_tree.get_children():
            self.host_tree.delete(item)

        df = self.filtered_host_df if not self.filtered_host_df.empty else self.host_presence_df

        if df.empty:
            self.host_count_label.config(text="Showing 0 hosts")
            return

        # Apply Active/Missing filter based on toggles
        show_active = self.host_show_active.get()
        show_missing = self.host_show_missing.get()

        # Calculate total scans and missing threshold
        total_scans = df['scan_count'].max() if 'scan_count' in df.columns else df.get('scans_present', pd.Series([0])).max()

        # Determine host status: Active if present in recent scans, Missing if not
        # Missing = not present in >6 of most recent scans
        if 'status' not in df.columns:
            # Create status based on presence in recent scans
            df = df.copy()
            if 'scans_missed' in df.columns:
                scans_missed = df['scans_missed']
            elif 'scan_count' in df.columns:
                scans_missed = total_scans - df['scan_count']
            else:
                scans_missed = 0

            df['_is_missing'] = scans_missed > self.host_missing_threshold
            df['_scans_missed'] = scans_missed
        else:
            df = df.copy()
            df['_is_missing'] = df['status'].str.lower() != 'active'
            df['_scans_missed'] = total_scans - df.get('scan_count', 0)

        # Filter based on toggles
        if show_active and show_missing:
            pass  # Show all
        elif show_active:
            df = df[~df['_is_missing']]
        elif show_missing:
            df = df[df['_is_missing']]
        else:
            df = df.head(0)  # Neither selected

        # Limit display
        display_df = df.head(1000)

        for _, row in display_df.iterrows():
            hostname = row.get('hostname', '')
            # Determine host type
            host_type = 'Unknown'
            if isinstance(hostname, str):
                h_lower = hostname.lower()
                if 'ilom' in h_lower:
                    host_type = 'ILOM'
                elif h_lower.endswith('p'):
                    host_type = 'Physical'
                elif h_lower.endswith('v'):
                    host_type = 'Virtual'

            # Determine status display
            is_missing = row.get('_is_missing', False)
            scans_missed = row.get('_scans_missed', 0)
            if is_missing:
                if scans_missed <= self.host_missing_threshold:
                    status = f"Missing ({int(scans_missed)} scans)"
                else:
                    status = "Missing"
            else:
                status = row.get('status', 'Active')

            values = (
                hostname,
                row.get('ip_address', ''),
                status,
                str(row.get('first_seen', ''))[:10],
                str(row.get('last_seen', ''))[:10],
                row.get('scan_count', row.get('scans_present', '')),
                f"{row.get('presence_percentage', 0):.1f}%" if 'presence_percentage' in row else '',
                host_type
            )
            self.host_tree.insert('', tk.END, values=values)

        total = len(df)
        shown = len(display_df)

        # Status filter label
        status_filter = ""
        if show_active and not show_missing:
            status_filter = " (Active only)"
        elif show_missing and not show_active:
            status_filter = " (Missing only)"

        label_text = f"Showing {shown} of {total} hosts{status_filter}" if shown < total else f"Showing {total} hosts{status_filter}"
        self.host_count_label.config(text=label_text)

    def _host_status_changed(self):
        """Handle host status toggle change."""
        self._update_host_tree()

    def _sort_lifecycle_tree(self, col):
        """Sort lifecycle treeview by column."""
        items = [(self.lifecycle_tree.set(k, col), k) for k in self.lifecycle_tree.get_children('')]
        try:
            items.sort(key=lambda t: float(t[0]) if t[0].replace('.', '').isdigit() else t[0])
        except:
            items.sort(key=lambda t: t[0])
        for index, (val, k) in enumerate(items):
            self.lifecycle_tree.move(k, '', index)

    def _lifecycle_page_changed(self):
        """Handle page size change."""
        self.lifecycle_current_start = 0  # Reset to beginning on page size change
        self._update_lifecycle_tree()

    def _lifecycle_first_page(self):
        """Navigate to first page."""
        self.lifecycle_current_start = 0
        self._update_lifecycle_tree()

    def _lifecycle_prev_page(self):
        """Navigate to previous page."""
        page_size = self.lifecycle_page_size.get()
        if page_size > 0:
            self.lifecycle_current_start = max(0, self.lifecycle_current_start - page_size)
            self._update_lifecycle_tree()

    def _lifecycle_next_page(self):
        """Navigate to next page."""
        df = self._get_chart_data('lifecycle')
        total = len(df)
        page_size = self.lifecycle_page_size.get()
        if page_size > 0:
            new_start = self.lifecycle_current_start + page_size
            if new_start < total:
                self.lifecycle_current_start = new_start
                self._update_lifecycle_tree()

    def _lifecycle_last_page(self):
        """Navigate to last page."""
        df = self._get_chart_data('lifecycle')
        total = len(df)
        page_size = self.lifecycle_page_size.get()
        if page_size > 0:
            self.lifecycle_current_start = max(0, total - page_size)
        else:
            self.lifecycle_current_start = 0
        self._update_lifecycle_tree()

    def _lifecycle_jump(self):
        """Jump to specific row number."""
        try:
            target = int(self.lifecycle_jump_to.get()) - 1  # Convert to 0-based index
            df = self._get_chart_data('lifecycle')
            total = len(df)
            if 0 <= target < total:
                self.lifecycle_current_start = target
                self._update_lifecycle_tree()
            else:
                messagebox.showwarning("Invalid Row", f"Row number must be between 1 and {total}")
        except ValueError:
            messagebox.showwarning("Invalid Input", "Please enter a valid row number")

    def _show_finding_detail(self, event):
        """Show detailed popup for double-clicked finding."""
        # Get selected item
        selection = self.lifecycle_tree.selection()
        if not selection:
            return

        item = selection[0]
        values = self.lifecycle_tree.item(item, 'values')

        if not values or len(values) < 2:
            return

        hostname = values[0]
        plugin_id = values[1]

        # Get full data from lifecycle_df
        df = self._get_chart_data('lifecycle')
        if df.empty:
            return

        # Find the matching row
        mask = (df['hostname'].astype(str) == str(hostname)) & \
               (df['plugin_id'].astype(str) == str(plugin_id))
        matches = df[mask]

        if matches.empty:
            return

        finding = matches.iloc[0]

        # Get additional details from historical_df if available
        hist_details = {}
        if not self.historical_df.empty:
            hist_mask = (self.historical_df['hostname'].astype(str) == str(hostname)) & \
                       (self.historical_df['plugin_id'].astype(str) == str(plugin_id))
            hist_matches = self.historical_df[hist_mask]
            if not hist_matches.empty:
                # Get the most recent entry
                latest_hist = hist_matches.sort_values('scan_date', ascending=False).iloc[0]
                hist_details = {
                    'output': latest_hist.get('output', ''),
                    'description': latest_hist.get('description', ''),
                    'solution': latest_hist.get('solution', ''),
                    'synopsis': latest_hist.get('synopsis', ''),
                    'see_also': latest_hist.get('see_also', ''),
                    'risk_factor': latest_hist.get('risk_factor', ''),
                    'port': latest_hist.get('port', ''),
                    'protocol': latest_hist.get('protocol', ''),
                }

        # Create the detail popup
        self._create_finding_detail_popup(finding, hist_details)

    def _create_finding_detail_popup(self, finding, hist_details):
        """Create and display the finding detail popup modal."""
        modal = tk.Toplevel(self.window)
        modal.title(f"Finding Details: {finding.get('plugin_name', 'Unknown')[:50]}")
        modal.geometry("900x900")
        modal.configure(bg=GUI_DARK_THEME['bg'])
        modal.transient(self.window)

        # Make resizable
        modal.resizable(True, True)
        modal.minsize(700, 900)

        # Main container with scrollbar
        main_frame = ttk.Frame(modal)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create canvas with scrollbar for the entire content
        canvas = tk.Canvas(main_frame, bg=GUI_DARK_THEME['bg'], highlightthickness=0)
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas_window = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        # Make scrollable_frame expand to canvas width
        def on_canvas_configure(event):
            canvas.itemconfig(canvas_window, width=event.width)
        canvas.bind('<Configure>', on_canvas_configure)

        # Enable mousewheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        canvas.bind_all("<MouseWheel>", _on_mousewheel)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Title section
        title_frame = tk.Frame(scrollable_frame, bg='#1a3a5c')
        title_frame.pack(fill=tk.X, pady=(0, 10))
        tk.Label(title_frame, text=finding.get('plugin_name', 'Unknown'),
                font=('Arial', 14, 'bold'), bg='#1a3a5c', fg='white',
                wraplength=850).pack(padx=10, pady=10)

        # Helper function to add a section
        def add_section(parent, title, content, is_resizable=False):
            if not content or content == 'nan' or pd.isna(content):
                return

            section_frame = ttk.LabelFrame(parent, text=title)
            section_frame.pack(fill=tk.X, pady=5, padx=5)

            if is_resizable:
                # Create resizable text widget for large content
                text_frame = ttk.Frame(section_frame)
                text_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

                text_widget = tk.Text(text_frame, wrap=tk.WORD,
                                     bg=GUI_DARK_THEME['entry_bg'],
                                     fg=GUI_DARK_THEME['fg'],
                                     font=('Consolas', 9),
                                     height=10)
                text_scrollbar = ttk.Scrollbar(text_frame, command=text_widget.yview)
                text_widget.configure(yscrollcommand=text_scrollbar.set)

                text_widget.insert('1.0', str(content))
                text_widget.configure(state='disabled')

                text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
                text_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

                # Add resize grip
                grip = ttk.Sizegrip(text_frame)
                grip.pack(side=tk.BOTTOM, anchor='se')
            else:
                label = tk.Label(section_frame, text=str(content),
                               bg=GUI_DARK_THEME['bg'], fg=GUI_DARK_THEME['fg'],
                               wraplength=850, justify=tk.LEFT, anchor='w')
                label.pack(fill=tk.X, padx=5, pady=5)

        # Helper function to add key-value row with multi-column support
        def add_row(parent, label, value, row_num, col_offset=0):
            if value is None or value == '' or value == 'nan' or (isinstance(value, float) and pd.isna(value)):
                return row_num

            base_col = col_offset * 3  # Each column pair takes 3 grid columns (label, value, spacer)
            tk.Label(parent, text=f"{label}:", font=('Arial', 9, 'bold'),
                    bg=GUI_DARK_THEME['bg'], fg='#17a2b8',
                    anchor='e', width=14).grid(row=row_num, column=base_col, sticky='e', padx=(5, 5), pady=2)
            tk.Label(parent, text=str(value), bg=GUI_DARK_THEME['bg'],
                    fg=GUI_DARK_THEME['fg'], anchor='w',
                    wraplength=300).grid(row=row_num, column=base_col + 1, sticky='w', pady=2)
            return row_num + 1

        # Basic Information section - condensed 2-column layout
        basic_frame = ttk.LabelFrame(scrollable_frame, text="Basic Information")
        basic_frame.pack(fill=tk.X, pady=5, padx=5)

        info_grid = ttk.Frame(basic_frame)
        info_grid.pack(fill=tk.X, padx=5, pady=5)

        # Collect valid items first
        basic_items = [
            ("Hostname", finding.get('hostname')),
            ("IP Address", finding.get('ip_address')),
            ("Plugin ID", finding.get('plugin_id')),
            ("Severity", finding.get('severity_text')),
            ("CVSS v3 Score", finding.get('cvss3_base_score')),
            ("Status", finding.get('status')),
        ]

        # Port/Protocol from historical
        if hist_details.get('port'):
            port_info = f"{hist_details.get('port')}/{hist_details.get('protocol', 'tcp')}"
            basic_items.append(("Port/Protocol", port_info))

        if hist_details.get('risk_factor'):
            basic_items.append(("Risk Factor", hist_details.get('risk_factor')))

        # Filter out empty/None values
        basic_items = [(k, v) for k, v in basic_items if v is not None and v != '' and v != 'nan' and not (isinstance(v, float) and pd.isna(v))]

        # Place in 2-column layout
        for i, (label, value) in enumerate(basic_items):
            row_num = i // 2
            col_offset = i % 2
            add_row(info_grid, label, value, row_num, col_offset)

        # Timeline section - condensed 2-column layout
        timeline_frame = ttk.LabelFrame(scrollable_frame, text="Timeline")
        timeline_frame.pack(fill=tk.X, pady=5, padx=5)

        time_grid = ttk.Frame(timeline_frame)
        time_grid.pack(fill=tk.X, padx=5, pady=5)

        timeline_items = [
            ("First Observed", finding.get('first_seen')),
            ("Last Seen", finding.get('last_seen')),
            ("Days Open", finding.get('days_open')),
            ("Total Observations", finding.get('total_observations')),
            ("Reappearances", finding.get('reappearances')),
        ]

        # Filter out empty/None values
        timeline_items = [(k, v) for k, v in timeline_items if v is not None and v != '' and v != 'nan' and not (isinstance(v, float) and pd.isna(v))]

        # Place in 2-column layout
        for i, (label, value) in enumerate(timeline_items):
            row_num = i // 2
            col_offset = i % 2
            add_row(time_grid, label, value, row_num, col_offset)

        # CVE/IAVX section - multi-column layout for long lists
        cve_iavx_frame = ttk.LabelFrame(scrollable_frame, text="CVE & IAVX References")
        cve_iavx_frame.pack(fill=tk.X, pady=5, padx=5)

        def add_multi_column_list(parent, label, values_str, num_cols=4):
            """Display a list of values in multiple columns."""
            if not values_str or values_str == 'nan' or pd.isna(values_str):
                return

            container = ttk.Frame(parent)
            container.pack(fill=tk.X, padx=5, pady=5)

            # Label row
            tk.Label(container, text=f"{label}:", font=('Arial', 9, 'bold'),
                    bg=GUI_DARK_THEME['bg'], fg='#17a2b8',
                    anchor='w').pack(anchor='w')

            # Parse values (comma or space separated)
            values_str = str(values_str)
            if ',' in values_str:
                values = [v.strip() for v in values_str.split(',') if v.strip()]
            else:
                values = [v.strip() for v in values_str.split() if v.strip()]

            if not values:
                return

            # Create grid for values
            grid_frame = ttk.Frame(container)
            grid_frame.pack(fill=tk.X, pady=(2, 0))

            # Configure columns to expand equally
            for col in range(num_cols):
                grid_frame.columnconfigure(col, weight=1)

            # Place values in grid
            for i, val in enumerate(values):
                row_num = i // num_cols
                col_num = i % num_cols
                tk.Label(grid_frame, text=val, bg=GUI_DARK_THEME['bg'],
                        fg=GUI_DARK_THEME['fg'], anchor='w',
                        font=('Consolas', 9)).grid(row=row_num, column=col_num,
                                                   sticky='w', padx=(0, 10), pady=1)

        add_multi_column_list(cve_iavx_frame, "CVEs", finding.get('cves'), num_cols=4)
        add_multi_column_list(cve_iavx_frame, "IAVX", finding.get('iavx'), num_cols=3)

        # OPDIR information if available
        opdir_num = finding.get('opdir_number')
        if opdir_num and not pd.isna(opdir_num):
            opdir_frame = ttk.LabelFrame(scrollable_frame, text="OPDIR Information")
            opdir_frame.pack(fill=tk.X, pady=5, padx=5)

            opdir_grid = ttk.Frame(opdir_frame)
            opdir_grid.pack(fill=tk.X, padx=5, pady=5)

            row = 0
            row = add_row(opdir_grid, "OPDIR Number", opdir_num, row)
            row = add_row(opdir_grid, "OPDIR Title", finding.get('opdir_title'), row)
            row = add_row(opdir_grid, "OPDIR Due Date", finding.get('opdir_due_date'), row)
            row = add_row(opdir_grid, "OPDIR Status", finding.get('opdir_status'), row)

        # Synopsis
        add_section(scrollable_frame, "Synopsis", hist_details.get('synopsis'))

        # Description
        add_section(scrollable_frame, "Description", hist_details.get('description'), is_resizable=True)

        # Solution
        add_section(scrollable_frame, "Solution", hist_details.get('solution'), is_resizable=True)

        # Plugin Output (resizable) - this is the big one
        add_section(scrollable_frame, "Plugin Output", hist_details.get('output'), is_resizable=True)

        # See Also
        add_section(scrollable_frame, "References (See Also)", hist_details.get('see_also'), is_resizable=True)

        # Gap details if reappearances exist
        gap_details = finding.get('gap_details')
        if gap_details and gap_details != '' and not pd.isna(gap_details):
            try:
                import json
                gaps = json.loads(gap_details)
                if gaps:
                    gap_text = "\n".join([
                        f"Gap {i+1}: {g['gap_start']} to {g['gap_end']} ({g['days']} days)"
                        for i, g in enumerate(gaps)
                    ])
                    add_section(scrollable_frame, "Reappearance Gaps", gap_text)
            except:
                pass

        # Close button
        btn_frame = ttk.Frame(modal)
        btn_frame.pack(fill=tk.X, pady=10)

        # Clean up mousewheel binding when modal closes
        def on_close():
            try:
                canvas.unbind_all("<MouseWheel>")
            except:
                pass
            modal.destroy()

        ttk.Button(btn_frame, text="Copy to Clipboard",
                  command=lambda: self._copy_finding_to_clipboard(finding, hist_details)).pack(side=tk.LEFT, padx=20)
        ttk.Button(btn_frame, text="Close", command=on_close).pack(side=tk.RIGHT, padx=20)

        modal.protocol("WM_DELETE_WINDOW", on_close)

        # Focus modal
        modal.focus_set()
        modal.grab_set()

    def _copy_finding_to_clipboard(self, finding, hist_details):
        """Copy finding details to clipboard as formatted text."""
        lines = []
        lines.append("=" * 60)
        lines.append(f"FINDING DETAILS: {finding.get('plugin_name', 'Unknown')}")
        lines.append("=" * 60)
        lines.append("")

        lines.append("BASIC INFORMATION")
        lines.append("-" * 40)
        lines.append(f"Hostname:       {finding.get('hostname', '')}")
        lines.append(f"IP Address:     {finding.get('ip_address', '')}")
        lines.append(f"Plugin ID:      {finding.get('plugin_id', '')}")
        lines.append(f"Severity:       {finding.get('severity_text', '')}")
        lines.append(f"CVSS v3 Score:  {finding.get('cvss3_base_score', '')}")
        lines.append(f"Status:         {finding.get('status', '')}")
        lines.append("")

        lines.append("TIMELINE")
        lines.append("-" * 40)
        lines.append(f"First Observed: {finding.get('first_seen', '')}")
        lines.append(f"Last Seen:      {finding.get('last_seen', '')}")
        lines.append(f"Days Open:      {finding.get('days_open', '')}")
        lines.append("")

        if finding.get('cves') or finding.get('iavx'):
            lines.append("REFERENCES")
            lines.append("-" * 40)
            if finding.get('cves'):
                lines.append(f"CVEs: {finding.get('cves')}")
            if finding.get('iavx'):
                lines.append(f"IAVX: {finding.get('iavx')}")
            lines.append("")

        if hist_details.get('synopsis'):
            lines.append("SYNOPSIS")
            lines.append("-" * 40)
            lines.append(hist_details.get('synopsis'))
            lines.append("")

        if hist_details.get('description'):
            lines.append("DESCRIPTION")
            lines.append("-" * 40)
            lines.append(hist_details.get('description'))
            lines.append("")

        if hist_details.get('solution'):
            lines.append("SOLUTION")
            lines.append("-" * 40)
            lines.append(hist_details.get('solution'))
            lines.append("")

        if hist_details.get('output'):
            lines.append("PLUGIN OUTPUT")
            lines.append("-" * 40)
            lines.append(hist_details.get('output'))
            lines.append("")

        text = "\n".join(lines)

        # Copy to clipboard
        self.window.clipboard_clear()
        self.window.clipboard_append(text)

        messagebox.showinfo("Copied", "Finding details copied to clipboard!")

    def _sort_host_tree(self, col):
        """Sort host treeview by column."""
        items = [(self.host_tree.set(k, col), k) for k in self.host_tree.get_children('')]
        try:
            items.sort(key=lambda t: float(t[0].rstrip('%')) if t[0].replace('.', '').replace('%', '').isdigit() else t[0])
        except:
            items.sort(key=lambda t: t[0])
        for index, (val, k) in enumerate(items):
            self.host_tree.move(k, '', index)

    def _update_trends_chart(self):
        """Update the trends chart showing active vs resolved over time."""
        if not HAS_MATPLOTLIB:
            return

        if not hasattr(self, 'trends_ax'):
            return

        self.trends_ax.clear()
        self.trends_ax.set_facecolor(GUI_DARK_THEME['entry_bg'])

        # Get the appropriate date interval based on date range
        interval = self._get_current_date_interval()
        period_format = get_period_format(interval)
        interval_label = get_interval_label(interval)

        # Use filtered scan_changes_df to show trends over time
        scan_df = self._get_chart_data('scan_changes')
        if not scan_df.empty and 'scan_date' in scan_df.columns:
            df = scan_df.copy()
            df['scan_date'] = pd.to_datetime(df['scan_date'])

            # Group by interval and count new/resolved
            if 'change_type' in df.columns:
                df['period'] = df['scan_date'].dt.to_period(period_format)
                trends = df.groupby(['period', 'change_type']).size().unstack(fill_value=0)
                labels = get_period_labels(trends.index, interval)

                if 'New' in trends.columns:
                    self.trends_ax.plot(range(len(trends)), trends['New'], 'r-', label='New', marker='o', markersize=4)
                if 'Resolved' in trends.columns:
                    self.trends_ax.plot(range(len(trends)), trends['Resolved'], 'g-', label='Resolved', marker='s', markersize=4)

                self.trends_ax.set_xticks(range(len(trends)))
                self.trends_ax.set_xticklabels(labels, rotation=45, ha='right', fontsize=8)
                self.trends_ax.legend(loc='upper right', facecolor=GUI_DARK_THEME['bg'],
                                     labelcolor=GUI_DARK_THEME['fg'])

        # If no scan_changes, try to use historical_df to show cumulative counts
        hist_df = self._get_chart_data('historical')
        if scan_df.empty and not hist_df.empty and 'scan_date' in hist_df.columns:
            df = hist_df.copy()
            df['scan_date'] = pd.to_datetime(df['scan_date'])

            # Count findings per interval
            counts = group_by_interval(df, 'scan_date', interval)
            labels = get_period_labels(counts.index, interval)

            self.trends_ax.bar(range(len(counts)), counts.values, color='#007bff', alpha=0.7)
            self.trends_ax.set_xticks(range(len(counts)))
            self.trends_ax.set_xticklabels(labels, rotation=45, ha='right', fontsize=8)

        # Style the chart
        self.trends_ax.set_xlabel(interval_label, color=GUI_DARK_THEME['fg'])
        self.trends_ax.set_ylabel('Count', color=GUI_DARK_THEME['fg'])
        self.trends_ax.tick_params(colors=GUI_DARK_THEME['fg'])
        for spine in self.trends_ax.spines.values():
            spine.set_color(GUI_DARK_THEME['fg'])

        self.trends_fig.tight_layout()
        self.trends_canvas.draw()

    def _update_timeline_charts(self):
        """Update timeline analysis visualizations."""
        if not HAS_MATPLOTLIB or not hasattr(self, 'timeline_ax1'):
            return

        df = self._get_chart_data('lifecycle')
        hist_df = self._get_chart_data('historical')
        show_labels = self.settings_manager.settings.show_data_labels

        # Get the appropriate date interval based on date range
        interval = self._get_current_date_interval()
        period_format = get_period_format(interval)
        interval_label = get_interval_label(interval)

        # Clear all axes
        for ax in [self.timeline_ax1, self.timeline_ax2, self.timeline_ax3, self.timeline_ax4]:
            ax.clear()
            ax.set_facecolor(GUI_DARK_THEME['entry_bg'])

        if hist_df.empty:
            self.timeline_canvas.draw()
            return

        hist_df = hist_df.copy()
        hist_df['scan_date'] = pd.to_datetime(hist_df['scan_date'])

        # Chart 1: Total findings over time with data labels (grouped by interval)
        counts = group_by_interval(hist_df, 'scan_date', interval)
        labels = get_period_labels(counts.index, interval)
        line, = self.timeline_ax1.plot(range(len(counts)), counts.values, 'c-', marker='o', markersize=5)
        self.timeline_ax1.fill_between(range(len(counts)), counts.values, alpha=0.2, color='cyan')
        self.timeline_ax1.set_xticks(range(len(counts)))
        self.timeline_ax1.set_xticklabels(labels, rotation=45, ha='right', fontsize=7)
        if show_labels and len(counts) <= 15:
            for i, (x, y) in enumerate(zip(range(len(counts)), counts.values)):
                self.timeline_ax1.annotate(f'{int(y)}', xy=(x, y), xytext=(0, 5),
                                          textcoords='offset points', ha='center', va='bottom',
                                          fontsize=7, color='white')
        # Add trend indicator
        if len(counts) >= 2:
            change = counts.iloc[-1] - counts.iloc[0]
            pct = change / counts.iloc[0] * 100 if counts.iloc[0] > 0 else 0
            color = '#28a745' if change < 0 else '#dc3545'
            symbol = '↓' if change < 0 else '↑'
            self.timeline_ax1.text(0.98, 0.98, f'{symbol}{abs(pct):.0f}%', transform=self.timeline_ax1.transAxes,
                                  fontsize=9, va='top', ha='right', color=color, fontweight='bold')
        self.timeline_ax1.set_title(f'Total Findings by {interval_label}', color=GUI_DARK_THEME['fg'], fontsize=10)
        self.timeline_ax1.set_ylabel('Count', color=GUI_DARK_THEME['fg'])

        # Chart 2: Severity breakdown over time with markers (grouped by interval)
        if 'severity_text' in hist_df.columns:
            severity_colors = {'Critical': '#dc3545', 'High': '#fd7e14', 'Medium': '#ffc107', 'Low': '#007bff', 'Info': '#6c757d'}
            for sev in ['Critical', 'High', 'Medium', 'Low']:
                sev_df = hist_df[hist_df['severity_text'] == sev]
                if not sev_df.empty:
                    sev_counts = group_by_interval(sev_df, 'scan_date', interval)
                    if len(sev_counts) > 0:
                        self.timeline_ax2.plot(range(len(sev_counts)), sev_counts.values, color=severity_colors.get(sev, 'gray'),
                                              label=f'{sev} ({sev_counts.iloc[-1] if len(sev_counts) > 0 else 0})',
                                              marker='o', markersize=4, linewidth=2)
            self.timeline_ax2.legend(fontsize=7, facecolor=GUI_DARK_THEME['bg'], labelcolor=GUI_DARK_THEME['fg'])
        self.timeline_ax2.set_title('Findings by Severity', color=GUI_DARK_THEME['fg'], fontsize=10)

        # Chart 3: New vs Resolved with data labels (grouped by interval)
        scan_df = self._get_chart_data('scan_changes')
        if not scan_df.empty and 'change_type' in scan_df.columns:
            changes = scan_df.copy()
            changes['scan_date'] = pd.to_datetime(changes['scan_date'])
            changes['period'] = changes['scan_date'].dt.to_period(period_format)
            new_counts = changes[changes['change_type'] == 'New'].groupby('period').size()
            resolved_counts = changes[changes['change_type'] == 'Resolved'].groupby('period').size()
            period_labels = get_period_labels(new_counts.index, interval) if len(new_counts) > 0 else []
            if len(new_counts) > 0:
                bars1 = self.timeline_ax3.bar([i - 0.2 for i in range(len(new_counts))], new_counts.values, 0.4, label='New', color='#dc3545')
                self.timeline_ax3.set_xticks(range(len(new_counts)))
                self.timeline_ax3.set_xticklabels(period_labels, rotation=45, ha='right', fontsize=7)
                if show_labels:
                    for bar, val in zip(bars1, new_counts.values):
                        self.timeline_ax3.annotate(f'{int(val)}', xy=(bar.get_x() + bar.get_width()/2, val),
                                                  xytext=(0, 2), textcoords='offset points',
                                                  ha='center', va='bottom', fontsize=6, color='white')
            if len(resolved_counts) > 0:
                bars2 = self.timeline_ax3.bar([i + 0.2 for i in range(len(resolved_counts))], resolved_counts.values, 0.4, label='Resolved', color='#28a745')
                if show_labels:
                    for bar, val in zip(bars2, resolved_counts.values):
                        self.timeline_ax3.annotate(f'{int(val)}', xy=(bar.get_x() + bar.get_width()/2, val),
                                                  xytext=(0, 2), textcoords='offset points',
                                                  ha='center', va='bottom', fontsize=6, color='white')
            self.timeline_ax3.legend(fontsize=7, facecolor=GUI_DARK_THEME['bg'], labelcolor=GUI_DARK_THEME['fg'])
        self.timeline_ax3.set_title('New vs Resolved', color=GUI_DARK_THEME['fg'], fontsize=10)

        # Chart 4: Cumulative risk with current value label (grouped by interval)
        if 'severity_value' in hist_df.columns:
            hist_df['period'] = hist_df['scan_date'].dt.to_period(period_format)
            risk = hist_df.groupby('period')['severity_value'].sum().cumsum()
            risk_labels = get_period_labels(risk.index, interval)
            self.timeline_ax4.fill_between(range(len(risk)), risk.values, alpha=0.5, color='#dc3545')
            self.timeline_ax4.plot(range(len(risk)), risk.values, 'r-', linewidth=2, marker='o', markersize=4)
            self.timeline_ax4.set_xticks(range(len(risk)))
            self.timeline_ax4.set_xticklabels(risk_labels, rotation=45, ha='right', fontsize=7)
            if len(risk) > 0:
                # Show current and peak values
                current = risk.iloc[-1]
                peak = risk.max()
                self.timeline_ax4.text(0.02, 0.98, f'Current: {int(current):,}', transform=self.timeline_ax4.transAxes,
                                      fontsize=8, va='top', color='white')
                if peak != current:
                    self.timeline_ax4.text(0.02, 0.88, f'Peak: {int(peak):,}', transform=self.timeline_ax4.transAxes,
                                          fontsize=8, va='top', color='#ffc107')
        self.timeline_ax4.set_title('Cumulative Risk Exposure', color=GUI_DARK_THEME['fg'], fontsize=10)

        for ax in [self.timeline_ax1, self.timeline_ax2, self.timeline_ax3, self.timeline_ax4]:
            ax.tick_params(colors=GUI_DARK_THEME['fg'])
            for spine in ax.spines.values():
                spine.set_color(GUI_DARK_THEME['fg'])

        self.timeline_fig.tight_layout()
        self.timeline_canvas.draw()

    def _update_risk_charts(self):
        """Update risk analysis visualizations."""
        if not HAS_MATPLOTLIB or not hasattr(self, 'risk_ax1'):
            return

        df = self._get_chart_data('lifecycle')

        for ax in [self.risk_ax1, self.risk_ax2, self.risk_ax3, self.risk_ax4]:
            ax.clear()
            ax.set_facecolor(GUI_DARK_THEME['entry_bg'])

        if df.empty:
            self.risk_canvas.draw()
            return

        # Check if data labels are enabled
        show_labels = self.settings_manager.settings.show_data_labels

        # Chart 1: CVSS distribution with severity-based coloring
        if 'cvss3_base_score' in df.columns:
            cvss_scores = pd.to_numeric(df['cvss3_base_score'], errors='coerce').dropna()
            if len(cvss_scores) > 0:
                # Create histogram with color-coded bins
                n, bins, patches = self.risk_ax1.hist(cvss_scores, bins=10, edgecolor='white', alpha=0.8)
                # Color by severity range
                for i, patch in enumerate(patches):
                    bin_center = (bins[i] + bins[i+1]) / 2
                    if bin_center >= 9:
                        patch.set_facecolor('#dc3545')  # Critical
                    elif bin_center >= 7:
                        patch.set_facecolor('#fd7e14')  # High
                    elif bin_center >= 4:
                        patch.set_facecolor('#ffc107')  # Medium
                    else:
                        patch.set_facecolor('#007bff')  # Low
                # Add summary stats
                avg_cvss = cvss_scores.mean()
                max_cvss = cvss_scores.max()
                self.risk_ax1.text(0.98, 0.98, f'Avg: {avg_cvss:.1f} | Max: {max_cvss:.1f}',
                                  transform=self.risk_ax1.transAxes, fontsize=8, va='top', ha='right', color='white')
        self.risk_ax1.set_title('CVSS Score Distribution', color=GUI_DARK_THEME['fg'], fontsize=10)
        self.risk_ax1.set_xlabel('CVSS Score', color=GUI_DARK_THEME['fg'])
        self.risk_ax1.set_ylabel('Count', color=GUI_DARK_THEME['fg'])

        # Chart 2: MTTR by severity with severity-colored bars
        if 'severity_text' in df.columns and 'days_open' in df.columns:
            resolved = df[df['status'] == 'Resolved'].copy()
            if not resolved.empty:
                resolved['days_open_numeric'] = pd.to_numeric(resolved['days_open'], errors='coerce')
                mttr = resolved.groupby('severity_text')['days_open_numeric'].mean()
                severity_order = ['Critical', 'High', 'Medium', 'Low']
                mttr = mttr.reindex([s for s in severity_order if s in mttr.index])
                severity_colors = {'Critical': '#dc3545', 'High': '#fd7e14', 'Medium': '#ffc107', 'Low': '#007bff'}
                colors = [severity_colors.get(s, '#6c757d') for s in mttr.index]
                bars = self.risk_ax2.bar(range(len(mttr)), mttr.values, color=colors)
                self.risk_ax2.set_xticks(range(len(mttr)))
                self.risk_ax2.set_xticklabels(mttr.index, fontsize=8)
                if show_labels:
                    for bar, val in zip(bars, mttr.values):
                        self.risk_ax2.annotate(f'{val:.0f}d', xy=(bar.get_x() + bar.get_width()/2, val),
                                              xytext=(0, 3), textcoords='offset points',
                                              ha='center', va='bottom', fontsize=7, color='white')
                # Overall MTTR
                overall_mttr = resolved['days_open_numeric'].mean()
                self.risk_ax2.axhline(y=overall_mttr, color='white', linestyle='--', linewidth=1, alpha=0.5)
                self.risk_ax2.text(0.02, 0.98, f'Overall: {overall_mttr:.0f}d', transform=self.risk_ax2.transAxes,
                                  fontsize=7, va='top', color='white')
        self.risk_ax2.set_title('Mean Time to Remediation', color=GUI_DARK_THEME['fg'], fontsize=10)
        self.risk_ax2.set_ylabel('Days', color=GUI_DARK_THEME['fg'])

        # Chart 3: Findings by age with urgency coloring
        if 'days_open' in df.columns:
            active = df[df['status'] == 'Active'].copy()
            if not active.empty:
                active['days_open_numeric'] = pd.to_numeric(active['days_open'], errors='coerce')
                buckets = [0, 30, 60, 90, 120, float('inf')]
                labels = ['0-30', '31-60', '61-90', '91-120', '121+']
                age_counts = pd.cut(active['days_open_numeric'], bins=buckets, labels=labels).value_counts().sort_index()
                colors = ['#28a745', '#ffc107', '#fd7e14', '#dc3545', '#dc3545']
                bars = self.risk_ax3.bar(range(len(age_counts)), age_counts.values, color=colors)
                self.risk_ax3.set_xticks(range(len(age_counts)))
                self.risk_ax3.set_xticklabels(labels, fontsize=8)
                if show_labels:
                    for bar, val in zip(bars, age_counts.values):
                        if val > 0:
                            self.risk_ax3.annotate(f'{int(val)}', xy=(bar.get_x() + bar.get_width()/2, val),
                                                  xytext=(0, 3), textcoords='offset points',
                                                  ha='center', va='bottom', fontsize=7, color='white')
                # Average age
                avg_age = active['days_open_numeric'].mean()
                self.risk_ax3.text(0.98, 0.98, f'Avg: {avg_age:.0f}d', transform=self.risk_ax3.transAxes,
                                  fontsize=8, va='top', ha='right', color='white')
        self.risk_ax3.set_title('Active Findings by Age', color=GUI_DARK_THEME['fg'], fontsize=10)
        self.risk_ax3.set_xlabel('Days Open', color=GUI_DARK_THEME['fg'])

        # Chart 4: Top risky hosts - Top 5 per environment (embedded view)
        if 'hostname' in df.columns and 'severity_value' in df.columns:
            env_colors = {'Production': '#28a745', 'PSS': '#007bff', 'Shared': '#ffc107', 'Unknown': '#6c757d'}
            env_types = self.settings_manager.settings.environment_types if hasattr(self, 'settings_manager') else ['Production', 'PSS', 'Shared']

            all_hosts = []
            for env in env_types:
                env_hosts = df[df['hostname'].apply(lambda h: self._get_environment_type(h) == env)]
                if not env_hosts.empty:
                    host_risk = env_hosts.groupby('hostname')['severity_value'].sum().nlargest(5)
                    for h, r in host_risk.items():
                        all_hosts.append({'hostname': h, 'risk': r, 'env': env})

            if all_hosts:
                # Sort by environment then by risk descending
                all_hosts.sort(key=lambda x: (env_types.index(x['env']) if x['env'] in env_types else 99, -x['risk']))
                hostnames = [h['hostname'] for h in all_hosts]
                risks = [h['risk'] for h in all_hosts]
                colors = [env_colors.get(h['env'], '#6c757d') for h in all_hosts]

                bars = self.risk_ax4.barh(range(len(all_hosts)), risks, color=colors)
                self.risk_ax4.set_yticks(range(len(all_hosts)))
                self.risk_ax4.set_yticklabels([h[:12] for h in hostnames], fontsize=6)
                if show_labels:
                    for bar, val in zip(bars, risks):
                        self.risk_ax4.annotate(f'{int(val)}', xy=(val, bar.get_y() + bar.get_height()/2),
                                              xytext=(3, 0), textcoords='offset points',
                                              ha='left', va='center', fontsize=5, color='white')
                self.risk_ax4.invert_yaxis()
                # Add legend for environment colors
                from matplotlib.patches import Patch
                legend_elements = [Patch(facecolor=env_colors.get(e, '#6c757d'), label=e[:4]) for e in env_types if e in [h['env'] for h in all_hosts]]
                if legend_elements:
                    self.risk_ax4.legend(handles=legend_elements, loc='lower right', fontsize=5,
                                        facecolor=GUI_DARK_THEME['bg'], labelcolor=GUI_DARK_THEME['fg'])
        self.risk_ax4.set_title('Top Risky Hosts by Environment', color=GUI_DARK_THEME['fg'], fontsize=10)
        self.risk_ax4.set_xlabel('Risk Score', color=GUI_DARK_THEME['fg'])

        for ax in [self.risk_ax1, self.risk_ax2, self.risk_ax3, self.risk_ax4]:
            ax.tick_params(colors=GUI_DARK_THEME['fg'])
            for spine in ax.spines.values():
                spine.set_color(GUI_DARK_THEME['fg'])

        self.risk_fig.tight_layout()
        self.risk_canvas.draw()

    def _bind_chart_popouts_risk(self):
        """Bind double-click pop-out for risk charts."""
        def get_click_quadrant(event):
            """Determine which quadrant was clicked (0-3 for 2x2 grid)."""
            widget = event.widget
            w, h = widget.winfo_width(), widget.winfo_height()
            x, y = event.x, event.y
            col = 0 if x < w / 2 else 1
            row = 0 if y < h / 2 else 1
            return row * 2 + col

        def on_double_click(event):
            quadrant = get_click_quadrant(event)
            chart_info = [
                ('CVSS Score Distribution', self._draw_cvss_popout),
                ('Mean Time to Remediation', self._draw_mttr_popout),
                ('Findings by Age', self._draw_age_popout),
                ('Top Risky Hosts', self._draw_risky_hosts_popout),
            ]
            title, redraw_func = chart_info[quadrant]
            ChartPopoutModal(self.window, title, redraw_func)

        self.risk_canvas.get_tk_widget().bind('<Double-Button-1>', on_double_click)

    def _draw_cvss_popout(self, fig, ax, enlarged=False, show_labels=True, filter_settings=None):
        """Draw CVSS distribution chart for pop-out."""
        df = self._get_chart_data('lifecycle')
        if df.empty or 'cvss3_base_score' not in df.columns:
            ax.text(0.5, 0.5, 'No CVSS data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        cvss_scores = pd.to_numeric(df['cvss3_base_score'], errors='coerce').dropna()
        if len(cvss_scores) == 0:
            ax.text(0.5, 0.5, 'No CVSS scores found', ha='center', va='center',
                   color='white', fontsize=12)
            return

        # Larger bins for better visibility
        n, bins, patches = ax.hist(cvss_scores, bins=20, color='#007bff',
                                   edgecolor='white', alpha=0.8)

        # Color by severity range
        for i, patch in enumerate(patches):
            bin_center = (bins[i] + bins[i+1]) / 2
            if bin_center >= 9.0:
                patch.set_facecolor('#dc3545')  # Critical
            elif bin_center >= 7.0:
                patch.set_facecolor('#fd7e14')  # High
            elif bin_center >= 4.0:
                patch.set_facecolor('#ffc107')  # Medium
            else:
                patch.set_facecolor('#28a745')  # Low

        if show_labels and enlarged:
            for i, count in enumerate(n):
                if count > 0:
                    ax.annotate(f'{int(count)}',
                               xy=((bins[i] + bins[i+1]) / 2, count),
                               ha='center', va='bottom', fontsize=8, color='white')

        ax.set_title('CVSS Score Distribution')
        ax.set_xlabel('CVSS Score')
        ax.set_ylabel('Count')
        ax.axvline(x=7.0, color='#fd7e14', linestyle='--', alpha=0.7, label='High (7.0)')
        ax.axvline(x=9.0, color='#dc3545', linestyle='--', alpha=0.7, label='Critical (9.0)')
        ax.legend(fontsize=9)

    def _draw_mttr_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw MTTR by severity chart for pop-out.

        Uses smart filtering: Always shows Remediated findings regardless of status filter.
        MTTR can only be calculated from resolved findings.
        """
        # Smart filter: MTTR always needs remediated findings
        df = self._get_chart_data('lifecycle', smart_filter='remediated_only')
        if df.empty or 'severity_text' not in df.columns or 'days_open' not in df.columns:
            ax.text(0.5, 0.5, 'No MTTR data available\n(No remediated findings in selected range)',
                   ha='center', va='center', color='white', fontsize=12)
            return

        df = df.copy()
        df['days_open'] = pd.to_numeric(df['days_open'], errors='coerce')
        mttr = df.groupby('severity_text')['days_open'].mean()
        severity_order = ['Critical', 'High', 'Medium', 'Low', 'Info']
        mttr = mttr.reindex([s for s in severity_order if s in mttr.index])

        colors = {'Critical': '#dc3545', 'High': '#fd7e14', 'Medium': '#ffc107',
                 'Low': '#28a745', 'Info': '#17a2b8'}
        bar_colors = [colors.get(s, '#6c757d') for s in mttr.index]

        bars = ax.bar(range(len(mttr)), mttr.values, color=bar_colors)
        ax.set_xticks(range(len(mttr)))
        ax.set_xticklabels(mttr.index, fontsize=10)

        if show_labels:
            for bar, val in zip(bars, mttr.values):
                ax.annotate(f'{val:.1f}d',
                           xy=(bar.get_x() + bar.get_width() / 2, val),
                           ha='center', va='bottom', fontsize=10, color='white')

        ax.set_title('Mean Time to Remediation by Severity')
        ax.set_ylabel('Days')

    def _draw_age_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw findings by age chart for pop-out."""
        df = self._get_chart_data('lifecycle')
        if df.empty or 'days_open' not in df.columns:
            ax.text(0.5, 0.5, 'No age data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        active = df[df['status'] == 'Active']
        if active.empty:
            ax.text(0.5, 0.5, 'No active findings', ha='center', va='center',
                   color='white', fontsize=12)
            return

        buckets = [0, 30, 60, 90, 120, 180, 365, float('inf')]
        labels = ['0-30', '31-60', '61-90', '91-120', '121-180', '181-365', '365+']
        age_counts = pd.cut(active['days_open'], bins=buckets, labels=labels).value_counts().sort_index()

        # Color gradient from green to red
        colors = ['#28a745', '#7cb342', '#ffc107', '#ff9800', '#ff5722', '#dc3545', '#b71c1c']
        bars = ax.bar(range(len(age_counts)), age_counts.values, color=colors[:len(age_counts)])
        ax.set_xticks(range(len(age_counts)))
        ax.set_xticklabels(labels, fontsize=9)

        if show_labels:
            for bar, val in zip(bars, age_counts.values):
                if val > 0:
                    ax.annotate(f'{int(val)}',
                               xy=(bar.get_x() + bar.get_width() / 2, val),
                               ha='center', va='bottom', fontsize=9, color='white')

        ax.set_title('Active Findings by Age (Days)')
        ax.set_ylabel('Count')

    def _draw_risky_hosts_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw top risky hosts chart for pop-out - Top 10 per environment."""
        df = self._get_chart_data('lifecycle')
        if df.empty or 'hostname' not in df.columns or 'severity_value' not in df.columns:
            ax.text(0.5, 0.5, 'No host risk data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        env_colors = {'Production': '#28a745', 'PSS': '#007bff', 'Shared': '#ffc107', 'Unknown': '#6c757d'}
        env_types = self.settings_manager.settings.environment_types if hasattr(self, 'settings_manager') else ['Production', 'PSS', 'Shared']
        num_per_env = 10

        all_hosts = []
        for env in env_types:
            env_hosts = df[df['hostname'].apply(lambda h: self._get_environment_type(h) == env)]
            if not env_hosts.empty:
                host_risk = env_hosts.groupby('hostname')['severity_value'].sum().nlargest(num_per_env)
                for h, r in host_risk.items():
                    all_hosts.append({'hostname': h, 'risk': r, 'env': env})

        if not all_hosts:
            ax.text(0.5, 0.5, 'No host data', ha='center', va='center',
                   color='white', fontsize=12)
            return

        # Sort by environment then by risk descending
        all_hosts.sort(key=lambda x: (env_types.index(x['env']) if x['env'] in env_types else 99, -x['risk']))
        hostnames = [h['hostname'] for h in all_hosts]
        risks = [h['risk'] for h in all_hosts]
        colors = [env_colors.get(h['env'], '#6c757d') for h in all_hosts]

        bars = ax.barh(range(len(all_hosts)), risks, color=colors)
        ax.set_yticks(range(len(all_hosts)))
        ax.set_yticklabels([h[:20] for h in hostnames], fontsize=8)

        if show_labels:
            for bar, val in zip(bars, risks):
                ax.annotate(f'{int(val)}',
                           xy=(val, bar.get_y() + bar.get_height() / 2),
                           xytext=(3, 0), textcoords='offset points',
                           ha='left', va='center', fontsize=8, color='white')

        # Add legend
        from matplotlib.patches import Patch
        legend_elements = [Patch(facecolor=env_colors.get(e, '#6c757d'), label=e) for e in env_types if e in [h['env'] for h in all_hosts]]
        if legend_elements:
            ax.legend(handles=legend_elements, loc='lower right', fontsize=9)

        ax.set_title(f'Top {num_per_env} Risky Hosts per Environment (by Severity Score)')
        ax.set_xlabel('Risk Score')
        ax.invert_yaxis()

    def _bind_chart_popouts_metrics(self):
        """Bind double-click pop-out for Metrics tab charts."""
        if not hasattr(self, 'metrics_canvas'):
            return

        def get_click_quadrant(event):
            """Determine which quadrant of the 2x2 grid was clicked."""
            widget = event.widget
            w, h = widget.winfo_width(), widget.winfo_height()
            x, y = event.x, event.y
            col = 0 if x < w / 2 else 1
            row = 0 if y < h / 2 else 1
            return row * 2 + col

        def on_double_click(event):
            quadrant = get_click_quadrant(event)
            chart_info = [
                ('Remediation Status by Severity', self._draw_remediation_popout),
                ('Risk Score Trend', self._draw_risk_trend_popout),
                ('SLA Status by Severity', self._draw_sla_status_popout),
                ('Vulnerabilities per Host Trend', self._draw_vulns_per_host_popout),
            ]
            title, redraw_func = chart_info[quadrant]
            ChartPopoutModal(self.window, title, redraw_func)

        self.metrics_canvas.get_tk_widget().bind('<Double-Button-1>', on_double_click)

    def _draw_remediation_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw remediation status chart for pop-out."""
        df = self._get_chart_data('lifecycle')
        hist_df = self._get_chart_data('historical')

        if df.empty:
            ax.text(0.5, 0.5, 'No data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        remediation_metrics = calculate_remediation_rate(df, hist_df)
        by_sev = remediation_metrics.get('by_severity', {})

        if not by_sev:
            ax.text(0.5, 0.5, 'No remediation data', ha='center', va='center',
                   color='white', fontsize=12)
            return

        severities = ['Critical', 'High', 'Medium', 'Low']
        remediated = [by_sev.get(s, {}).get('remediated', 0) for s in severities]
        active = [by_sev.get(s, {}).get('active', 0) for s in severities]
        discovered = [by_sev.get(s, {}).get('discovered', 0) for s in severities]

        x = range(len(severities))
        width = 0.25

        # Show discovered in enlarged view
        if enlarged:
            bars1 = ax.bar([i - width for i in x], discovered, width, label='Discovered', color='#6c757d')
            bars2 = ax.bar([i for i in x], remediated, width, label='Remediated', color='#28a745')
            bars3 = ax.bar([i + width for i in x], active, width, label='Active', color='#dc3545')
            if show_labels:
                for bars in [bars1, bars2, bars3]:
                    for bar in bars:
                        h = bar.get_height()
                        if h > 0:
                            ax.annotate(f'{int(h)}', xy=(bar.get_x() + bar.get_width()/2, h),
                                       xytext=(0, 3), textcoords='offset points',
                                       ha='center', va='bottom', fontsize=9, color='white')
        else:
            bars1 = ax.bar([i - width/2 for i in x], remediated, width, label='Remediated', color='#28a745')
            bars2 = ax.bar([i + width/2 for i in x], active, width, label='Active', color='#dc3545')
            if show_labels:
                for bars in [bars1, bars2]:
                    for bar in bars:
                        h = bar.get_height()
                        if h > 0:
                            ax.annotate(f'{int(h)}', xy=(bar.get_x() + bar.get_width()/2, h),
                                       xytext=(0, 3), textcoords='offset points',
                                       ha='center', va='bottom', fontsize=9, color='white')

        ax.set_xticks(x)
        ax.set_xticklabels(severities, fontsize=10)
        ax.legend(loc='upper right', fontsize=9)
        ax.set_title('Remediation Status by Severity')
        ax.set_ylabel('Count')

        # Add summary text in enlarged view
        if enlarged:
            total_rem = sum(remediated)
            total_act = sum(active)
            rate = total_rem / (total_rem + total_act) * 100 if (total_rem + total_act) > 0 else 0
            ax.text(0.02, 0.98, f'Overall Rate: {rate:.1f}%', transform=ax.transAxes,
                   fontsize=10, va='top', color='#28a745')

    def _draw_risk_trend_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw risk score trend chart for pop-out."""
        hist_df = self._get_chart_data('historical')

        risk_trend = calculate_risk_reduction_trend(hist_df)

        if risk_trend.empty or len(risk_trend) < 2:
            ax.text(0.5, 0.5, 'Insufficient historical data\n(need 2+ scans)', ha='center', va='center',
                   color='white', fontsize=12)
            return

        dates = risk_trend['scan_date']
        risk_scores = risk_trend['total_risk_score']

        # Plot with markers
        line, = ax.plot(range(len(dates)), risk_scores, marker='o', color='#007bff',
                       linewidth=2, markersize=8 if enlarged else 5)
        ax.fill_between(range(len(dates)), risk_scores, alpha=0.3, color='#007bff')

        # Add data labels
        if show_labels:
            for i, (x, y) in enumerate(zip(range(len(dates)), risk_scores)):
                # Skip some labels if too crowded
                if not enlarged and len(dates) > 10 and i % 2 != 0:
                    continue
                ax.annotate(f'{int(y)}', xy=(x, y), xytext=(0, 8), textcoords='offset points',
                           ha='center', va='bottom', fontsize=9 if enlarged else 7, color='white')

        # Format date labels
        if len(dates) > 8:
            step = max(1, len(dates) // 8)
            tick_positions = list(range(0, len(dates), step))
            ax.set_xticks(tick_positions)
            tick_labels = [dates.iloc[i].strftime('%m/%d/%y') if hasattr(dates.iloc[i], 'strftime')
                          else str(dates.iloc[i])[:8] for i in tick_positions]
            ax.set_xticklabels(tick_labels, fontsize=9, rotation=45, ha='right')
        else:
            ax.set_xticks(range(len(dates)))
            tick_labels = [d.strftime('%m/%d/%y') if hasattr(d, 'strftime') else str(d)[:8] for d in dates]
            ax.set_xticklabels(tick_labels, fontsize=9, rotation=45, ha='right')

        ax.set_title('Risk Score Trend Over Time')
        ax.set_ylabel('Total Risk Score')
        ax.set_xlabel('Scan Date')

        # Add trend indicator
        if enlarged and len(risk_scores) >= 2:
            change = risk_scores.iloc[-1] - risk_scores.iloc[0]
            pct_change = change / risk_scores.iloc[0] * 100 if risk_scores.iloc[0] > 0 else 0
            color = '#28a745' if change < 0 else '#dc3545'
            symbol = '↓' if change < 0 else '↑'
            ax.text(0.98, 0.98, f'{symbol} {abs(pct_change):.1f}%', transform=ax.transAxes,
                   fontsize=12, va='top', ha='right', color=color, fontweight='bold')

    def _draw_sla_status_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw SLA status chart for pop-out."""
        df = self._get_chart_data('lifecycle')

        if df.empty:
            ax.text(0.5, 0.5, 'No data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        sla_targets = self.settings_manager.settings.get_sla_targets()
        sla_targets = {k: v for k, v in sla_targets.items() if v is not None}
        sla_metrics = calculate_sla_breach_tracking(df, sla_targets)
        sla_by_sev = sla_metrics.get('by_severity', {})

        if not sla_by_sev:
            ax.text(0.5, 0.5, 'No SLA data\n(configure SLA targets in Settings)', ha='center', va='center',
                   color='white', fontsize=12)
            return

        severities = ['Critical', 'High', 'Medium', 'Low']
        breached = [sla_by_sev.get(s, {}).get('breached', 0) for s in severities]
        at_risk = [sla_by_sev.get(s, {}).get('at_risk', 0) for s in severities]
        on_track = [sla_by_sev.get(s, {}).get('on_track', 0) for s in severities]

        x = range(len(severities))
        bars1 = ax.bar(x, breached, label='Breached', color='#dc3545')
        bars2 = ax.bar(x, at_risk, bottom=breached, label='At Risk', color='#ffc107')
        bottom_track = [b + r for b, r in zip(breached, at_risk)]
        bars3 = ax.bar(x, on_track, bottom=bottom_track, label='On Track', color='#28a745')

        ax.set_xticks(x)
        ax.set_xticklabels(severities, fontsize=10)
        ax.legend(loc='upper right', fontsize=9)
        ax.set_title('SLA Status by Severity')
        ax.set_ylabel('Count')

        # Add labels on bars
        if show_labels:
            for bars, values in [(bars1, breached), (bars2, at_risk), (bars3, on_track)]:
                for bar, val in zip(bars, values):
                    if val > 0:
                        h = bar.get_height()
                        y_pos = bar.get_y() + h / 2
                        ax.annotate(f'{int(val)}', xy=(bar.get_x() + bar.get_width()/2, y_pos),
                                   ha='center', va='center', fontsize=9, color='white', fontweight='bold')

        # Add summary in enlarged view
        if enlarged:
            total_breached = sum(breached)
            total_count = sum(breached) + sum(at_risk) + sum(on_track)
            breach_rate = total_breached / total_count * 100 if total_count > 0 else 0
            ax.text(0.02, 0.98, f'Breach Rate: {breach_rate:.1f}%', transform=ax.transAxes,
                   fontsize=10, va='top', color='#dc3545' if breach_rate > 20 else '#28a745')

            # Show SLA targets
            targets_text = 'SLA Targets (days): ' + ', '.join([f'{k[0]}: {v}' for k, v in sla_targets.items()])
            ax.text(0.5, -0.12, targets_text, transform=ax.transAxes, fontsize=8,
                   ha='center', color='gray')

    def _draw_vulns_per_host_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw vulnerabilities per host trend chart for pop-out."""
        df = self._get_chart_data('lifecycle')
        hist_df = self._get_chart_data('historical')

        normalized_metrics = calculate_normalized_metrics(hist_df, df)
        norm_trend = normalized_metrics.get('trend', [])

        if not norm_trend or len(norm_trend) < 2:
            ax.text(0.5, 0.5, 'Insufficient historical data\n(need 2+ scans)', ha='center', va='center',
                   color='white', fontsize=12)
            return

        dates = [t['scan_date'] for t in norm_trend]
        vph = [t['vulns_per_host'] for t in norm_trend]

        # Plot with markers
        line, = ax.plot(range(len(dates)), vph, marker='s', color='#17a2b8',
                       linewidth=2, markersize=8 if enlarged else 5)

        # Add data labels
        if show_labels:
            for i, (x, y) in enumerate(zip(range(len(dates)), vph)):
                if not enlarged and len(dates) > 10 and i % 2 != 0:
                    continue
                ax.annotate(f'{y:.1f}', xy=(x, y), xytext=(0, 8), textcoords='offset points',
                           ha='center', va='bottom', fontsize=9 if enlarged else 7, color='white')

        # Format date labels
        if len(dates) > 8:
            step = max(1, len(dates) // 8)
            tick_positions = list(range(0, len(dates), step))
            ax.set_xticks(tick_positions)
            tick_labels = [dates[i][:8] for i in tick_positions]
            ax.set_xticklabels(tick_labels, fontsize=9, rotation=45, ha='right')
        else:
            ax.set_xticks(range(len(dates)))
            ax.set_xticklabels([d[:8] for d in dates], fontsize=9, rotation=45, ha='right')

        ax.set_title('Vulnerabilities per Host Over Time')
        ax.set_ylabel('Vulns per Host')
        ax.set_xlabel('Scan Date')

        # Add trend indicator
        if enlarged and len(vph) >= 2:
            change = vph[-1] - vph[0]
            pct_change = change / vph[0] * 100 if vph[0] > 0 else 0
            color = '#28a745' if change < 0 else '#dc3545'
            symbol = '↓' if change < 0 else '↑'
            ax.text(0.98, 0.98, f'{symbol} {abs(pct_change):.1f}%', transform=ax.transAxes,
                   fontsize=12, va='top', ha='right', color=color, fontweight='bold')

            # Add context
            ax.text(0.02, 0.98, f'Current: {vph[-1]:.1f} vulns/host', transform=ax.transAxes,
                   fontsize=10, va='top', color='#17a2b8')

    # ==================== Timeline Tab Pop-outs ====================

    def _bind_chart_popouts_timeline(self):
        """Bind double-click pop-out for Timeline tab charts."""
        if not hasattr(self, 'timeline_canvas'):
            return

        def get_click_quadrant(event):
            widget = event.widget
            w, h = widget.winfo_width(), widget.winfo_height()
            x, y = event.x, event.y
            col = 0 if x < w / 2 else 1
            row = 0 if y < h / 2 else 1
            return row * 2 + col

        def on_double_click(event):
            quadrant = get_click_quadrant(event)
            chart_info = [
                ('Total Findings Over Time', self._draw_total_findings_popout),
                ('Findings by Severity Over Time', self._draw_severity_timeline_popout),
                ('New vs Resolved Findings', self._draw_new_vs_resolved_popout),
                ('Cumulative Risk Exposure', self._draw_cumulative_risk_popout),
            ]
            title, redraw_func = chart_info[quadrant]
            ChartPopoutModal(self.window, title, redraw_func)

        self.timeline_canvas.get_tk_widget().bind('<Double-Button-1>', on_double_click)

    def _draw_total_findings_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw total findings over time chart for pop-out."""
        hist_df = self._get_chart_data('historical')

        if hist_df.empty or 'scan_date' not in hist_df.columns:
            ax.text(0.5, 0.5, 'No historical data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        # Group by scan date
        scan_counts = hist_df.groupby('scan_date').size().reset_index(name='count')
        scan_counts = scan_counts.sort_values('scan_date')

        if len(scan_counts) < 2:
            ax.text(0.5, 0.5, 'Need 2+ scans for timeline', ha='center', va='center',
                   color='white', fontsize=12)
            return

        dates = scan_counts['scan_date']
        counts = scan_counts['count']

        # Plot
        ax.plot(range(len(dates)), counts, marker='o', color='#007bff',
               linewidth=2, markersize=8 if enlarged else 5)
        ax.fill_between(range(len(dates)), counts, alpha=0.3, color='#007bff')

        if show_labels:
            for i, (x, y) in enumerate(zip(range(len(dates)), counts)):
                if not enlarged and len(dates) > 8 and i % 2 != 0:
                    continue
                ax.annotate(f'{int(y)}', xy=(x, y), xytext=(0, 8), textcoords='offset points',
                           ha='center', va='bottom', fontsize=9, color='white')

        # Format x-axis
        if len(dates) > 8:
            step = max(1, len(dates) // 8)
            tick_positions = list(range(0, len(dates), step))
            ax.set_xticks(tick_positions)
            tick_labels = [str(dates.iloc[i])[:10] for i in tick_positions]
            ax.set_xticklabels(tick_labels, fontsize=9, rotation=45, ha='right')
        else:
            ax.set_xticks(range(len(dates)))
            ax.set_xticklabels([str(d)[:10] for d in dates], fontsize=9, rotation=45, ha='right')

        ax.set_title('Total Findings Over Time')
        ax.set_ylabel('Finding Count')
        ax.set_xlabel('Scan Date')

        if enlarged:
            change = counts.iloc[-1] - counts.iloc[0]
            pct = change / counts.iloc[0] * 100 if counts.iloc[0] > 0 else 0
            color = '#28a745' if change < 0 else '#dc3545'
            symbol = '↓' if change < 0 else '↑'
            ax.text(0.98, 0.98, f'{symbol} {abs(pct):.1f}%', transform=ax.transAxes,
                   fontsize=12, va='top', ha='right', color=color, fontweight='bold')

    def _draw_severity_timeline_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw findings by severity over time for pop-out."""
        hist_df = self._get_chart_data('historical')

        if hist_df.empty or 'scan_date' not in hist_df.columns or 'severity' not in hist_df.columns:
            ax.text(0.5, 0.5, 'No historical data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        # Group by scan date and severity
        pivot = hist_df.groupby(['scan_date', 'severity']).size().unstack(fill_value=0)

        if len(pivot) < 2:
            ax.text(0.5, 0.5, 'Need 2+ scans for timeline', ha='center', va='center',
                   color='white', fontsize=12)
            return

        dates = pivot.index
        severity_colors = {'Critical': '#dc3545', 'High': '#fd7e14', 'Medium': '#ffc107', 'Low': '#007bff', 'Info': '#6c757d'}

        for sev in ['Critical', 'High', 'Medium', 'Low']:
            if sev in pivot.columns:
                values = pivot[sev].values
                ax.plot(range(len(dates)), values, marker='o', label=sev,
                       color=severity_colors.get(sev, '#6c757d'),
                       linewidth=2, markersize=6 if enlarged else 4)

        ax.legend(loc='upper right', fontsize=9)

        # Format x-axis
        if len(dates) > 8:
            step = max(1, len(dates) // 8)
            tick_positions = list(range(0, len(dates), step))
            ax.set_xticks(tick_positions)
            tick_labels = [str(dates[i])[:10] for i in tick_positions]
            ax.set_xticklabels(tick_labels, fontsize=9, rotation=45, ha='right')
        else:
            ax.set_xticks(range(len(dates)))
            ax.set_xticklabels([str(d)[:10] for d in dates], fontsize=9, rotation=45, ha='right')

        ax.set_title('Findings by Severity Over Time')
        ax.set_ylabel('Finding Count')
        ax.set_xlabel('Scan Date')

    def _draw_new_vs_resolved_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw new vs resolved findings for pop-out."""
        df = self._get_chart_data('lifecycle')

        if df.empty or 'first_seen' not in df.columns:
            ax.text(0.5, 0.5, 'No lifecycle data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        # Count new findings per first_seen date
        new_counts = df.groupby('first_seen').size().reset_index(name='new')
        new_counts = new_counts.sort_values('first_seen')

        # Count resolved (last_seen != first_seen and status == 'resolved')
        resolved_df = df[df['status'] == 'resolved'].copy() if 'status' in df.columns else pd.DataFrame()
        if not resolved_df.empty and 'last_seen' in resolved_df.columns:
            resolved_counts = resolved_df.groupby('last_seen').size().reset_index(name='resolved')
        else:
            resolved_counts = pd.DataFrame({'last_seen': [], 'resolved': []})

        if len(new_counts) < 2:
            ax.text(0.5, 0.5, 'Need more data for timeline', ha='center', va='center',
                   color='white', fontsize=12)
            return

        dates = new_counts['first_seen']
        new_vals = new_counts['new'].values

        x = range(len(dates))
        width = 0.35

        bars1 = ax.bar([i - width/2 for i in x], new_vals, width, label='New', color='#dc3545')

        # Try to align resolved with dates
        if not resolved_counts.empty:
            resolved_dict = dict(zip(resolved_counts['last_seen'], resolved_counts['resolved']))
            resolved_vals = [resolved_dict.get(d, 0) for d in dates]
            bars2 = ax.bar([i + width/2 for i in x], resolved_vals, width, label='Resolved', color='#28a745')

        ax.legend(loc='upper right', fontsize=9)

        # Format x-axis
        if len(dates) > 8:
            step = max(1, len(dates) // 8)
            tick_positions = list(range(0, len(dates), step))
            ax.set_xticks(tick_positions)
            tick_labels = [str(dates.iloc[i])[:10] for i in tick_positions]
            ax.set_xticklabels(tick_labels, fontsize=9, rotation=45, ha='right')
        else:
            ax.set_xticks(x)
            ax.set_xticklabels([str(d)[:10] for d in dates], fontsize=9, rotation=45, ha='right')

        ax.set_title('New vs Resolved Findings')
        ax.set_ylabel('Count')
        ax.set_xlabel('Date')

    def _draw_cumulative_risk_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw cumulative risk exposure for pop-out."""
        hist_df = self._get_chart_data('historical')

        if hist_df.empty or 'scan_date' not in hist_df.columns or 'severity_value' not in hist_df.columns:
            ax.text(0.5, 0.5, 'No historical data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        # Calculate cumulative risk by date
        risk_by_date = hist_df.groupby('scan_date')['severity_value'].sum().reset_index()
        risk_by_date = risk_by_date.sort_values('scan_date')

        if len(risk_by_date) < 2:
            ax.text(0.5, 0.5, 'Need 2+ scans for timeline', ha='center', va='center',
                   color='white', fontsize=12)
            return

        dates = risk_by_date['scan_date']
        risk_scores = risk_by_date['severity_value']

        # Plot with gradient fill
        ax.fill_between(range(len(dates)), risk_scores, alpha=0.5, color='#dc3545')
        ax.plot(range(len(dates)), risk_scores, color='#dc3545', linewidth=2,
               marker='o', markersize=6 if enlarged else 4)

        if show_labels:
            for i, (x, y) in enumerate(zip(range(len(dates)), risk_scores)):
                if not enlarged and len(dates) > 6 and i % 2 != 0:
                    continue
                ax.annotate(f'{int(y)}', xy=(x, y), xytext=(0, 8), textcoords='offset points',
                           ha='center', va='bottom', fontsize=9, color='white')

        # Format x-axis
        if len(dates) > 8:
            step = max(1, len(dates) // 8)
            tick_positions = list(range(0, len(dates), step))
            ax.set_xticks(tick_positions)
            tick_labels = [str(dates.iloc[i])[:10] for i in tick_positions]
            ax.set_xticklabels(tick_labels, fontsize=9, rotation=45, ha='right')
        else:
            ax.set_xticks(range(len(dates)))
            ax.set_xticklabels([str(d)[:10] for d in dates], fontsize=9, rotation=45, ha='right')

        ax.set_title('Cumulative Risk Exposure')
        ax.set_ylabel('Total Risk Score')
        ax.set_xlabel('Scan Date')

        if enlarged:
            peak = risk_scores.max()
            current = risk_scores.iloc[-1]
            ax.text(0.02, 0.98, f'Current: {int(current)} | Peak: {int(peak)}',
                   transform=ax.transAxes, fontsize=10, va='top', color='#dc3545')

    # ==================== OPDIR Tab Pop-outs ====================

    def _bind_chart_popouts_opdir(self):
        """Bind double-click pop-out for OPDIR tab charts."""
        if not hasattr(self, 'opdir_canvas'):
            return

        def get_click_quadrant(event):
            widget = event.widget
            w, h = widget.winfo_width(), widget.winfo_height()
            x, y = event.x, event.y
            col = 0 if x < w / 2 else 1
            row = 0 if y < h / 2 else 1
            return row * 2 + col

        def on_double_click(event):
            quadrant = get_click_quadrant(event)
            chart_info = [
                ('OPDIR Mapping Coverage', self._draw_opdir_coverage_popout),
                ('OPDIR Status Distribution', self._draw_opdir_status_popout),
                ('Finding Age (OPDIR Mapped)', self._draw_opdir_age_popout),
                ('Compliance by OPDIR Year', self._draw_opdir_year_popout),
            ]
            title, redraw_func = chart_info[quadrant]
            ChartPopoutModal(self.window, title, redraw_func)

        self.opdir_canvas.get_tk_widget().bind('<Double-Button-1>', on_double_click)

    def _draw_opdir_coverage_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw OPDIR coverage pie chart for pop-out."""
        df = self._get_chart_data('lifecycle')

        if df.empty or 'opdir_number' not in df.columns:
            ax.text(0.5, 0.5, 'No OPDIR data available\n(Load OPDIR mapping first)', ha='center', va='center',
                   color='white', fontsize=12)
            return

        mapped = df['opdir_number'].notna() & (df['opdir_number'] != '')
        mapped_count = mapped.sum()
        unmapped_count = (~mapped).sum()
        total = len(df)

        if total == 0:
            ax.text(0.5, 0.5, 'No data', ha='center', va='center', color='white', fontsize=12)
            return

        # Enhanced pie chart
        sizes = [mapped_count, unmapped_count]
        labels = [f'Mapped\n({mapped_count})', f'Unmapped\n({unmapped_count})']
        colors = ['#28a745', '#6c757d']
        explode = (0.05, 0) if mapped_count > unmapped_count else (0, 0.05)

        wedges, texts, autotexts = ax.pie(sizes, labels=labels, colors=colors,
                                          autopct='%1.1f%%', explode=explode,
                                          textprops={'color': 'white', 'fontsize': 10})

        ax.set_title('OPDIR Mapping Coverage')

        if enlarged:
            ax.text(0.5, -0.1, f'Total Findings: {total}', transform=ax.transAxes,
                   ha='center', fontsize=10, color='gray')

    def _draw_opdir_status_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw OPDIR status distribution for pop-out."""
        df = self._get_chart_data('lifecycle')

        if df.empty or 'opdir_status' not in df.columns:
            ax.text(0.5, 0.5, 'No OPDIR status data\n(Load OPDIR mapping first)', ha='center', va='center',
                   color='white', fontsize=12)
            return

        status_counts = df['opdir_status'].value_counts()

        if len(status_counts) == 0:
            ax.text(0.5, 0.5, 'No status data', ha='center', va='center', color='white', fontsize=12)
            return

        colors = {'Overdue': '#dc3545', 'Due Soon': '#ffc107', 'On Track': '#28a745', 'No OPDIR': '#6c757d'}
        bar_colors = [colors.get(s, '#6c757d') for s in status_counts.index]

        bars = ax.bar(range(len(status_counts)), status_counts.values, color=bar_colors)
        ax.set_xticks(range(len(status_counts)))
        ax.set_xticklabels(status_counts.index, fontsize=10)

        if show_labels:
            for bar, val in zip(bars, status_counts.values):
                ax.annotate(f'{int(val)}', xy=(bar.get_x() + bar.get_width()/2, val),
                           xytext=(0, 3), textcoords='offset points',
                           ha='center', va='bottom', fontsize=10, color='white')

        ax.set_title('OPDIR Status Distribution')
        ax.set_ylabel('Count')

        if enlarged:
            total = status_counts.sum()
            overdue = status_counts.get('Overdue', 0)
            pct = overdue / total * 100 if total > 0 else 0
            ax.text(0.02, 0.98, f'Overdue: {pct:.1f}%', transform=ax.transAxes,
                   fontsize=10, va='top', color='#dc3545' if pct > 20 else '#28a745')

    def _draw_opdir_age_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw finding age for OPDIR mapped items for pop-out."""
        df = self._get_chart_data('lifecycle')

        if df.empty or 'days_open' not in df.columns or 'opdir_number' not in df.columns:
            ax.text(0.5, 0.5, 'No data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        mapped_df = df[df['opdir_number'].notna() & (df['opdir_number'] != '')]

        if mapped_df.empty:
            ax.text(0.5, 0.5, 'No OPDIR-mapped findings', ha='center', va='center',
                   color='white', fontsize=12)
            return

        days = mapped_df['days_open'].values

        # Histogram with age buckets
        bins = [0, 7, 30, 60, 90, 180, 365, max(days.max() + 1, 366)]
        bin_labels = ['0-7', '8-30', '31-60', '61-90', '91-180', '181-365', '365+']
        hist, bin_edges = np.histogram(days, bins=bins)

        colors = ['#28a745', '#28a745', '#ffc107', '#ffc107', '#fd7e14', '#dc3545', '#dc3545']
        bars = ax.bar(range(len(hist)), hist, color=colors[:len(hist)])
        ax.set_xticks(range(len(hist)))
        ax.set_xticklabels(bin_labels[:len(hist)], fontsize=9)

        if show_labels:
            for bar, val in zip(bars, hist):
                if val > 0:
                    ax.annotate(f'{int(val)}', xy=(bar.get_x() + bar.get_width()/2, val),
                               xytext=(0, 3), textcoords='offset points',
                               ha='center', va='bottom', fontsize=9, color='white')

        ax.set_title('Finding Age Distribution (OPDIR Mapped)')
        ax.set_ylabel('Count')
        ax.set_xlabel('Days Open')

        if enlarged:
            days_numeric = pd.to_numeric(days, errors='coerce')
            avg_age = days_numeric.mean()
            median_age = np.median(days_numeric.dropna())
            ax.text(0.98, 0.98, f'Avg: {avg_age:.0f}d | Median: {median_age:.0f}d',
                   transform=ax.transAxes, fontsize=10, va='top', ha='right', color='#17a2b8')

    def _draw_opdir_year_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw compliance by OPDIR year for pop-out."""
        df = self._get_chart_data('lifecycle')

        if df.empty or 'opdir_year' not in df.columns:
            ax.text(0.5, 0.5, 'No OPDIR year data\n(Load OPDIR mapping with year info)',
                   ha='center', va='center', color='white', fontsize=12)
            return

        year_df = df[df['opdir_year'].notna()]
        if year_df.empty:
            ax.text(0.5, 0.5, 'No year data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        # Group by year and status
        if 'opdir_status' in year_df.columns:
            year_status = year_df.groupby(['opdir_year', 'opdir_status']).size().unstack(fill_value=0)
        else:
            year_status = year_df.groupby('opdir_year').size().reset_index(name='count')
            ax.bar(range(len(year_status)), year_status['count'].values, color='#007bff')
            ax.set_xticks(range(len(year_status)))
            ax.set_xticklabels([int(y) for y in year_status['opdir_year']], fontsize=10)
            ax.set_title('Findings by OPDIR Year')
            ax.set_ylabel('Count')
            return

        years = year_status.index
        x = range(len(years))

        # Stacked bar chart
        bottom = np.zeros(len(years))
        colors = {'Overdue': '#dc3545', 'Due Soon': '#ffc107', 'On Track': '#28a745'}

        for status in ['On Track', 'Due Soon', 'Overdue']:
            if status in year_status.columns:
                values = year_status[status].values
                ax.bar(x, values, bottom=bottom, label=status, color=colors.get(status, '#6c757d'))
                bottom += values

        ax.set_xticks(x)
        ax.set_xticklabels([int(y) for y in years], fontsize=10)
        ax.legend(loc='upper right', fontsize=9)
        ax.set_title('Compliance by OPDIR Year')
        ax.set_ylabel('Count')
        ax.set_xlabel('OPDIR Year')

    # ==================== SLA Tab Pop-outs ====================

    def _bind_chart_popouts_sla(self):
        """Bind double-click pop-out for SLA tab charts."""
        if not hasattr(self, 'sla_canvas'):
            return

        def get_click_quadrant(event):
            widget = event.widget
            w, h = widget.winfo_width(), widget.winfo_height()
            x, y = event.x, event.y
            col = 0 if x < w / 2 else 1
            row = 0 if y < h / 2 else 1
            return row * 2 + col

        def on_double_click(event):
            quadrant = get_click_quadrant(event)
            chart_info = [
                ('SLA Compliance Status', self._draw_sla_compliance_popout),
                ('Overdue Findings by Severity', self._draw_sla_overdue_popout),
                ('Approaching SLA Deadline', self._draw_sla_approaching_popout),
                ('Days Until/Past SLA', self._draw_sla_days_popout),
            ]
            title, redraw_func = chart_info[quadrant]
            ChartPopoutModal(self.window, title, redraw_func)

        self.sla_canvas.get_tk_widget().bind('<Double-Button-1>', on_double_click)

    def _draw_sla_compliance_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw SLA compliance status pie chart for pop-out."""
        df = self._get_chart_data('lifecycle')

        if df.empty or 'sla_status' not in df.columns:
            ax.text(0.5, 0.5, 'No SLA data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        status_counts = df['sla_status'].value_counts()

        if len(status_counts) == 0:
            ax.text(0.5, 0.5, 'No SLA status data', ha='center', va='center',
                   color='white', fontsize=12)
            return

        colors = {'Overdue': '#dc3545', 'At Risk': '#ffc107', 'On Track': '#28a745'}
        pie_colors = [colors.get(s, '#6c757d') for s in status_counts.index]

        labels = [f'{s}\n({c})' for s, c in zip(status_counts.index, status_counts.values)]
        wedges, texts, autotexts = ax.pie(status_counts.values, labels=labels, colors=pie_colors,
                                          autopct='%1.1f%%',
                                          textprops={'color': 'white', 'fontsize': 10})

        ax.set_title('SLA Compliance Status')

        if enlarged:
            total = status_counts.sum()
            compliant = status_counts.get('On Track', 0)
            pct = compliant / total * 100 if total > 0 else 0
            ax.text(0.5, -0.1, f'Compliance Rate: {pct:.1f}%', transform=ax.transAxes,
                   ha='center', fontsize=11, color='#28a745' if pct >= 80 else '#dc3545')

    def _draw_sla_overdue_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw overdue findings by severity for pop-out."""
        df = self._get_chart_data('lifecycle')

        if df.empty or 'sla_status' not in df.columns or 'severity' not in df.columns:
            ax.text(0.5, 0.5, 'No SLA data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        overdue_df = df[df['sla_status'] == 'Overdue']

        if overdue_df.empty:
            ax.text(0.5, 0.5, 'No overdue findings', ha='center', va='center',
                   color='#28a745', fontsize=14)
            ax.set_title('Overdue Findings by Severity')
            return

        sev_counts = overdue_df['severity'].value_counts()
        severity_order = ['Critical', 'High', 'Medium', 'Low']
        sev_counts = sev_counts.reindex([s for s in severity_order if s in sev_counts.index])

        severity_colors = {'Critical': '#dc3545', 'High': '#fd7e14', 'Medium': '#ffc107', 'Low': '#007bff'}
        colors = [severity_colors.get(s, '#6c757d') for s in sev_counts.index]

        bars = ax.bar(range(len(sev_counts)), sev_counts.values, color=colors)
        ax.set_xticks(range(len(sev_counts)))
        ax.set_xticklabels(sev_counts.index, fontsize=10)

        if show_labels:
            for bar, val in zip(bars, sev_counts.values):
                ax.annotate(f'{int(val)}', xy=(bar.get_x() + bar.get_width()/2, val),
                           xytext=(0, 3), textcoords='offset points',
                           ha='center', va='bottom', fontsize=10, color='white')

        ax.set_title('Overdue Findings by Severity')
        ax.set_ylabel('Count')

        if enlarged:
            total_overdue = len(overdue_df)
            crit_high = sev_counts.get('Critical', 0) + sev_counts.get('High', 0)
            ax.text(0.02, 0.98, f'Total Overdue: {total_overdue} | Critical+High: {crit_high}',
                   transform=ax.transAxes, fontsize=10, va='top', color='#dc3545')

    def _draw_sla_approaching_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw findings approaching SLA deadline for pop-out."""
        df = self._get_chart_data('lifecycle')

        if df.empty or 'days_until_sla' not in df.columns:
            ax.text(0.5, 0.5, 'No SLA timeline data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        # Get findings due within 30 days
        approaching_df = df[(df['days_until_sla'] >= 0) & (df['days_until_sla'] <= 30)]

        if approaching_df.empty:
            ax.text(0.5, 0.5, 'No findings approaching deadline\n(within 30 days)',
                   ha='center', va='center', color='#28a745', fontsize=12)
            ax.set_title('Approaching SLA Deadline')
            return

        # Bucket by days
        bins = [0, 7, 14, 21, 30]
        labels = ['0-7 days', '8-14 days', '15-21 days', '22-30 days']
        approaching_df = approaching_df.copy()
        approaching_df['bucket'] = pd.cut(approaching_df['days_until_sla'], bins=bins, labels=labels, include_lowest=True)
        bucket_counts = approaching_df['bucket'].value_counts().reindex(labels)

        colors = ['#dc3545', '#fd7e14', '#ffc107', '#28a745']
        bars = ax.bar(range(len(bucket_counts)), bucket_counts.values, color=colors)
        ax.set_xticks(range(len(bucket_counts)))
        ax.set_xticklabels(labels, fontsize=9)

        if show_labels:
            for bar, val in zip(bars, bucket_counts.values):
                if pd.notna(val) and val > 0:
                    ax.annotate(f'{int(val)}', xy=(bar.get_x() + bar.get_width()/2, val),
                               xytext=(0, 3), textcoords='offset points',
                               ha='center', va='bottom', fontsize=10, color='white')

        ax.set_title('Findings Approaching SLA Deadline (Next 30 Days)')
        ax.set_ylabel('Count')
        ax.set_xlabel('Days Until SLA')

        if enlarged:
            urgent = bucket_counts.iloc[0] if pd.notna(bucket_counts.iloc[0]) else 0
            ax.text(0.02, 0.98, f'Urgent (0-7 days): {int(urgent)}',
                   transform=ax.transAxes, fontsize=10, va='top', color='#dc3545')

    def _draw_sla_days_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw days until/past SLA scatter plot for pop-out."""
        df = self._get_chart_data('lifecycle')

        if df.empty or 'days_until_sla' not in df.columns or 'severity' not in df.columns:
            ax.text(0.5, 0.5, 'No SLA data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        # Filter to reasonable range
        plot_df = df[df['days_until_sla'].notna()].copy()
        if plot_df.empty:
            ax.text(0.5, 0.5, 'No SLA timeline data', ha='center', va='center',
                   color='white', fontsize=12)
            return

        # Limit for performance
        if len(plot_df) > 500:
            plot_df = plot_df.sample(500, random_state=42)

        severity_colors = {'Critical': '#dc3545', 'High': '#fd7e14', 'Medium': '#ffc107', 'Low': '#007bff'}

        for sev in ['Critical', 'High', 'Medium', 'Low']:
            sev_df = plot_df[plot_df['severity'] == sev]
            if not sev_df.empty:
                ax.scatter(range(len(sev_df)), sev_df['days_until_sla'].values,
                          c=severity_colors.get(sev, '#6c757d'), label=sev,
                          alpha=0.6, s=30 if enlarged else 15)

        # Add zero line (SLA deadline)
        ax.axhline(y=0, color='white', linestyle='--', linewidth=1, alpha=0.7)
        ax.text(ax.get_xlim()[1] * 0.98, 2, 'SLA Deadline', ha='right', va='bottom',
               fontsize=8, color='white', alpha=0.7)

        ax.legend(loc='upper right', fontsize=9)
        ax.set_title('Days Until/Past SLA by Finding')
        ax.set_ylabel('Days (negative = overdue)')
        ax.set_xlabel('Finding Index')

        if enlarged:
            overdue = (plot_df['days_until_sla'] < 0).sum()
            total = len(plot_df)
            pct = overdue / total * 100 if total > 0 else 0
            ax.text(0.02, 0.98, f'Overdue: {overdue}/{total} ({pct:.1f}%)',
                   transform=ax.transAxes, fontsize=10, va='top',
                   color='#dc3545' if pct > 20 else '#28a745')

    # ==================== Efficiency Tab Pop-outs ====================

    def _bind_chart_popouts_efficiency(self):
        """Bind double-click pop-out for Efficiency tab charts."""
        if not hasattr(self, 'efficiency_canvas'):
            return

        def get_click_quadrant(event):
            widget = event.widget
            w, h = widget.winfo_width(), widget.winfo_height()
            x, y = event.x, event.y
            col = 0 if x < w / 2 else 1
            row = 0 if y < h / 2 else 1
            return row * 2 + col

        def on_double_click(event):
            quadrant = get_click_quadrant(event)
            chart_info = [
                ('Scan Coverage Consistency', self._draw_scan_coverage_popout),
                ('Reappearance Analysis', self._draw_reappearance_popout),
                ('Host Vulnerability Burden', self._draw_host_burden_popout),
                ('Resolution Velocity', self._draw_resolution_velocity_popout),
            ]
            title, redraw_func = chart_info[quadrant]
            ChartPopoutModal(self.window, title, redraw_func)

        self.efficiency_canvas.get_tk_widget().bind('<Double-Button-1>', on_double_click)

    def _draw_scan_coverage_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw scan coverage consistency histogram for pop-out."""
        host_df = self.filtered_host_df if not self.filtered_host_df.empty else self.host_presence_df

        if host_df.empty or 'presence_percentage' not in host_df.columns:
            ax.text(0.5, 0.5, 'No host presence data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        presence = host_df['presence_percentage'].values
        bins = 20 if enlarged else 10
        n, bin_edges, patches = ax.hist(presence, bins=bins, color='#17a2b8', edgecolor='white', alpha=0.8)

        # Color code by coverage
        for i, patch in enumerate(patches):
            bin_center = (bin_edges[i] + bin_edges[i+1]) / 2
            if bin_center >= 80:
                patch.set_facecolor('#28a745')
            elif bin_center >= 50:
                patch.set_facecolor('#ffc107')
            else:
                patch.set_facecolor('#dc3545')

        ax.set_title('Scan Coverage Consistency')
        ax.set_xlabel('Presence Percentage')
        ax.set_ylabel('Host Count')

        if enlarged:
            presence_numeric = pd.to_numeric(pd.Series(presence), errors='coerce')
            avg = presence_numeric.mean()
            median = np.median(presence_numeric.dropna()) if len(presence_numeric.dropna()) > 0 else 0
            ax.axvline(x=avg, color='white', linestyle='--', linewidth=1, alpha=0.7)
            ax.text(0.02, 0.98, f'Avg: {avg:.1f}% | Median: {median:.1f}%',
                   transform=ax.transAxes, fontsize=10, va='top', color='#17a2b8')

    def _draw_reappearance_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw reappearance analysis for pop-out."""
        df = self._get_chart_data('lifecycle')

        if df.empty or 'appearance_count' not in df.columns:
            ax.text(0.5, 0.5, 'No reappearance data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        # Group by appearance count
        reappear_counts = df['appearance_count'].value_counts().sort_index()

        if len(reappear_counts) == 0:
            ax.text(0.5, 0.5, 'No reappearance data', ha='center', va='center', color='white', fontsize=12)
            return

        # Limit to first 10 for readability
        if len(reappear_counts) > 10:
            reappear_counts = reappear_counts.head(10)

        bars = ax.bar(range(len(reappear_counts)), reappear_counts.values, color='#fd7e14')
        ax.set_xticks(range(len(reappear_counts)))
        ax.set_xticklabels([int(x) for x in reappear_counts.index], fontsize=9)

        if show_labels:
            for bar, val in zip(bars, reappear_counts.values):
                ax.annotate(f'{int(val)}', xy=(bar.get_x() + bar.get_width()/2, val),
                           xytext=(0, 3), textcoords='offset points',
                           ha='center', va='bottom', fontsize=8, color='white')

        ax.set_title('Finding Reappearance Analysis')
        ax.set_xlabel('Times Appeared in Scans')
        ax.set_ylabel('Finding Count')

        if enlarged:
            total = reappear_counts.sum()
            recurring = reappear_counts[reappear_counts.index > 1].sum() if len(reappear_counts) > 1 else 0
            pct = recurring / total * 100 if total > 0 else 0
            ax.text(0.98, 0.98, f'Recurring: {pct:.1f}%', transform=ax.transAxes,
                   fontsize=10, va='top', ha='right', color='#fd7e14')

    def _draw_host_burden_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw host vulnerability burden for pop-out."""
        df = self._get_chart_data('lifecycle')

        if df.empty or 'hostname' not in df.columns:
            ax.text(0.5, 0.5, 'No host data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        # Count vulnerabilities per host
        vuln_per_host = df.groupby('hostname').size()

        if len(vuln_per_host) == 0:
            ax.text(0.5, 0.5, 'No host data', ha='center', va='center', color='white', fontsize=12)
            return

        # Histogram of vulnerability count per host
        bins = 20 if enlarged else 10
        n, bin_edges, patches = ax.hist(vuln_per_host.values, bins=bins, color='#6c757d', edgecolor='white')

        ax.set_title('Host Vulnerability Burden Distribution')
        ax.set_xlabel('Vulnerabilities per Host')
        ax.set_ylabel('Host Count')

        if enlarged:
            vuln_numeric = pd.to_numeric(vuln_per_host, errors='coerce')
            avg = vuln_numeric.mean()
            max_vulns = vuln_numeric.max()
            ax.text(0.02, 0.98, f'Avg: {avg:.1f} vulns/host | Max: {max_vulns}',
                   transform=ax.transAxes, fontsize=10, va='top', color='#17a2b8')

    def _draw_resolution_velocity_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw resolution velocity for pop-out."""
        df = self._get_chart_data('lifecycle')

        if df.empty or 'status' not in df.columns or 'days_to_remediation' not in df.columns:
            ax.text(0.5, 0.5, 'No resolution data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        resolved = df[df['status'] == 'resolved']
        if resolved.empty or resolved['days_to_remediation'].isna().all():
            ax.text(0.5, 0.5, 'No resolved findings with\nremediation time data',
                   ha='center', va='center', color='white', fontsize=12)
            return

        days = resolved['days_to_remediation'].dropna().values

        # Histogram
        bins = [0, 7, 14, 30, 60, 90, max(days.max() + 1, 91)]
        bin_labels = ['0-7', '8-14', '15-30', '31-60', '61-90', '90+']
        hist, _ = np.histogram(days, bins=bins)

        colors = ['#28a745', '#28a745', '#ffc107', '#ffc107', '#fd7e14', '#dc3545']
        bars = ax.bar(range(len(hist)), hist, color=colors[:len(hist)])
        ax.set_xticks(range(len(hist)))
        ax.set_xticklabels(bin_labels[:len(hist)], fontsize=9)

        if show_labels:
            for bar, val in zip(bars, hist):
                if val > 0:
                    ax.annotate(f'{int(val)}', xy=(bar.get_x() + bar.get_width()/2, val),
                               xytext=(0, 3), textcoords='offset points',
                               ha='center', va='bottom', fontsize=8, color='white')

        ax.set_title('Resolution Velocity (Days to Remediate)')
        ax.set_xlabel('Days')
        ax.set_ylabel('Finding Count')

        if enlarged:
            days_numeric = pd.to_numeric(pd.Series(days), errors='coerce').dropna()
            avg = days_numeric.mean() if len(days_numeric) > 0 else 0
            median = np.median(days_numeric) if len(days_numeric) > 0 else 0
            ax.text(0.98, 0.98, f'Avg: {avg:.0f}d | Median: {median:.0f}d',
                   transform=ax.transAxes, fontsize=10, va='top', ha='right', color='#28a745')

    # ==================== Network Tab Pop-outs ====================

    def _bind_chart_popouts_network(self):
        """Bind double-click pop-out for Network tab charts."""
        if not hasattr(self, 'network_canvas'):
            return

        def get_click_quadrant(event):
            widget = event.widget
            w, h = widget.winfo_width(), widget.winfo_height()
            x, y = event.x, event.y
            col = 0 if x < w / 2 else 1
            row = 0 if y < h / 2 else 1
            return row * 2 + col

        def on_double_click(event):
            quadrant = get_click_quadrant(event)
            chart_info = [
                ('Top Subnets by Vulnerability', self._draw_top_subnets_popout),
                ('Subnet Risk Scores', self._draw_subnet_risk_popout),
                ('Host Criticality Distribution', self._draw_host_criticality_popout),
                ('Environment Distribution', self._draw_environment_breakdown_popout),
            ]
            title, redraw_func = chart_info[quadrant]
            ChartPopoutModal(self.window, title, redraw_func)

        self.network_canvas.get_tk_widget().bind('<Double-Button-1>', on_double_click)

    def _draw_top_subnets_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw top subnets by vulnerability count for pop-out."""
        df = self._get_chart_data('lifecycle')

        if df.empty or 'ip' not in df.columns:
            ax.text(0.5, 0.5, 'No IP data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        # Extract subnet from IP
        def get_subnet(ip):
            try:
                parts = str(ip).split('.')
                if len(parts) >= 3:
                    return '.'.join(parts[:3]) + '.0/24'
            except:
                pass
            return 'Unknown'

        df_copy = df.copy()
        df_copy['subnet'] = df_copy['ip'].apply(get_subnet)
        subnet_counts = df_copy['subnet'].value_counts().head(15 if enlarged else 10)

        if len(subnet_counts) == 0:
            ax.text(0.5, 0.5, 'No subnet data', ha='center', va='center', color='white', fontsize=12)
            return

        bars = ax.barh(range(len(subnet_counts)), subnet_counts.values, color='#007bff')
        ax.set_yticks(range(len(subnet_counts)))
        ax.set_yticklabels(subnet_counts.index, fontsize=8)

        if show_labels:
            for bar, val in zip(bars, subnet_counts.values):
                ax.annotate(f'{int(val)}', xy=(val, bar.get_y() + bar.get_height()/2),
                           xytext=(3, 0), textcoords='offset points',
                           ha='left', va='center', fontsize=8, color='white')

        ax.set_title('Top Subnets by Vulnerability Count')
        ax.set_xlabel('Vulnerability Count')
        ax.invert_yaxis()

    def _draw_subnet_risk_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw subnet risk scores for pop-out."""
        df = self._get_chart_data('lifecycle')

        if df.empty or 'ip' not in df.columns or 'severity_value' not in df.columns:
            ax.text(0.5, 0.5, 'No IP/severity data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        def get_subnet(ip):
            try:
                parts = str(ip).split('.')
                if len(parts) >= 3:
                    return '.'.join(parts[:3]) + '.0/24'
            except:
                pass
            return 'Unknown'

        df_copy = df.copy()
        df_copy['subnet'] = df_copy['ip'].apply(get_subnet)
        subnet_risk = df_copy.groupby('subnet')['severity_value'].sum().nlargest(10)

        if len(subnet_risk) == 0:
            ax.text(0.5, 0.5, 'No risk data', ha='center', va='center', color='white', fontsize=12)
            return

        # Color gradient by risk
        max_risk = subnet_risk.max()
        colors = ['#dc3545' if r > max_risk * 0.7 else '#ffc107' if r > max_risk * 0.4 else '#28a745'
                 for r in subnet_risk.values]

        bars = ax.barh(range(len(subnet_risk)), subnet_risk.values, color=colors)
        ax.set_yticks(range(len(subnet_risk)))
        ax.set_yticklabels(subnet_risk.index, fontsize=8)

        if show_labels:
            for bar, val in zip(bars, subnet_risk.values):
                ax.annotate(f'{int(val)}', xy=(val, bar.get_y() + bar.get_height()/2),
                           xytext=(3, 0), textcoords='offset points',
                           ha='left', va='center', fontsize=8, color='white')

        ax.set_title('Subnet Risk Scores')
        ax.set_xlabel('Total Risk Score')
        ax.invert_yaxis()

    def _draw_host_criticality_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw host criticality distribution for pop-out."""
        df = self._get_chart_data('lifecycle')

        if df.empty or 'hostname' not in df.columns or 'severity_value' not in df.columns:
            ax.text(0.5, 0.5, 'No host severity data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        # Calculate host risk scores
        host_risk = df.groupby('hostname')['severity_value'].sum()

        if len(host_risk) == 0:
            ax.text(0.5, 0.5, 'No host data', ha='center', va='center', color='white', fontsize=12)
            return

        # Histogram of host risk scores
        bins = 20 if enlarged else 10
        n, bin_edges, patches = ax.hist(host_risk.values, bins=bins, color='#6c757d', edgecolor='white')

        ax.set_title('Host Criticality Distribution')
        ax.set_xlabel('Total Risk Score per Host')
        ax.set_ylabel('Host Count')

        if enlarged:
            risk_numeric = pd.to_numeric(host_risk, errors='coerce')
            avg = risk_numeric.mean()
            high_risk = (risk_numeric > risk_numeric.quantile(0.9)).sum()
            ax.text(0.02, 0.98, f'Avg Risk: {avg:.0f} | High Risk Hosts: {high_risk}',
                   transform=ax.transAxes, fontsize=10, va='top', color='#dc3545')

    def _draw_network_segment_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw network segment analysis for pop-out."""
        df = self._get_chart_data('lifecycle')

        if df.empty or 'ip' not in df.columns or 'severity' not in df.columns:
            ax.text(0.5, 0.5, 'No network segment data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        def get_class_b(ip):
            try:
                parts = str(ip).split('.')
                if len(parts) >= 2:
                    return f'{parts[0]}.{parts[1]}.x.x'
            except:
                pass
            return 'Unknown'

        df_copy = df.copy()
        df_copy['segment'] = df_copy['ip'].apply(get_class_b)

        # Group by segment and severity
        segment_sev = df_copy.groupby(['segment', 'severity']).size().unstack(fill_value=0)
        segment_sev = segment_sev.head(10)

        if segment_sev.empty:
            ax.text(0.5, 0.5, 'No segment data', ha='center', va='center', color='white', fontsize=12)
            return

        x = range(len(segment_sev))
        severity_colors = {'Critical': '#dc3545', 'High': '#fd7e14', 'Medium': '#ffc107', 'Low': '#007bff'}

        bottom = np.zeros(len(segment_sev))
        for sev in ['Low', 'Medium', 'High', 'Critical']:
            if sev in segment_sev.columns:
                values = segment_sev[sev].values
                ax.bar(x, values, bottom=bottom, label=sev, color=severity_colors.get(sev, '#6c757d'))
                bottom += values

        ax.set_xticks(x)
        ax.set_xticklabels(segment_sev.index, fontsize=7, rotation=45, ha='right')
        ax.legend(loc='upper right', fontsize=7)
        ax.set_title('Network Segment Analysis')
        ax.set_ylabel('Vulnerability Count')

    def _draw_environment_breakdown_popout(self, fig, ax, enlarged=False, show_labels=True, filter_settings=None):
        """Draw environment breakdown analysis for pop-out."""
        df = self._get_chart_data('lifecycle')

        if df.empty:
            ax.text(0.5, 0.5, 'No data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        # Ensure environment_type column exists
        if 'environment_type' not in df.columns and 'hostname' in df.columns:
            df = df.copy()
            df['environment_type'] = df['hostname'].apply(self._get_environment_type)

        if 'environment_type' not in df.columns:
            ax.text(0.5, 0.5, 'No environment data', ha='center', va='center',
                   color='white', fontsize=12)
            return

        # Count by environment and severity
        env_colors = {'Production': '#28a745', 'PSS': '#007bff', 'Shared': '#ffc107', 'Unknown': '#6c757d'}
        env_order = self.settings_manager.settings.environment_types

        if 'severity_text' in df.columns:
            # Create grouped bar chart by environment and severity
            env_sev = df.groupby(['environment_type', 'severity_text']).size().unstack(fill_value=0)
            env_sev = env_sev.reindex([e for e in env_order if e in env_sev.index])

            if not env_sev.empty:
                x = np.arange(len(env_sev))
                width = 0.15
                severity_order = ['Critical', 'High', 'Medium', 'Low', 'Info']
                severity_colors = {'Critical': '#dc3545', 'High': '#fd7e14', 'Medium': '#ffc107',
                                  'Low': '#28a745', 'Info': '#17a2b8'}

                for i, sev in enumerate(severity_order):
                    if sev in env_sev.columns:
                        offset = (i - len(severity_order)/2) * width
                        bars = ax.bar(x + offset, env_sev[sev], width, label=sev,
                                      color=severity_colors.get(sev, '#6c757d'))
                        if show_labels and enlarged:
                            for bar in bars:
                                height = bar.get_height()
                                if height > 0:
                                    ax.annotate(f'{int(height)}',
                                               xy=(bar.get_x() + bar.get_width()/2, height),
                                               ha='center', va='bottom', fontsize=7, color='white')

                ax.set_xticks(x)
                ax.set_xticklabels(env_sev.index, fontsize=9)
                ax.legend(loc='upper right', fontsize=8)
        else:
            # Simple count by environment
            env_counts = df['environment_type'].value_counts()
            env_counts = env_counts.reindex([e for e in env_order if e in env_counts.index])

            if len(env_counts) > 0:
                colors = [env_colors.get(e, '#6c757d') for e in env_counts.index]
                bars = ax.bar(range(len(env_counts)), env_counts.values, color=colors)
                ax.set_xticks(range(len(env_counts)))
                ax.set_xticklabels(env_counts.index, fontsize=9)
                if show_labels:
                    for bar, val in zip(bars, env_counts.values):
                        ax.annotate(f'{int(val)}', xy=(bar.get_x() + bar.get_width()/2, val),
                                   ha='center', va='bottom', fontsize=9, color='white')

        ax.set_title('Findings by Environment', fontsize=12)
        ax.set_ylabel('Finding Count')

        # Add summary stats
        total = len(df)
        active = len(df[df['status'] == 'Active']) if 'status' in df.columns else total
        ax.text(0.98, 0.98, f'Total: {total} | Active: {active}',
               transform=ax.transAxes, fontsize=9, va='top', ha='right', color='white')

    def _draw_env_severity_matrix_popout(self, fig, ax, enlarged=False, show_labels=True, filter_settings=None):
        """Draw environment vs severity matrix heatmap for pop-out."""
        df = self._get_chart_data('lifecycle')

        if df.empty:
            ax.text(0.5, 0.5, 'No data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        # Ensure environment_type column exists
        if 'environment_type' not in df.columns and 'hostname' in df.columns:
            df = df.copy()
            df['environment_type'] = df['hostname'].apply(self._get_environment_type)

        if 'environment_type' not in df.columns or 'severity_text' not in df.columns:
            ax.text(0.5, 0.5, 'Missing required data', ha='center', va='center',
                   color='white', fontsize=12)
            return

        # Create pivot table
        pivot = df.groupby(['environment_type', 'severity_text']).size().unstack(fill_value=0)

        # Order by environment and severity
        env_order = self.settings_manager.settings.environment_types
        sev_order = ['Critical', 'High', 'Medium', 'Low', 'Info']

        pivot = pivot.reindex([e for e in env_order if e in pivot.index])
        pivot = pivot.reindex(columns=[s for s in sev_order if s in pivot.columns])

        if pivot.empty:
            ax.text(0.5, 0.5, 'No data for matrix', ha='center', va='center',
                   color='white', fontsize=12)
            return

        # Create heatmap
        cmap = plt.cm.YlOrRd
        im = ax.imshow(pivot.values, cmap=cmap, aspect='auto')

        ax.set_xticks(range(len(pivot.columns)))
        ax.set_yticks(range(len(pivot.index)))
        ax.set_xticklabels(pivot.columns, fontsize=9)
        ax.set_yticklabels(pivot.index, fontsize=9)

        # Add text annotations
        if show_labels:
            for i in range(len(pivot.index)):
                for j in range(len(pivot.columns)):
                    val = pivot.iloc[i, j]
                    text_color = 'white' if val > pivot.values.max() * 0.5 else 'black'
                    ax.text(j, i, f'{int(val)}', ha='center', va='center',
                           color=text_color, fontsize=10, fontweight='bold')

        ax.set_title('Environment vs Severity Matrix', fontsize=12)
        fig.colorbar(im, ax=ax, label='Finding Count')

    # ==================== Plugin Tab Pop-outs ====================

    def _bind_chart_popouts_plugin(self):
        """Bind double-click pop-out for Plugin tab charts."""
        if not hasattr(self, 'plugin_canvas'):
            return

        def get_click_quadrant(event):
            widget = event.widget
            w, h = widget.winfo_width(), widget.winfo_height()
            x, y = event.x, event.y
            col = 0 if x < w / 2 else 1
            row = 0 if y < h / 2 else 1
            return row * 2 + col

        def on_double_click(event):
            quadrant = get_click_quadrant(event)
            chart_info = [
                ('Top Most Common Plugins', self._draw_top_plugins_popout),
                ('Plugin Severity Distribution', self._draw_plugin_severity_popout),
                ('Plugins Affecting Most Hosts', self._draw_plugins_by_hosts_popout),
                ('Plugin Average Age', self._draw_plugin_age_popout),
            ]
            title, redraw_func = chart_info[quadrant]
            ChartPopoutModal(self.window, title, redraw_func)

        self.plugin_canvas.get_tk_widget().bind('<Double-Button-1>', on_double_click)

    def _draw_top_plugins_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw top most common plugins for pop-out - Top 10 per environment."""
        df = self._get_chart_data('lifecycle')

        if df.empty or 'plugin_id' not in df.columns or 'hostname' not in df.columns:
            ax.text(0.5, 0.5, 'No plugin data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        env_colors = {'Production': '#28a745', 'PSS': '#007bff', 'Shared': '#ffc107', 'Unknown': '#6c757d'}
        env_types = self.settings_manager.settings.environment_types if hasattr(self, 'settings_manager') else ['Production', 'PSS', 'Shared']
        num_per_env = 10

        # Get plugin names for labels
        plugin_names = {}
        if 'plugin_name' in df.columns:
            plugin_names = df.groupby('plugin_id')['plugin_name'].first().to_dict()

        all_plugins = []
        for env in env_types:
            env_df = df[df['hostname'].apply(lambda h: self._get_environment_type(h) == env)]
            if not env_df.empty:
                plugin_counts = env_df.groupby('plugin_id').size().nlargest(num_per_env)
                for pid, count in plugin_counts.items():
                    all_plugins.append({'plugin_id': pid, 'count': count, 'env': env})

        if not all_plugins:
            ax.text(0.5, 0.5, 'No plugin data', ha='center', va='center', color='white', fontsize=12)
            return

        # Sort by environment then by count descending
        all_plugins.sort(key=lambda x: (env_types.index(x['env']) if x['env'] in env_types else 99, -x['count']))
        counts = [p['count'] for p in all_plugins]
        colors = [env_colors.get(p['env'], '#6c757d') for p in all_plugins]

        # Use plugin name if available, otherwise ID
        labels = [str(plugin_names.get(p['plugin_id'], p['plugin_id']))[:30] for p in all_plugins]

        bars = ax.barh(range(len(all_plugins)), counts, color=colors)
        ax.set_yticks(range(len(all_plugins)))
        ax.set_yticklabels(labels, fontsize=7)

        if show_labels:
            for bar, val in zip(bars, counts):
                ax.annotate(f'{int(val)}', xy=(val, bar.get_y() + bar.get_height()/2),
                           xytext=(3, 0), textcoords='offset points',
                           ha='left', va='center', fontsize=7, color='white')

        # Add legend
        from matplotlib.patches import Patch
        legend_elements = [Patch(facecolor=env_colors.get(e, '#6c757d'), label=e) for e in env_types if e in [p['env'] for p in all_plugins]]
        if legend_elements:
            ax.legend(handles=legend_elements, loc='lower right', fontsize=9)

        ax.set_title(f'Top {num_per_env} Plugins per Environment')
        ax.set_xlabel('Finding Count')
        ax.invert_yaxis()

    def _draw_plugin_severity_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw plugin severity distribution for pop-out."""
        df = self._get_chart_data('lifecycle')

        if df.empty or 'plugin_id' not in df.columns or 'severity' not in df.columns:
            ax.text(0.5, 0.5, 'No plugin severity data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        # Count unique plugins per severity
        plugin_sev = df.groupby('severity')['plugin_id'].nunique()
        severity_order = ['Critical', 'High', 'Medium', 'Low', 'Info']
        plugin_sev = plugin_sev.reindex([s for s in severity_order if s in plugin_sev.index])

        if len(plugin_sev) == 0:
            ax.text(0.5, 0.5, 'No severity data', ha='center', va='center', color='white', fontsize=12)
            return

        severity_colors = {'Critical': '#dc3545', 'High': '#fd7e14', 'Medium': '#ffc107',
                          'Low': '#007bff', 'Info': '#6c757d'}
        colors = [severity_colors.get(s, '#6c757d') for s in plugin_sev.index]

        bars = ax.bar(range(len(plugin_sev)), plugin_sev.values, color=colors)
        ax.set_xticks(range(len(plugin_sev)))
        ax.set_xticklabels(plugin_sev.index, fontsize=10)

        if show_labels:
            for bar, val in zip(bars, plugin_sev.values):
                ax.annotate(f'{int(val)}', xy=(bar.get_x() + bar.get_width()/2, val),
                           xytext=(0, 3), textcoords='offset points',
                           ha='center', va='bottom', fontsize=9, color='white')

        ax.set_title('Unique Plugins by Severity')
        ax.set_ylabel('Plugin Count')

    def _draw_plugins_by_hosts_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw plugins affecting most hosts for pop-out."""
        df = self._get_chart_data('lifecycle')

        if df.empty or 'plugin_id' not in df.columns or 'hostname' not in df.columns:
            ax.text(0.5, 0.5, 'No plugin/host data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        num_plugins = 15 if enlarged else 10
        hosts_per_plugin = df.groupby('plugin_id')['hostname'].nunique().nlargest(num_plugins)

        if len(hosts_per_plugin) == 0:
            ax.text(0.5, 0.5, 'No data', ha='center', va='center', color='white', fontsize=12)
            return

        bars = ax.barh(range(len(hosts_per_plugin)), hosts_per_plugin.values, color='#fd7e14')
        ax.set_yticks(range(len(hosts_per_plugin)))

        if 'plugin_name' in df.columns:
            plugin_names = df.groupby('plugin_id')['plugin_name'].first()
            labels = [str(plugin_names.get(pid, pid))[:25] for pid in hosts_per_plugin.index]
        else:
            labels = [str(pid) for pid in hosts_per_plugin.index]

        ax.set_yticklabels(labels, fontsize=7)

        if show_labels:
            for bar, val in zip(bars, hosts_per_plugin.values):
                ax.annotate(f'{int(val)}', xy=(val, bar.get_y() + bar.get_height()/2),
                           xytext=(3, 0), textcoords='offset points',
                           ha='left', va='center', fontsize=7, color='white')

        ax.set_title(f'Plugins Affecting Most Hosts')
        ax.set_xlabel('Host Count')
        ax.invert_yaxis()

    def _draw_plugin_age_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw plugin average age for pop-out."""
        df = self._get_chart_data('lifecycle')

        if df.empty or 'plugin_id' not in df.columns or 'days_open' not in df.columns:
            ax.text(0.5, 0.5, 'No plugin age data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        num_plugins = 15 if enlarged else 10
        df = df.copy()
        df['days_open'] = pd.to_numeric(df['days_open'], errors='coerce')
        avg_age = df.groupby('plugin_id')['days_open'].mean().nlargest(num_plugins)

        if len(avg_age) == 0:
            ax.text(0.5, 0.5, 'No age data', ha='center', va='center', color='white', fontsize=12)
            return

        # Color by age
        colors = ['#dc3545' if a > 90 else '#ffc107' if a > 30 else '#28a745' for a in avg_age.values]

        bars = ax.barh(range(len(avg_age)), avg_age.values, color=colors)
        ax.set_yticks(range(len(avg_age)))

        if 'plugin_name' in df.columns:
            plugin_names = df.groupby('plugin_id')['plugin_name'].first()
            labels = [str(plugin_names.get(pid, pid))[:25] for pid in avg_age.index]
        else:
            labels = [str(pid) for pid in avg_age.index]

        ax.set_yticklabels(labels, fontsize=7)

        if show_labels:
            for bar, val in zip(bars, avg_age.values):
                ax.annotate(f'{int(val)}d', xy=(val, bar.get_y() + bar.get_height()/2),
                           xytext=(3, 0), textcoords='offset points',
                           ha='left', va='center', fontsize=7, color='white')

        ax.set_title('Plugins with Longest Average Age')
        ax.set_xlabel('Average Days Open')
        ax.invert_yaxis()

    # ==================== Priority Tab Pop-outs ====================

    def _bind_chart_popouts_priority(self):
        """Bind double-click pop-out for Priority tab charts."""
        if not hasattr(self, 'priority_canvas'):
            return

        def get_click_quadrant(event):
            widget = event.widget
            w, h = widget.winfo_width(), widget.winfo_height()
            x, y = event.x, event.y
            col = 0 if x < w / 2 else 1
            row = 0 if y < h / 2 else 1
            return row * 2 + col

        def on_double_click(event):
            quadrant = get_click_quadrant(event)
            chart_info = [
                ('Remediation Priority Matrix', self._draw_priority_matrix_popout),
                ('Priority Distribution', self._draw_priority_distribution_popout),
                ('Top Priority Findings', self._draw_top_priority_popout),
                ('Priority Score by Severity', self._draw_priority_by_severity_popout),
            ]
            title, redraw_func = chart_info[quadrant]
            ChartPopoutModal(self.window, title, redraw_func)

        self.priority_canvas.get_tk_widget().bind('<Double-Button-1>', on_double_click)

    def _draw_priority_matrix_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw remediation priority matrix (CVSS vs Age) for pop-out."""
        df = self._get_chart_data('lifecycle')

        if df.empty or 'cvss' not in df.columns or 'days_open' not in df.columns:
            ax.text(0.5, 0.5, 'No CVSS/age data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        plot_df = df[df['cvss'].notna() & df['days_open'].notna()].copy()
        if plot_df.empty:
            ax.text(0.5, 0.5, 'No data with CVSS and age', ha='center', va='center',
                   color='white', fontsize=12)
            return

        # Limit sample size for performance
        if len(plot_df) > 500:
            plot_df = plot_df.sample(500, random_state=42)

        # Calculate priority score
        plot_df['priority_score'] = plot_df['cvss'] * np.log1p(plot_df['days_open'])

        # Color by priority
        scatter = ax.scatter(plot_df['days_open'], plot_df['cvss'],
                           c=plot_df['priority_score'], cmap='RdYlGn_r',
                           s=30 if enlarged else 15, alpha=0.6)

        # Add quadrant lines
        ax.axhline(y=7.0, color='white', linestyle='--', linewidth=1, alpha=0.5)
        ax.axvline(x=30, color='white', linestyle='--', linewidth=1, alpha=0.5)

        # Label quadrants
        if enlarged:
            ax.text(0.75, 0.95, 'URGENT', transform=ax.transAxes, fontsize=10,
                   color='#dc3545', fontweight='bold', ha='center')
            ax.text(0.25, 0.95, 'HIGH PRIORITY', transform=ax.transAxes, fontsize=10,
                   color='#fd7e14', fontweight='bold', ha='center')
            ax.text(0.75, 0.05, 'MONITOR', transform=ax.transAxes, fontsize=10,
                   color='#ffc107', fontweight='bold', ha='center')
            ax.text(0.25, 0.05, 'LOW PRIORITY', transform=ax.transAxes, fontsize=10,
                   color='#28a745', fontweight='bold', ha='center')

        ax.set_title('Remediation Priority Matrix')
        ax.set_xlabel('Days Open')
        ax.set_ylabel('CVSS Score')

        if enlarged:
            fig.colorbar(scatter, ax=ax, label='Priority Score')

    def _draw_priority_distribution_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw priority distribution pie for pop-out."""
        df = self._get_chart_data('lifecycle')

        if df.empty or 'cvss' not in df.columns or 'days_open' not in df.columns:
            ax.text(0.5, 0.5, 'No priority data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        # Categorize by priority
        def get_priority(row):
            cvss = row.get('cvss', 0) or 0
            days = row.get('days_open', 0) or 0
            if cvss >= 7 and days > 30:
                return 'Urgent'
            elif cvss >= 7 or days > 60:
                return 'High'
            elif cvss >= 4 or days > 30:
                return 'Medium'
            else:
                return 'Low'

        df_copy = df.copy()
        df_copy['priority'] = df_copy.apply(get_priority, axis=1)
        priority_counts = df_copy['priority'].value_counts()

        priority_order = ['Urgent', 'High', 'Medium', 'Low']
        priority_counts = priority_counts.reindex([p for p in priority_order if p in priority_counts.index])

        if len(priority_counts) == 0:
            ax.text(0.5, 0.5, 'No data', ha='center', va='center', color='white', fontsize=12)
            return

        colors = {'Urgent': '#dc3545', 'High': '#fd7e14', 'Medium': '#ffc107', 'Low': '#28a745'}
        pie_colors = [colors.get(p, '#6c757d') for p in priority_counts.index]

        labels = [f'{p}\n({c})' for p, c in zip(priority_counts.index, priority_counts.values)]
        ax.pie(priority_counts.values, labels=labels, colors=pie_colors, autopct='%1.1f%%',
              textprops={'color': 'white', 'fontsize': 9})

        ax.set_title('Priority Distribution')

    def _draw_top_priority_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw top priority findings for pop-out."""
        df = self._get_chart_data('lifecycle')

        if df.empty or 'cvss' not in df.columns or 'days_open' not in df.columns:
            ax.text(0.5, 0.5, 'No priority data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        df_copy = df.copy()
        df_copy['days_open'] = pd.to_numeric(df_copy['days_open'], errors='coerce')
        df_copy['cvss'] = pd.to_numeric(df_copy['cvss'], errors='coerce')
        df_copy['priority_score'] = df_copy['cvss'].fillna(0) * np.log1p(df_copy['days_open'].fillna(0))

        num_findings = 15 if enlarged else 10
        top_priority = df_copy.nlargest(num_findings, 'priority_score')

        if len(top_priority) == 0:
            ax.text(0.5, 0.5, 'No data', ha='center', va='center', color='white', fontsize=12)
            return

        bars = ax.barh(range(len(top_priority)), top_priority['priority_score'].values, color='#dc3545')
        ax.set_yticks(range(len(top_priority)))

        if 'plugin_name' in top_priority.columns:
            labels = [f"{str(row['plugin_name'])[:20]} ({row['hostname'][:10]})"
                     for _, row in top_priority.iterrows()]
        else:
            labels = [f"Plugin {row['plugin_id']} ({row['hostname'][:10]})"
                     for _, row in top_priority.iterrows()]

        ax.set_yticklabels(labels, fontsize=7)

        ax.set_title(f'Top {num_findings} Priority Findings')
        ax.set_xlabel('Priority Score (CVSS × log(days+1))')
        ax.invert_yaxis()

    def _draw_priority_by_severity_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw priority score by severity for pop-out."""
        df = self._get_chart_data('lifecycle')

        if df.empty or 'severity' not in df.columns or 'cvss' not in df.columns or 'days_open' not in df.columns:
            ax.text(0.5, 0.5, 'No priority data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        df_copy = df.copy()
        df_copy['days_open'] = pd.to_numeric(df_copy['days_open'], errors='coerce')
        df_copy['cvss'] = pd.to_numeric(df_copy['cvss'], errors='coerce')
        df_copy['priority_score'] = df_copy['cvss'].fillna(0) * np.log1p(df_copy['days_open'].fillna(0))

        avg_priority = df_copy.groupby('severity')['priority_score'].mean()
        severity_order = ['Critical', 'High', 'Medium', 'Low']
        avg_priority = avg_priority.reindex([s for s in severity_order if s in avg_priority.index])

        if len(avg_priority) == 0:
            ax.text(0.5, 0.5, 'No data', ha='center', va='center', color='white', fontsize=12)
            return

        severity_colors = {'Critical': '#dc3545', 'High': '#fd7e14', 'Medium': '#ffc107', 'Low': '#007bff'}
        colors = [severity_colors.get(s, '#6c757d') for s in avg_priority.index]

        bars = ax.bar(range(len(avg_priority)), avg_priority.values, color=colors)
        ax.set_xticks(range(len(avg_priority)))
        ax.set_xticklabels(avg_priority.index, fontsize=10)

        if show_labels:
            for bar, val in zip(bars, avg_priority.values):
                ax.annotate(f'{val:.1f}', xy=(bar.get_x() + bar.get_width()/2, val),
                           xytext=(0, 3), textcoords='offset points',
                           ha='center', va='bottom', fontsize=9, color='white')

        ax.set_title('Average Priority Score by Severity')
        ax.set_ylabel('Avg Priority Score')

    # ==================== Host Tracking Tab Pop-outs ====================

    def _bind_chart_popouts_host_tracking(self):
        """Bind double-click pop-out for Host Tracking tab charts."""
        if not hasattr(self, 'host_tracking_canvas'):
            return

        def get_click_quadrant(event):
            widget = event.widget
            w, h = widget.winfo_width(), widget.winfo_height()
            x, y = event.x, event.y
            col = 0 if x < w / 2 else 1
            row = 0 if y < h / 2 else 1
            return row * 2 + col

        def on_double_click(event):
            quadrant = get_click_quadrant(event)
            chart_info = [
                ('Hosts Missing from Recent Scans', self._draw_missing_hosts_popout),
                ('Host Presence Over Time', self._draw_host_presence_popout),
                ('Hosts with Declining Presence', self._draw_declining_hosts_popout),
                ('Host Status Distribution', self._draw_host_status_popout),
            ]
            title, redraw_func = chart_info[quadrant]
            ChartPopoutModal(self.window, title, redraw_func)

        self.host_tracking_canvas.get_tk_widget().bind('<Double-Button-1>', on_double_click)

    def _draw_missing_hosts_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw hosts missing from recent scans for pop-out."""
        host_df = self.filtered_host_df if not self.filtered_host_df.empty else self.host_presence_df

        if host_df.empty:
            ax.text(0.5, 0.5, 'No host tracking data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        # Find hosts not in recent scans
        if 'last_seen' in host_df.columns and 'scans_missed' in host_df.columns:
            missing = host_df[host_df['scans_missed'] > 0].nlargest(15 if enlarged else 10, 'scans_missed')
        else:
            ax.text(0.5, 0.5, 'Missing scan data not available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        if missing.empty:
            ax.text(0.5, 0.5, 'No missing hosts detected', ha='center', va='center',
                   color='#28a745', fontsize=12)
            return

        bars = ax.barh(range(len(missing)), missing['scans_missed'].values, color='#dc3545')
        ax.set_yticks(range(len(missing)))
        ax.set_yticklabels([str(h)[:20] for h in missing['hostname']], fontsize=8)

        if show_labels:
            for bar, val in zip(bars, missing['scans_missed'].values):
                ax.annotate(f'{int(val)}', xy=(val, bar.get_y() + bar.get_height()/2),
                           xytext=(3, 0), textcoords='offset points',
                           ha='left', va='center', fontsize=8, color='white')

        ax.set_title('Hosts Missing from Recent Scans')
        ax.set_xlabel('Scans Missed')
        ax.invert_yaxis()

    def _draw_host_presence_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw host presence over time for pop-out."""
        hist_df = self._get_chart_data('historical')

        if hist_df.empty or 'scan_date' not in hist_df.columns or 'hostname' not in hist_df.columns:
            ax.text(0.5, 0.5, 'No historical host data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        # Count unique hosts per scan date
        hosts_per_scan = hist_df.groupby('scan_date')['hostname'].nunique().reset_index()
        hosts_per_scan = hosts_per_scan.sort_values('scan_date')

        if len(hosts_per_scan) < 2:
            ax.text(0.5, 0.5, 'Need 2+ scans for trend', ha='center', va='center',
                   color='white', fontsize=12)
            return

        dates = hosts_per_scan['scan_date']
        counts = hosts_per_scan['hostname']

        ax.plot(range(len(dates)), counts, marker='o', color='#17a2b8',
               linewidth=2, markersize=6 if enlarged else 4)
        ax.fill_between(range(len(dates)), counts, alpha=0.3, color='#17a2b8')

        if show_labels:
            for i, (x, y) in enumerate(zip(range(len(dates)), counts)):
                if not enlarged and len(dates) > 8 and i % 2 != 0:
                    continue
                ax.annotate(f'{int(y)}', xy=(x, y), xytext=(0, 8), textcoords='offset points',
                           ha='center', va='bottom', fontsize=8, color='white')

        # Format x-axis
        if len(dates) > 8:
            step = max(1, len(dates) // 8)
            tick_positions = list(range(0, len(dates), step))
            ax.set_xticks(tick_positions)
            tick_labels = [str(dates.iloc[i])[:10] for i in tick_positions]
            ax.set_xticklabels(tick_labels, fontsize=8, rotation=45, ha='right')
        else:
            ax.set_xticks(range(len(dates)))
            ax.set_xticklabels([str(d)[:10] for d in dates], fontsize=8, rotation=45, ha='right')

        ax.set_title('Host Count Over Time')
        ax.set_ylabel('Unique Hosts')
        ax.set_xlabel('Scan Date')

    def _draw_declining_hosts_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw hosts with declining presence for pop-out."""
        host_df = self.filtered_host_df if not self.filtered_host_df.empty else self.host_presence_df

        if host_df.empty or 'presence_percentage' not in host_df.columns:
            ax.text(0.5, 0.5, 'No host presence data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        # Find hosts with low presence
        declining = host_df[host_df['presence_percentage'] < 50].nsmallest(
            15 if enlarged else 10, 'presence_percentage')

        if declining.empty:
            ax.text(0.5, 0.5, 'No hosts with declining presence\n(<50% scan coverage)',
                   ha='center', va='center', color='#28a745', fontsize=12)
            return

        bars = ax.barh(range(len(declining)), declining['presence_percentage'].values, color='#ffc107')
        ax.set_yticks(range(len(declining)))
        ax.set_yticklabels([str(h)[:20] for h in declining['hostname']], fontsize=8)

        if show_labels:
            for bar, val in zip(bars, declining['presence_percentage'].values):
                ax.annotate(f'{val:.1f}%', xy=(val, bar.get_y() + bar.get_height()/2),
                           xytext=(3, 0), textcoords='offset points',
                           ha='left', va='center', fontsize=8, color='white')

        ax.set_title('Hosts with Declining Presence')
        ax.set_xlabel('Presence Percentage')
        ax.set_xlim(0, 100)
        ax.invert_yaxis()

    def _draw_host_status_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw host status distribution for pop-out."""
        host_df = self.filtered_host_df if not self.filtered_host_df.empty else self.host_presence_df

        if host_df.empty or 'presence_percentage' not in host_df.columns:
            ax.text(0.5, 0.5, 'No host status data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        # Categorize hosts by presence
        def categorize(pct):
            if pct >= 90:
                return 'Consistent (90%+)'
            elif pct >= 70:
                return 'Moderate (70-90%)'
            elif pct >= 50:
                return 'Intermittent (50-70%)'
            else:
                return 'Rare (<50%)'

        host_df_copy = host_df.copy()
        host_df_copy['status'] = host_df_copy['presence_percentage'].apply(categorize)
        status_counts = host_df_copy['status'].value_counts()

        status_order = ['Consistent (90%+)', 'Moderate (70-90%)', 'Intermittent (50-70%)', 'Rare (<50%)']
        status_counts = status_counts.reindex([s for s in status_order if s in status_counts.index])

        if len(status_counts) == 0:
            ax.text(0.5, 0.5, 'No status data', ha='center', va='center', color='white', fontsize=12)
            return

        colors = {'Consistent (90%+)': '#28a745', 'Moderate (70-90%)': '#17a2b8',
                 'Intermittent (50-70%)': '#ffc107', 'Rare (<50%)': '#dc3545'}
        pie_colors = [colors.get(s, '#6c757d') for s in status_counts.index]

        labels = [f'{s.split(" ")[0]}\n({c})' for s, c in zip(status_counts.index, status_counts.values)]
        ax.pie(status_counts.values, labels=labels, colors=pie_colors, autopct='%1.1f%%',
              textprops={'color': 'white', 'fontsize': 8})

        ax.set_title('Host Status Distribution')

        if enlarged:
            total = status_counts.sum()
            consistent = status_counts.get('Consistent (90%+)', 0)
            pct = consistent / total * 100 if total > 0 else 0
            ax.text(0.5, -0.1, f'Consistent Coverage: {pct:.1f}%', transform=ax.transAxes,
                   ha='center', fontsize=10, color='#28a745' if pct >= 70 else '#dc3545')

    # ===== Advanced Tab Pop-out Methods =====

    def _bind_chart_popouts_advanced_risk(self):
        """Bind double-click pop-out for Advanced Risk Analysis charts."""
        if not hasattr(self, 'advanced_canvas1'):
            return

        def get_click_half(event):
            widget = event.widget
            w = widget.winfo_width()
            return 0 if event.x < w / 2 else 1

        def on_double_click(event):
            idx = get_click_half(event)
            chart_info = [
                ('Risk Heatmap by Subnet/Time', self._draw_heatmap_popout),
                ('CVSS vs Age vs Impact', self._draw_bubble_popout),
            ]
            title, redraw_func = chart_info[idx]
            ChartPopoutModal(self.window, title, redraw_func)

        self.advanced_canvas1.get_tk_widget().bind('<Double-Button-1>', on_double_click)

    def _bind_chart_popouts_advanced_comp(self):
        """Bind double-click pop-out for Advanced Composition charts."""
        if not hasattr(self, 'advanced_canvas2'):
            return

        def get_click_half(event):
            widget = event.widget
            w = widget.winfo_width()
            return 0 if event.x < w / 2 else 1

        def on_double_click(event):
            idx = get_click_half(event)
            chart_info = [
                ('Vulnerability Lifecycle Flow', self._draw_sankey_popout),
                ('Plugin Family Distribution', self._draw_treemap_popout),
            ]
            title, redraw_func = chart_info[idx]
            ChartPopoutModal(self.window, title, redraw_func)

        self.advanced_canvas2.get_tk_widget().bind('<Double-Button-1>', on_double_click)

    def _bind_chart_popouts_advanced_health(self):
        """Bind double-click pop-out for Advanced Health Indicator charts."""
        if not hasattr(self, 'advanced_canvas3'):
            return

        def get_click_half(event):
            widget = event.widget
            w = widget.winfo_width()
            return 0 if event.x < w / 2 else 1

        def on_double_click(event):
            idx = get_click_half(event)
            chart_info = [
                ('Subnet Risk Profile', self._draw_radar_popout),
                ('Remediation Velocity', self._draw_gauge_popout),
            ]
            title, redraw_func = chart_info[idx]
            ChartPopoutModal(self.window, title, redraw_func)

        self.advanced_canvas3.get_tk_widget().bind('<Double-Button-1>', on_double_click)

    def _bind_chart_popouts_advanced_trends(self):
        """Bind double-click pop-out for Advanced Trends charts."""
        if not hasattr(self, 'advanced_canvas4'):
            return

        def get_click_half(event):
            widget = event.widget
            w = widget.winfo_width()
            return 0 if event.x < w / 2 else 1

        def on_double_click(event):
            idx = get_click_half(event)
            chart_info = [
                ('SLA Breach Prediction', self._draw_sla_prediction_popout),
                ('Period Comparison', self._draw_period_comparison_popout),
            ]
            title, redraw_func = chart_info[idx]
            ChartPopoutModal(self.window, title, redraw_func)

        self.advanced_canvas4.get_tk_widget().bind('<Double-Button-1>', on_double_click)

    def _draw_heatmap_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw Risk Heatmap for pop-out."""
        hist_df = self._get_chart_data('historical')

        if hist_df.empty or 'scan_date' not in hist_df.columns:
            ax.text(0.5, 0.5, 'Insufficient historical data for heatmap', ha='center', va='center',
                   color='white', fontsize=12)
            return

        ip_col = 'ip_address' if 'ip_address' in hist_df.columns else 'ip' if 'ip' in hist_df.columns else None
        if not ip_col:
            ax.text(0.5, 0.5, 'No IP address data', ha='center', va='center', color='white', fontsize=12)
            return

        hist_copy = hist_df.copy()
        hist_copy['scan_date'] = pd.to_datetime(hist_copy['scan_date'])
        hist_copy['month'] = hist_copy['scan_date'].dt.to_period('M').astype(str)
        hist_copy['subnet'] = hist_copy[ip_col].apply(
            lambda x: '.'.join(str(x).split('.')[:3]) + '.0/24' if pd.notna(x) and '.' in str(x) else 'Unknown'
        )

        top_subnets = hist_copy['subnet'].value_counts().head(15 if enlarged else 10).index.tolist()
        filtered = hist_copy[hist_copy['subnet'].isin(top_subnets)]

        if filtered.empty:
            ax.text(0.5, 0.5, 'No subnet data', ha='center', va='center', color='white', fontsize=12)
            return

        pivot = filtered.pivot_table(index='subnet', columns='month', aggfunc='size', fill_value=0)

        im = ax.imshow(pivot.values, cmap='YlOrRd', aspect='auto')
        ax.set_xticks(range(len(pivot.columns)))
        ax.set_xticklabels(pivot.columns, fontsize=8 if enlarged else 7, rotation=45, ha='right')
        ax.set_yticks(range(len(pivot.index)))
        ax.set_yticklabels(pivot.index, fontsize=8 if enlarged else 7)

        if show_labels and enlarged:
            for i in range(len(pivot.index)):
                for j in range(len(pivot.columns)):
                    val = pivot.values[i, j]
                    if val > 0:
                        color = 'white' if val > pivot.values.max() * 0.5 else 'black'
                        ax.text(j, i, str(int(val)), ha='center', va='center', fontsize=7, color=color)

        ax.set_title('Risk Heatmap by Subnet/Time')
        cbar = fig.colorbar(im, ax=ax, shrink=0.8)
        cbar.set_label('Vulnerability Count', fontsize=9)

    def _draw_bubble_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw Bubble Chart for pop-out."""
        df = self._get_chart_data('lifecycle')

        if df.empty or 'days_open' not in df.columns:
            ax.text(0.5, 0.5, 'No vulnerability age data', ha='center', va='center',
                   color='white', fontsize=12)
            return

        active = df[df['status'] == 'Active'].copy() if 'status' in df.columns else df.copy()
        if active.empty:
            ax.text(0.5, 0.5, 'No active findings', ha='center', va='center', color='white', fontsize=12)
            return

        cvss_col = 'cvss3_base_score' if 'cvss3_base_score' in active.columns else 'cvss_base_score' if 'cvss_base_score' in active.columns else None
        if not cvss_col:
            if 'severity_value' in active.columns:
                active['cvss_proxy'] = active['severity_value'] * 2.5
                cvss_col = 'cvss_proxy'
            else:
                ax.text(0.5, 0.5, 'No CVSS data available', ha='center', va='center', color='white', fontsize=12)
                return

        if 'plugin_id' in active.columns:
            # Convert to numeric before aggregation
            active = active.copy()
            active[cvss_col] = pd.to_numeric(active[cvss_col], errors='coerce')
            active['days_open'] = pd.to_numeric(active['days_open'], errors='coerce')
            grouped = active.groupby('plugin_id').agg({
                cvss_col: 'mean',
                'days_open': 'mean',
                'hostname': 'nunique' if 'hostname' in active.columns else 'count'
            }).reset_index()
            grouped.columns = ['plugin_id', 'cvss', 'age', 'hosts']
        else:
            grouped = pd.DataFrame({
                'cvss': pd.to_numeric(active[cvss_col], errors='coerce').values,
                'age': pd.to_numeric(active['days_open'], errors='coerce').values,
                'hosts': [1] * len(active)
            })

        grouped = grouped.dropna(subset=['cvss', 'age'])
        if grouped.empty:
            ax.text(0.5, 0.5, 'No data after filtering', ha='center', va='center', color='white', fontsize=12)
            return

        colors = grouped['cvss'].apply(
            lambda x: '#dc3545' if x >= 9 else '#fd7e14' if x >= 7 else '#ffc107' if x >= 4 else '#007bff'
        )
        sizes = (grouped['hosts'] * 80 + 30).clip(upper=800) if enlarged else (grouped['hosts'] * 50 + 20).clip(upper=500)

        ax.scatter(grouped['age'], grouped['cvss'], s=sizes, c=colors, alpha=0.6, edgecolors='white', linewidth=0.5)

        if show_labels and enlarged and len(grouped) <= 30:
            for _, row in grouped.head(20).iterrows():
                ax.annotate(f'{int(row["hosts"])}h', xy=(row['age'], row['cvss']),
                           fontsize=7, ha='center', va='center', color='white')

        ax.set_xlabel('Days Open', fontsize=10)
        ax.set_ylabel('CVSS Score', fontsize=10)
        ax.set_title('CVSS vs Age vs Impact (Bubble = Hosts Affected)')
        ax.axhline(y=7, color='#fd7e14', linestyle='--', alpha=0.5, linewidth=1, label='High Threshold')
        ax.axvline(x=30, color='#ffc107', linestyle='--', alpha=0.5, linewidth=1, label='30-Day Mark')
        ax.legend(fontsize=8)

    def _draw_sankey_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw Sankey-style lifecycle flow for pop-out."""
        df = self._get_chart_data('lifecycle')
        hist_df = self._get_chart_data('historical')

        if df.empty or 'status' not in df.columns:
            ax.text(0.5, 0.5, 'No lifecycle data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        status_counts = df['status'].value_counts()
        total = len(df)
        active = status_counts.get('Active', 0)
        resolved = status_counts.get('Resolved', 0)
        reopened = df['reappearances'].sum() if 'reappearances' in df.columns else 0

        ax.set_xlim(0, 10)
        ax.set_ylim(0, 10)
        ax.axis('off')

        # Draw boxes
        box_style = dict(boxstyle='round,pad=0.3', facecolor='#2d2d2d', edgecolor='white')
        ax.text(1, 5, f'Discovered\n{total}', ha='center', va='center', fontsize=11 if enlarged else 9,
               color='white', bbox=box_style)
        ax.text(5, 7, f'Active\n{active}', ha='center', va='center', fontsize=11 if enlarged else 9,
               color='#dc3545', bbox=box_style)
        ax.text(5, 3, f'Resolved\n{resolved}', ha='center', va='center', fontsize=11 if enlarged else 9,
               color='#28a745', bbox=box_style)
        ax.text(9, 5, f'Reopened\n{int(reopened)}', ha='center', va='center', fontsize=11 if enlarged else 9,
               color='#ffc107', bbox=box_style)

        # Draw arrows
        from matplotlib.patches import FancyArrowPatch
        arrow_style = dict(arrowstyle='->', color='white', lw=2, mutation_scale=15)
        ax.annotate('', xy=(4, 6.5), xytext=(2, 5.5), arrowprops=arrow_style)
        ax.annotate('', xy=(4, 3.5), xytext=(2, 4.5), arrowprops=arrow_style)
        if reopened > 0:
            ax.annotate('', xy=(8, 5.5), xytext=(6, 7), arrowprops=dict(arrowstyle='->', color='#ffc107', lw=2))

        if show_labels:
            active_pct = active / total * 100 if total > 0 else 0
            resolved_pct = resolved / total * 100 if total > 0 else 0
            ax.text(3, 7.5, f'{active_pct:.1f}%', fontsize=9, color='#dc3545')
            ax.text(3, 2.5, f'{resolved_pct:.1f}%', fontsize=9, color='#28a745')

        ax.set_title('Vulnerability Lifecycle Flow')

    def _draw_treemap_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw Plugin Family Distribution for pop-out."""
        df = self._get_chart_data('lifecycle')

        if df.empty or 'plugin_family' not in df.columns:
            ax.text(0.5, 0.5, 'No plugin family data', ha='center', va='center',
                   color='white', fontsize=12)
            return

        family_counts = df['plugin_family'].value_counts().head(20 if enlarged else 12)
        if family_counts.empty:
            ax.text(0.5, 0.5, 'No plugin families found', ha='center', va='center',
                   color='white', fontsize=12)
            return

        # Try squarify, fallback to bar chart
        try:
            import squarify
            colors = plt.cm.Set3(range(len(family_counts)))
            squarify.plot(sizes=family_counts.values, label=[f[:15] for f in family_counts.index],
                         alpha=0.8, ax=ax, color=colors, text_kwargs={'fontsize': 8 if enlarged else 6})
            ax.axis('off')
        except ImportError:
            bars = ax.barh(range(len(family_counts)), family_counts.values, color='#007bff')
            ax.set_yticks(range(len(family_counts)))
            ax.set_yticklabels([f[:25] for f in family_counts.index], fontsize=8)
            ax.invert_yaxis()
            if show_labels:
                for bar, val in zip(bars, family_counts.values):
                    ax.annotate(f'{int(val)}', xy=(val, bar.get_y() + bar.get_height()/2),
                               xytext=(3, 0), textcoords='offset points',
                               ha='left', va='center', fontsize=8, color='white')
            ax.set_xlabel('Count')

        ax.set_title('Plugin Family Distribution')

    def _draw_radar_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw Radar Chart for pop-out (requires polar projection)."""
        df = self._get_chart_data('lifecycle')

        if df.empty:
            ax.text(0.5, 0.5, 'No data available', ha='center', va='center',
                   transform=ax.transAxes, color='white', fontsize=12)
            return

        # Clear and recreate with polar projection
        ax.clear()

        ip_col = 'ip_address' if 'ip_address' in df.columns else 'ip' if 'ip' in df.columns else None
        if not ip_col:
            ax.text(0.5, 0.5, 'No IP data for subnet analysis', ha='center', va='center',
                   transform=ax.transAxes, color='white', fontsize=12)
            return

        df_copy = df.copy()
        df_copy['subnet'] = df_copy[ip_col].apply(
            lambda x: '.'.join(str(x).split('.')[:3]) + '.0/24' if pd.notna(x) and '.' in str(x) else 'Unknown'
        )

        top_subnets = df_copy['subnet'].value_counts().head(5 if enlarged else 3).index.tolist()

        metrics = ['Critical', 'High', 'Medium', 'Active', 'Old (30d+)']
        num_metrics = len(metrics)
        angles = [n / float(num_metrics) * 2 * 3.14159 for n in range(num_metrics)]
        angles += angles[:1]

        colors = ['#dc3545', '#fd7e14', '#007bff', '#17a2b8', '#28a745']

        for i, subnet in enumerate(top_subnets):
            subnet_data = df_copy[df_copy['subnet'] == subnet]
            crit = len(subnet_data[subnet_data['severity_text'] == 'Critical']) if 'severity_text' in subnet_data.columns else 0
            high = len(subnet_data[subnet_data['severity_text'] == 'High']) if 'severity_text' in subnet_data.columns else 0
            med = len(subnet_data[subnet_data['severity_text'] == 'Medium']) if 'severity_text' in subnet_data.columns else 0
            active_count = len(subnet_data[subnet_data['status'] == 'Active']) if 'status' in subnet_data.columns else 0
            old = len(subnet_data[subnet_data['days_open'] > 30]) if 'days_open' in subnet_data.columns else 0

            values = [crit, high, med, active_count, old]
            max_val = max(values) if max(values) > 0 else 1
            values_norm = [v / max_val * 100 for v in values]
            values_norm += values_norm[:1]

            ax.plot(angles, values_norm, 'o-', linewidth=2, label=subnet[:15], color=colors[i % len(colors)])
            ax.fill(angles, values_norm, alpha=0.15, color=colors[i % len(colors)])

        ax.set_xticks(angles[:-1])
        ax.set_xticklabels(metrics, fontsize=9 if enlarged else 7)
        ax.set_title('Subnet Risk Profile', pad=20)
        ax.legend(loc='upper right', bbox_to_anchor=(1.3, 1), fontsize=8)

    def _draw_gauge_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw Remediation Velocity Gauge for pop-out."""
        df = self._get_chart_data('lifecycle')
        hist_df = self._get_chart_data('historical')

        if df.empty:
            ax.text(0.5, 0.5, 'No data for velocity calculation', ha='center', va='center',
                   color='white', fontsize=12)
            ax.axis('off')
            return

        status_counts = df['status'].value_counts() if 'status' in df.columns else pd.Series()
        resolved = status_counts.get('Resolved', 0)
        total = len(df)
        velocity_pct = (resolved / total * 100) if total > 0 else 0

        ax.set_xlim(-1.5, 1.5)
        ax.set_ylim(-0.5, 1.2)
        ax.set_aspect('equal')
        ax.axis('off')

        # Draw gauge arcs
        import numpy as np
        theta_range = np.linspace(np.pi, 0, 100)
        colors_zones = [('#dc3545', 0, 30), ('#ffc107', 30, 60), ('#28a745', 60, 100)]

        for color, start_pct, end_pct in colors_zones:
            start_angle = np.pi - (start_pct / 100) * np.pi
            end_angle = np.pi - (end_pct / 100) * np.pi
            theta = np.linspace(start_angle, end_angle, 50)
            for r in [0.8, 0.85, 0.9, 0.95, 1.0]:
                ax.plot(r * np.cos(theta), r * np.sin(theta), color=color, linewidth=3 if enlarged else 2)

        # Draw needle
        needle_angle = np.pi - (velocity_pct / 100) * np.pi
        ax.arrow(0, 0, 0.7 * np.cos(needle_angle), 0.7 * np.sin(needle_angle),
                head_width=0.08, head_length=0.05, fc='white', ec='white')
        ax.plot(0, 0, 'o', markersize=10 if enlarged else 8, color='white')

        # Labels
        ax.text(0, -0.25, f'{velocity_pct:.1f}%', ha='center', va='center',
               fontsize=18 if enlarged else 14, color='white', fontweight='bold')
        ax.text(0, -0.4, 'Remediation Velocity', ha='center', va='center',
               fontsize=11 if enlarged else 9, color='#888888')

        if show_labels:
            ax.text(-1.1, 0, '0%', ha='center', fontsize=9, color='white')
            ax.text(0, 1.1, '50%', ha='center', fontsize=9, color='white')
            ax.text(1.1, 0, '100%', ha='center', fontsize=9, color='white')

        ax.set_title('Remediation Velocity Gauge')

    def _draw_sla_prediction_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw SLA Breach Prediction for pop-out."""
        df = self._get_chart_data('lifecycle')

        if df.empty or 'days_until_sla' not in df.columns:
            ax.text(0.5, 0.5, 'No SLA data for prediction', ha='center', va='center',
                   color='white', fontsize=12)
            return

        active = df[df['status'] == 'Active'] if 'status' in df.columns else df
        if active.empty:
            ax.text(0.5, 0.5, 'No active findings', ha='center', va='center', color='white', fontsize=12)
            return

        days_ahead = 45 if enlarged else 30
        cumulative = []
        for day in range(days_ahead + 1):
            breaching = len(active[active['days_until_sla'] <= day])
            cumulative.append(breaching)

        ax.plot(range(len(cumulative)), cumulative, color='#dc3545', linewidth=2, marker='o',
               markersize=4 if enlarged else 2)
        ax.fill_between(range(len(cumulative)), cumulative, alpha=0.3, color='#dc3545')

        if show_labels:
            key_days = [0, 7, 14, 30] if enlarged else [0, 7, 14, 30]
            for day in key_days:
                if day < len(cumulative):
                    ax.annotate(f'{cumulative[day]}', xy=(day, cumulative[day]),
                               xytext=(0, 8), textcoords='offset points',
                               ha='center', fontsize=9 if enlarged else 7, color='white')

        ax.axvline(x=7, color='#ffc107', linestyle='--', alpha=0.7, label='1 Week')
        ax.axvline(x=14, color='#fd7e14', linestyle='--', alpha=0.7, label='2 Weeks')

        ax.set_xlabel('Days from Now', fontsize=10)
        ax.set_ylabel('Cumulative SLA Breaches', fontsize=10)
        ax.set_title('SLA Breach Prediction (Next 30 Days)')
        ax.legend(fontsize=8)

        if enlarged:
            current_breach = cumulative[0]
            week_breach = cumulative[7] if len(cumulative) > 7 else 0
            ax.text(0.02, 0.98, f'Currently Breached: {current_breach}\nBreached by Day 7: {week_breach}',
                   transform=ax.transAxes, fontsize=10, va='top', color='white',
                   bbox=dict(boxstyle='round', facecolor='#2d2d2d', alpha=0.8))

    def _draw_period_comparison_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw Period Comparison for pop-out."""
        hist_df = self._get_chart_data('historical')

        if hist_df.empty or 'scan_date' not in hist_df.columns:
            ax.text(0.5, 0.5, 'Insufficient historical data', ha='center', va='center',
                   color='white', fontsize=12)
            return

        hist_copy = hist_df.copy()
        hist_copy['scan_date'] = pd.to_datetime(hist_copy['scan_date'])
        mid_date = hist_copy['scan_date'].median()
        earlier = hist_copy[hist_copy['scan_date'] < mid_date]
        recent = hist_copy[hist_copy['scan_date'] >= mid_date]

        if earlier.empty or recent.empty:
            ax.text(0.5, 0.5, 'Need data across time periods', ha='center', va='center',
                   color='white', fontsize=12)
            return

        # Compare metrics
        metrics = ['Total', 'Critical', 'High', 'Hosts']

        earlier_vals = [
            len(earlier),
            len(earlier[earlier['severity_text'] == 'Critical']) if 'severity_text' in earlier.columns else 0,
            len(earlier[earlier['severity_text'] == 'High']) if 'severity_text' in earlier.columns else 0,
            earlier['hostname'].nunique() if 'hostname' in earlier.columns else 0
        ]

        recent_vals = [
            len(recent),
            len(recent[recent['severity_text'] == 'Critical']) if 'severity_text' in recent.columns else 0,
            len(recent[recent['severity_text'] == 'High']) if 'severity_text' in recent.columns else 0,
            recent['hostname'].nunique() if 'hostname' in recent.columns else 0
        ]

        x = range(len(metrics))
        width = 0.35

        bars1 = ax.bar([i - width/2 for i in x], earlier_vals, width, label='Earlier Period', color='#6c757d')
        bars2 = ax.bar([i + width/2 for i in x], recent_vals, width, label='Recent Period', color='#007bff')

        ax.set_xticks(x)
        ax.set_xticklabels(metrics, fontsize=10 if enlarged else 8)
        ax.set_ylabel('Count', fontsize=10)
        ax.set_title('Period Comparison: Earlier vs Recent')
        ax.legend(fontsize=9)

        if show_labels:
            for bar, val in zip(bars1, earlier_vals):
                ax.annotate(f'{int(val)}', xy=(bar.get_x() + bar.get_width()/2, val),
                           xytext=(0, 3), textcoords='offset points',
                           ha='center', fontsize=8, color='white')
            for bar, val in zip(bars2, recent_vals):
                ax.annotate(f'{int(val)}', xy=(bar.get_x() + bar.get_width()/2, val),
                           xytext=(0, 3), textcoords='offset points',
                           ha='center', fontsize=8, color='white')

        if enlarged:
            # Add trend indicators
            for i, (e, r) in enumerate(zip(earlier_vals, recent_vals)):
                if e > 0:
                    change = ((r - e) / e) * 100
                    color = '#28a745' if change < 0 else '#dc3545'
                    symbol = '▼' if change < 0 else '▲'
                    ax.text(i, max(e, r) * 1.1, f'{symbol}{abs(change):.0f}%',
                           ha='center', fontsize=9, color=color)

    def _update_opdir_charts(self):
        """Update OPDIR compliance visualizations."""
        if not HAS_MATPLOTLIB or not hasattr(self, 'opdir_ax1'):
            return

        df = self._get_chart_data('lifecycle')

        for ax in [self.opdir_ax1, self.opdir_ax2, self.opdir_ax3, self.opdir_ax4]:
            ax.clear()
            ax.set_facecolor(GUI_DARK_THEME['entry_bg'])

        if df.empty:
            for ax in [self.opdir_ax1, self.opdir_ax2, self.opdir_ax3, self.opdir_ax4]:
                ax.text(0.5, 0.5, 'No vulnerability data loaded', ha='center', va='center',
                       color=GUI_DARK_THEME['fg'], fontsize=10)
            self.opdir_canvas.draw()
            return

        # Check if OPDIR file has been loaded
        opdir_loaded = hasattr(self, 'opdir_df') and not self.opdir_df.empty

        # Check if data labels are enabled
        show_labels = self.settings_manager.settings.show_data_labels

        # Chart 1: OPDIR coverage pie with counts
        if 'opdir_number' in df.columns:
            mapped = df['opdir_number'].notna() & (df['opdir_number'] != '')
            mapped_count = mapped.sum()
            unmapped_count = (~mapped).sum()
            counts = [mapped_count, unmapped_count]
            labels = [f'Mapped\n({mapped_count})', f'Unmapped\n({unmapped_count})']
            colors = ['#28a745', '#6c757d']
            if sum(counts) > 0:
                self.opdir_ax1.pie(counts, labels=labels, colors=colors, autopct='%1.1f%%',
                                  textprops={'color': GUI_DARK_THEME['fg'], 'fontsize': 8})
            else:
                self.opdir_ax1.text(0.5, 0.5, 'No findings to display', ha='center', va='center',
                                   color=GUI_DARK_THEME['fg'])
        else:
            # No opdir_number column means OPDIR enrichment hasn't run
            self.opdir_ax1.text(0.5, 0.5, 'Load OPDIR mapping file\nto enable compliance tracking',
                               ha='center', va='center', color=GUI_DARK_THEME['fg'], fontsize=9)
        self.opdir_ax1.set_title('OPDIR Mapping Coverage\n', color=GUI_DARK_THEME['fg'], fontsize=10)

        # Chart 2: OPDIR status distribution with data labels
        has_status_data = False
        if 'opdir_status' in df.columns:
            # Filter to only rows with status
            status_df = df[df['opdir_status'] != '']
            if not status_df.empty:
                status_counts = status_df['opdir_status'].value_counts()
                status_order = ['Overdue', 'Due Soon', 'On Track']
                status_counts = status_counts.reindex([s for s in status_order if s in status_counts.index])

                if len(status_counts) > 0:
                    has_status_data = True
                    colors_map = {'Overdue': '#dc3545', 'Due Soon': '#ffc107', 'On Track': '#28a745'}
                    bar_colors = [colors_map.get(s, '#6c757d') for s in status_counts.index]
                    bars = self.opdir_ax2.bar(range(len(status_counts)), status_counts.values, color=bar_colors)
                    self.opdir_ax2.set_xticks(range(len(status_counts)))
                    self.opdir_ax2.set_xticklabels(status_counts.index, fontsize=8)

                    # Add data labels
                    for bar, val in zip(bars, status_counts.values):
                        self.opdir_ax2.annotate(f'{int(val)}',
                                               xy=(bar.get_x() + bar.get_width()/2, val),
                                               xytext=(0, 3), textcoords='offset points',
                                               ha='center', va='bottom', fontsize=7, color='white')
        if not has_status_data:
            if not opdir_loaded:
                self.opdir_ax2.text(0.5, 0.5, 'Load OPDIR file with\ndue dates for status tracking',
                                   ha='center', va='center', color=GUI_DARK_THEME['fg'], fontsize=9)
            else:
                self.opdir_ax2.text(0.5, 0.5, 'No findings with\nOPDIR due dates',
                                   ha='center', va='center', color=GUI_DARK_THEME['fg'], fontsize=9)
        self.opdir_ax2.set_title('OPDIR Status Distribution', color=GUI_DARK_THEME['fg'], fontsize=10)
        self.opdir_ax2.set_ylabel('Count', color=GUI_DARK_THEME['fg'])

        # Chart 3: Finding age histogram for OPDIR-mapped items
        if 'days_open' in df.columns and 'opdir_number' in df.columns:
            mapped_df = df[df['opdir_number'].notna() & (df['opdir_number'] != '')]
            if not mapped_df.empty:
                days = mapped_df['days_open'].values
                bins = [0, 7, 30, 60, 90, 180, max(days.max() + 1, 181)]
                bin_labels = ['0-7', '8-30', '31-60', '61-90', '91-180', '180+']
                hist, _ = np.histogram(days, bins=bins)

                colors = ['#28a745', '#28a745', '#ffc107', '#ffc107', '#fd7e14', '#dc3545']
                bars = self.opdir_ax3.bar(range(len(hist)), hist, color=colors[:len(hist)])
                self.opdir_ax3.set_xticks(range(len(hist)))
                self.opdir_ax3.set_xticklabels(bin_labels[:len(hist)], fontsize=7)

                # Add data labels
                for bar, val in zip(bars, hist):
                    if val > 0:
                        self.opdir_ax3.annotate(f'{int(val)}',
                                               xy=(bar.get_x() + bar.get_width()/2, val),
                                               xytext=(0, 2), textcoords='offset points',
                                               ha='center', va='bottom', fontsize=6, color='white')
            else:
                self.opdir_ax3.text(0.5, 0.5, 'No OPDIR-mapped\nfindings', ha='center', va='center',
                                   color=GUI_DARK_THEME['fg'], fontsize=9)
        self.opdir_ax3.set_title('Finding Age (OPDIR Mapped)', color=GUI_DARK_THEME['fg'], fontsize=10)
        self.opdir_ax3.set_xlabel('Days Open', color=GUI_DARK_THEME['fg'])
        self.opdir_ax3.set_ylabel('Count', color=GUI_DARK_THEME['fg'])

        # Chart 4: Compliance by OPDIR Year (stacked bar)
        if 'opdir_year' in df.columns and 'opdir_status' in df.columns:
            year_df = df[df['opdir_year'].notna() & (df['opdir_status'] != '')]
            if not year_df.empty:
                # Group by year and status
                year_status = year_df.groupby(['opdir_year', 'opdir_status']).size().unstack(fill_value=0)
                years = year_status.index
                x = range(len(years))

                # Stacked bars
                bottom = np.zeros(len(years))
                colors_map = {'On Track': '#28a745', 'Due Soon': '#ffc107', 'Overdue': '#dc3545'}

                for status in ['On Track', 'Due Soon', 'Overdue']:
                    if status in year_status.columns:
                        values = year_status[status].values
                        self.opdir_ax4.bar(x, values, bottom=bottom, label=status,
                                          color=colors_map.get(status, '#6c757d'), width=0.7)
                        bottom += values

                self.opdir_ax4.set_xticks(x)
                self.opdir_ax4.set_xticklabels([int(y) for y in years], fontsize=8)
                self.opdir_ax4.legend(loc='upper right', fontsize=6)
            else:
                self.opdir_ax4.text(0.5, 0.5, 'No OPDIR year data\n(Load OPDIR mapping)',
                                   ha='center', va='center', color=GUI_DARK_THEME['fg'], fontsize=9)
        else:
            self.opdir_ax4.text(0.5, 0.5, 'OPDIR Year Analysis\n(Load OPDIR mapping)',
                               ha='center', va='center', color=GUI_DARK_THEME['fg'], fontsize=9)
        self.opdir_ax4.set_title('Compliance by OPDIR Year', color=GUI_DARK_THEME['fg'], fontsize=10)
        self.opdir_ax4.set_ylabel('Count', color=GUI_DARK_THEME['fg'])

        for ax in [self.opdir_ax1, self.opdir_ax2, self.opdir_ax3, self.opdir_ax4]:
            ax.tick_params(colors=GUI_DARK_THEME['fg'])
            for spine in ax.spines.values():
                spine.set_color(GUI_DARK_THEME['fg'])

        self.opdir_fig.tight_layout()
        self.opdir_canvas.draw()

    def _update_efficiency_charts(self):
        """Update operational efficiency visualizations."""
        if not HAS_MATPLOTLIB or not hasattr(self, 'efficiency_ax1'):
            return

        df = self._get_chart_data('lifecycle')
        host_df = self.filtered_host_df if not self.filtered_host_df.empty else self.host_presence_df
        show_labels = self.settings_manager.settings.show_data_labels

        for ax in [self.efficiency_ax1, self.efficiency_ax2, self.efficiency_ax3, self.efficiency_ax4]:
            ax.clear()
            ax.set_facecolor(GUI_DARK_THEME['entry_bg'])

        if df.empty:
            self.efficiency_canvas.draw()
            return

        # Chart 1: Scan coverage with color-coded bins
        if not host_df.empty and 'presence_percentage' in host_df.columns:
            presence = host_df['presence_percentage'].values
            n, bins, patches = self.efficiency_ax1.hist(presence, bins=10, edgecolor='white', alpha=0.8)
            # Color by coverage quality
            for i, patch in enumerate(patches):
                bin_center = (bins[i] + bins[i+1]) / 2
                if bin_center >= 80:
                    patch.set_facecolor('#28a745')
                elif bin_center >= 50:
                    patch.set_facecolor('#ffc107')
                else:
                    patch.set_facecolor('#dc3545')
            # Summary stats
            presence_numeric = pd.to_numeric(pd.Series(presence), errors='coerce')
            avg_presence = presence_numeric.mean()
            self.efficiency_ax1.axvline(x=avg_presence, color='white', linestyle='--', linewidth=1, alpha=0.7)
            self.efficiency_ax1.text(0.98, 0.98, f'Avg: {avg_presence:.1f}%', transform=self.efficiency_ax1.transAxes,
                                    fontsize=8, va='top', ha='right', color='white')
        self.efficiency_ax1.set_title('Scan Coverage Consistency', color=GUI_DARK_THEME['fg'], fontsize=10)
        self.efficiency_ax1.set_xlabel('Presence %', color=GUI_DARK_THEME['fg'])
        self.efficiency_ax1.set_ylabel('Host Count', color=GUI_DARK_THEME['fg'])

        # Chart 2: Reappearance analysis with data labels
        reapp_col = 'reappearances' if 'reappearances' in df.columns else 'appearance_count' if 'appearance_count' in df.columns else None
        if reapp_col:
            reapp_counts = df[reapp_col].value_counts().sort_index().head(8)
            if len(reapp_counts) > 0:
                bars = self.efficiency_ax2.bar(range(len(reapp_counts)), reapp_counts.values, color='#fd7e14')
                self.efficiency_ax2.set_xticks(range(len(reapp_counts)))
                self.efficiency_ax2.set_xticklabels([int(x) for x in reapp_counts.index], fontsize=8)
                if show_labels:
                    for bar, val in zip(bars, reapp_counts.values):
                        self.efficiency_ax2.annotate(f'{int(val)}', xy=(bar.get_x() + bar.get_width()/2, val),
                                                    xytext=(0, 2), textcoords='offset points',
                                                    ha='center', va='bottom', fontsize=7, color='white')
                # Recurring percentage
                total = reapp_counts.sum()
                recurring = reapp_counts[reapp_counts.index > 1].sum() if len(reapp_counts) > 1 else 0
                pct = recurring / total * 100 if total > 0 else 0
                self.efficiency_ax2.text(0.98, 0.98, f'Recurring: {pct:.1f}%', transform=self.efficiency_ax2.transAxes,
                                        fontsize=8, va='top', ha='right', color='#fd7e14')
        self.efficiency_ax2.set_title('Reappearance Analysis', color=GUI_DARK_THEME['fg'], fontsize=10)
        self.efficiency_ax2.set_xlabel('Times Seen', color=GUI_DARK_THEME['fg'])
        self.efficiency_ax2.set_ylabel('Finding Count', color=GUI_DARK_THEME['fg'])

        # Chart 3: Host vulnerability burden with stats
        if 'hostname' in df.columns:
            host_burden = df.groupby('hostname').size()
            if len(host_burden) > 0:
                n, bins, patches = self.efficiency_ax3.hist(host_burden, bins=15, color='#6f42c1', edgecolor='white', alpha=0.8)
                # Summary stats
                burden_numeric = pd.to_numeric(host_burden, errors='coerce')
                avg_burden = burden_numeric.mean()
                max_burden = burden_numeric.max()
                self.efficiency_ax3.axvline(x=avg_burden, color='white', linestyle='--', linewidth=1, alpha=0.7)
                self.efficiency_ax3.text(0.98, 0.98, f'Avg: {avg_burden:.1f} | Max: {max_burden}',
                                        transform=self.efficiency_ax3.transAxes, fontsize=8, va='top', ha='right', color='white')
        self.efficiency_ax3.set_title('Host Vulnerability Burden', color=GUI_DARK_THEME['fg'], fontsize=10)
        self.efficiency_ax3.set_xlabel('Findings per Host', color=GUI_DARK_THEME['fg'])
        self.efficiency_ax3.set_ylabel('Host Count', color=GUI_DARK_THEME['fg'])

        # Chart 4: Resolution velocity with bucketed bars
        if 'status' in df.columns and 'days_open' in df.columns:
            resolved = df[df['status'] == 'Resolved']
            if not resolved.empty:
                days = resolved['days_open'].dropna()
                if len(days) > 0:
                    bins = [0, 7, 14, 30, 60, 90, max(days.max() + 1, 91)]
                    bin_labels = ['0-7d', '8-14d', '15-30d', '31-60d', '61-90d', '90+d']
                    hist, _ = np.histogram(days, bins=bins)
                    colors = ['#28a745', '#28a745', '#ffc107', '#ffc107', '#fd7e14', '#dc3545']
                    bars = self.efficiency_ax4.bar(range(len(hist)), hist, color=colors[:len(hist)])
                    self.efficiency_ax4.set_xticks(range(len(hist)))
                    self.efficiency_ax4.set_xticklabels(bin_labels[:len(hist)], fontsize=7)
                    if show_labels:
                        for bar, val in zip(bars, hist):
                            if val > 0:
                                self.efficiency_ax4.annotate(f'{int(val)}', xy=(bar.get_x() + bar.get_width()/2, val),
                                                            xytext=(0, 2), textcoords='offset points',
                                                            ha='center', va='bottom', fontsize=7, color='white')
                    # Average resolution time
                    days_numeric = pd.to_numeric(days, errors='coerce')
                    avg_days = days_numeric.mean()
                    self.efficiency_ax4.text(0.98, 0.98, f'Avg: {avg_days:.0f}d', transform=self.efficiency_ax4.transAxes,
                                            fontsize=8, va='top', ha='right', color='white')
        self.efficiency_ax4.set_title('Resolution Velocity', color=GUI_DARK_THEME['fg'], fontsize=10)
        self.efficiency_ax4.set_xlabel('Time to Resolve', color=GUI_DARK_THEME['fg'])
        self.efficiency_ax4.set_ylabel('Finding Count', color=GUI_DARK_THEME['fg'])

        for ax in [self.efficiency_ax1, self.efficiency_ax2, self.efficiency_ax3, self.efficiency_ax4]:
            ax.tick_params(colors=GUI_DARK_THEME['fg'])
            for spine in ax.spines.values():
                spine.set_color(GUI_DARK_THEME['fg'])

        self.efficiency_fig.tight_layout()
        self.efficiency_canvas.draw()

    def _update_network_charts(self):
        """Update network analysis visualizations."""
        if not HAS_MATPLOTLIB or not hasattr(self, 'network_ax1'):
            return

        df = self._get_chart_data('lifecycle')
        show_labels = self.settings_manager.settings.show_data_labels

        for ax in [self.network_ax1, self.network_ax2, self.network_ax3, self.network_ax4]:
            ax.clear()
            ax.set_facecolor(GUI_DARK_THEME['entry_bg'])

        # Try ip_address or ip column
        ip_col = 'ip_address' if 'ip_address' in df.columns else 'ip' if 'ip' in df.columns else None
        if df.empty or ip_col is None:
            self.network_canvas.draw()
            return

        # Extract subnet from IP
        def get_subnet(ip):
            if pd.isna(ip) or not isinstance(ip, str):
                return 'Unknown'
            parts = ip.split('.')
            if len(parts) >= 3:
                return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            return 'Unknown'

        df = df.copy()
        df['subnet'] = df[ip_col].apply(get_subnet)

        # Chart 1: Top subnets with data labels
        subnet_counts = df.groupby('subnet').size().nlargest(10)
        if len(subnet_counts) > 0:
            bars = self.network_ax1.barh(range(len(subnet_counts)), subnet_counts.values, color='#007bff')
            self.network_ax1.set_yticks(range(len(subnet_counts)))
            self.network_ax1.set_yticklabels([s[:18] for s in subnet_counts.index], fontsize=7)
            self.network_ax1.invert_yaxis()
            if show_labels:
                for bar, val in zip(bars, subnet_counts.values):
                    self.network_ax1.annotate(f'{int(val)}', xy=(val, bar.get_y() + bar.get_height()/2),
                                             xytext=(3, 0), textcoords='offset points',
                                             ha='left', va='center', fontsize=6, color='white')
        self.network_ax1.set_title('Top Subnets by Vulnerability', color=GUI_DARK_THEME['fg'], fontsize=10)
        self.network_ax1.set_xlabel('Vuln Count', color=GUI_DARK_THEME['fg'])

        # Chart 2: Subnet risk scores with gradient colors
        if 'severity_value' in df.columns:
            subnet_risk = df.groupby('subnet')['severity_value'].sum().nlargest(10)
            if len(subnet_risk) > 0:
                max_risk = subnet_risk.max()
                colors = ['#dc3545' if v > max_risk * 0.7 else '#fd7e14' if v > max_risk * 0.4 else '#ffc107'
                         for v in subnet_risk.values]
                bars = self.network_ax2.barh(range(len(subnet_risk)), subnet_risk.values, color=colors)
                self.network_ax2.set_yticks(range(len(subnet_risk)))
                self.network_ax2.set_yticklabels([s[:18] for s in subnet_risk.index], fontsize=7)
                self.network_ax2.invert_yaxis()
                if show_labels:
                    for bar, val in zip(bars, subnet_risk.values):
                        self.network_ax2.annotate(f'{int(val)}', xy=(val, bar.get_y() + bar.get_height()/2),
                                                 xytext=(3, 0), textcoords='offset points',
                                                 ha='left', va='center', fontsize=6, color='white')
        self.network_ax2.set_title('Subnet Risk Scores', color=GUI_DARK_THEME['fg'], fontsize=10)
        self.network_ax2.set_xlabel('Risk Score', color=GUI_DARK_THEME['fg'])

        # Chart 3: Host criticality distribution with stats
        if 'hostname' in df.columns and 'severity_value' in df.columns:
            host_crit = df.groupby('hostname')['severity_value'].sum()
            if len(host_crit) > 0:
                n, bins, patches = self.network_ax3.hist(host_crit, bins=15, color='#17a2b8', edgecolor='white', alpha=0.8)
                crit_numeric = pd.to_numeric(host_crit, errors='coerce')
                avg_risk = crit_numeric.mean()
                high_risk = (crit_numeric > crit_numeric.quantile(0.9)).sum()
                self.network_ax3.axvline(x=avg_risk, color='white', linestyle='--', linewidth=1, alpha=0.7)
                self.network_ax3.text(0.98, 0.98, f'Avg: {avg_risk:.0f} | High Risk: {high_risk}',
                                     transform=self.network_ax3.transAxes, fontsize=7, va='top', ha='right', color='white')
        self.network_ax3.set_title('Host Criticality Distribution', color=GUI_DARK_THEME['fg'], fontsize=10)
        self.network_ax3.set_xlabel('Risk Score', color=GUI_DARK_THEME['fg'])
        self.network_ax3.set_ylabel('Host Count', color=GUI_DARK_THEME['fg'])

        # Chart 4: Environment distribution (Production/PSS/Shared)
        if 'hostname' in df.columns:
            env_df = self._add_environment_column(df)
            env_counts = env_df['environment_type'].value_counts()
            # Define consistent colors and order
            env_order = ['Production', 'PSS', 'Shared', 'Unknown']
            env_colors = {'Production': '#28a745', 'PSS': '#007bff', 'Shared': '#ffc107', 'Unknown': '#6c757d'}
            # Filter and order
            env_counts = env_counts.reindex([e for e in env_order if e in env_counts.index])
            if len(env_counts) > 0:
                colors = [env_colors.get(e, '#6c757d') for e in env_counts.index]
                labels = [f'{idx}\n({val})' for idx, val in zip(env_counts.index, env_counts.values)]
                self.network_ax4.pie(env_counts.values, labels=labels, colors=colors,
                                    autopct='%1.1f%%', textprops={'color': 'white', 'fontsize': 8})
        self.network_ax4.set_title('Environment Distribution', color=GUI_DARK_THEME['fg'], fontsize=10)

        for ax in [self.network_ax1, self.network_ax2, self.network_ax3, self.network_ax4]:
            ax.tick_params(colors=GUI_DARK_THEME['fg'])
            for spine in ax.spines.values():
                spine.set_color(GUI_DARK_THEME['fg'])

        self.network_fig.tight_layout()
        self.network_canvas.draw()

    def _update_plugin_charts(self):
        """Update plugin analysis visualizations."""
        if not HAS_MATPLOTLIB or not hasattr(self, 'plugin_ax1'):
            return

        df = self._get_chart_data('lifecycle')
        show_labels = self.settings_manager.settings.show_data_labels

        for ax in [self.plugin_ax1, self.plugin_ax2, self.plugin_ax3, self.plugin_ax4]:
            ax.clear()
            ax.set_facecolor(GUI_DARK_THEME['entry_bg'])

        if df.empty:
            self.plugin_canvas.draw()
            return

        # Chart 1: Top 5 plugins per environment (embedded view)
        # Store plugin ID -> name mapping for hover tooltips
        self._plugin_name_map = {}
        if 'plugin_id' in df.columns and 'hostname' in df.columns:
            env_colors = {'Production': '#28a745', 'PSS': '#007bff', 'Shared': '#ffc107', 'Unknown': '#6c757d'}
            env_types = self.settings_manager.settings.environment_types if hasattr(self, 'settings_manager') else ['Production', 'PSS', 'Shared']

            # Get plugin names for tooltip lookup
            if 'plugin_name' in df.columns:
                names = df.groupby('plugin_id')['plugin_name'].first()
                for pid in df['plugin_id'].unique():
                    self._plugin_name_map[str(pid)] = str(names.get(pid, 'Unknown'))

            all_plugins = []
            for env in env_types:
                env_df = df[df['hostname'].apply(lambda h: self._get_environment_type(h) == env)]
                if not env_df.empty:
                    plugin_counts = env_df.groupby('plugin_id').size().nlargest(5)
                    for pid, count in plugin_counts.items():
                        all_plugins.append({'plugin_id': pid, 'count': count, 'env': env})

            if all_plugins:
                # Sort by environment then by count descending
                all_plugins.sort(key=lambda x: (env_types.index(x['env']) if x['env'] in env_types else 99, -x['count']))
                labels = [str(p['plugin_id']) for p in all_plugins]
                counts = [p['count'] for p in all_plugins]
                colors = [env_colors.get(p['env'], '#6c757d') for p in all_plugins]

                bars = self.plugin_ax1.barh(range(len(all_plugins)), counts, color=colors)
                self.plugin_ax1.set_yticks(range(len(all_plugins)))
                self.plugin_ax1.set_yticklabels(labels, fontsize=5)
                self.plugin_ax1.invert_yaxis()
                if show_labels:
                    for bar, val in zip(bars, counts):
                        self.plugin_ax1.annotate(f'{int(val)}', xy=(val, bar.get_y() + bar.get_height()/2),
                                                xytext=(3, 0), textcoords='offset points',
                                                ha='left', va='center', fontsize=5, color='white')
                # Add legend
                from matplotlib.patches import Patch
                legend_elements = [Patch(facecolor=env_colors.get(e, '#6c757d'), label=e[:4]) for e in env_types if e in [p['env'] for p in all_plugins]]
                if legend_elements:
                    self.plugin_ax1.legend(handles=legend_elements, loc='lower right', fontsize=5,
                                          facecolor=GUI_DARK_THEME['bg'], labelcolor=GUI_DARK_THEME['fg'])
        self.plugin_ax1.set_title('Top Plugins by Environment', color=GUI_DARK_THEME['fg'], fontsize=10)
        self.plugin_ax1.set_xlabel('Finding Count', color=GUI_DARK_THEME['fg'])

        # Chart 2: Plugin severity distribution with data labels
        sev_col = 'severity_text' if 'severity_text' in df.columns else 'severity' if 'severity' in df.columns else None
        if 'plugin_id' in df.columns and sev_col:
            plugin_severity = df.groupby(['plugin_id', sev_col]).size().unstack(fill_value=0)
            severity_totals = {}
            severity_order = ['Critical', 'High', 'Medium', 'Low', 'Info']
            for sev in severity_order:
                if sev in plugin_severity.columns:
                    severity_totals[sev] = plugin_severity[sev].sum()
            if severity_totals:
                colors = {'Critical': '#dc3545', 'High': '#fd7e14', 'Medium': '#ffc107', 'Low': '#007bff', 'Info': '#6c757d'}
                bar_colors = [colors.get(s, 'gray') for s in severity_totals.keys()]
                bars = self.plugin_ax2.bar(range(len(severity_totals)), list(severity_totals.values()), color=bar_colors)
                self.plugin_ax2.set_xticks(range(len(severity_totals)))
                self.plugin_ax2.set_xticklabels(list(severity_totals.keys()), fontsize=8)
                if show_labels:
                    for bar, val in zip(bars, severity_totals.values()):
                        self.plugin_ax2.annotate(f'{int(val)}', xy=(bar.get_x() + bar.get_width()/2, val),
                                                xytext=(0, 3), textcoords='offset points',
                                                ha='center', va='bottom', fontsize=7, color='white')
        self.plugin_ax2.set_title('Findings by Severity', color=GUI_DARK_THEME['fg'], fontsize=10)
        self.plugin_ax2.set_ylabel('Count', color=GUI_DARK_THEME['fg'])

        # Chart 3: Plugins affecting most hosts with data labels
        if 'plugin_id' in df.columns and 'hostname' in df.columns:
            plugin_hosts = df.groupby('plugin_id')['hostname'].nunique().nlargest(10)
            if len(plugin_hosts) > 0:
                # Add to plugin name map for hover
                if 'plugin_name' in df.columns:
                    names = df.groupby('plugin_id')['plugin_name'].first()
                    for pid in plugin_hosts.index:
                        if str(pid) not in self._plugin_name_map:
                            self._plugin_name_map[str(pid)] = str(names.get(pid, 'Unknown'))
                # Use plugin IDs as labels
                labels = [str(pid) for pid in plugin_hosts.index]
                bars = self.plugin_ax3.barh(range(len(plugin_hosts)), plugin_hosts.values, color='#17a2b8')
                self.plugin_ax3.set_yticks(range(len(plugin_hosts)))
                self.plugin_ax3.set_yticklabels(labels, fontsize=6)
                self.plugin_ax3.invert_yaxis()
                if show_labels:
                    for bar, val in zip(bars, plugin_hosts.values):
                        self.plugin_ax3.annotate(f'{int(val)}', xy=(val, bar.get_y() + bar.get_height()/2),
                                                xytext=(3, 0), textcoords='offset points',
                                                ha='left', va='center', fontsize=6, color='white')
        self.plugin_ax3.set_title('Plugins Most Hosts (hover)', color=GUI_DARK_THEME['fg'], fontsize=10)
        self.plugin_ax3.set_xlabel('Host Count', color=GUI_DARK_THEME['fg'])

        # Chart 4: Plugin average age with color coding
        if 'plugin_id' in df.columns and 'days_open' in df.columns:
            df_age = df.copy()
            df_age['days_open'] = pd.to_numeric(df_age['days_open'], errors='coerce')
            plugin_age = df_age.groupby('plugin_id')['days_open'].mean().nlargest(10)
            if len(plugin_age) > 0:
                # Add to plugin name map for hover
                if 'plugin_name' in df.columns:
                    names = df.groupby('plugin_id')['plugin_name'].first()
                    for pid in plugin_age.index:
                        if str(pid) not in self._plugin_name_map:
                            self._plugin_name_map[str(pid)] = str(names.get(pid, 'Unknown'))
                # Use plugin IDs as labels
                labels = [str(pid) for pid in plugin_age.index]
                # Color by age severity
                colors = ['#dc3545' if a > 90 else '#fd7e14' if a > 30 else '#28a745' for a in plugin_age.values]
                bars = self.plugin_ax4.barh(range(len(plugin_age)), plugin_age.values, color=colors)
                self.plugin_ax4.set_yticks(range(len(plugin_age)))
                self.plugin_ax4.set_yticklabels(labels, fontsize=6)
                self.plugin_ax4.invert_yaxis()
                if show_labels:
                    for bar, val in zip(bars, plugin_age.values):
                        self.plugin_ax4.annotate(f'{int(val)}d', xy=(val, bar.get_y() + bar.get_height()/2),
                                                xytext=(3, 0), textcoords='offset points',
                                                ha='left', va='center', fontsize=6, color='white')
        self.plugin_ax4.set_title('Longest Avg Age (hover)', color=GUI_DARK_THEME['fg'], fontsize=10)
        self.plugin_ax4.set_xlabel('Days Open', color=GUI_DARK_THEME['fg'])

        for ax in [self.plugin_ax1, self.plugin_ax2, self.plugin_ax3, self.plugin_ax4]:
            ax.tick_params(colors=GUI_DARK_THEME['fg'])
            for spine in ax.spines.values():
                spine.set_color(GUI_DARK_THEME['fg'])

        self.plugin_fig.tight_layout()
        self.plugin_canvas.draw()

    def _show_plugin_tooltip(self, event, text: str):
        """Show tooltip near cursor with plugin information."""
        if self._plugin_tooltip:
            self._hide_plugin_tooltip()

        # Create tooltip window
        self._plugin_tooltip = tk.Toplevel(self.window)
        self._plugin_tooltip.wm_overrideredirect(True)

        # Position near cursor
        x = self.window.winfo_pointerx() + 15
        y = self.window.winfo_pointery() + 15
        self._plugin_tooltip.wm_geometry(f"+{x}+{y}")

        # Style tooltip
        self._plugin_tooltip.configure(bg='#ffffe0')
        label = tk.Label(self._plugin_tooltip, text=text, bg='#ffffe0', fg='black',
                        relief='solid', borderwidth=1, padx=5, pady=3,
                        font=('Arial', 9), justify='left', wraplength=300)
        label.pack()

    def _hide_plugin_tooltip(self):
        """Hide the plugin tooltip."""
        if self._plugin_tooltip:
            self._plugin_tooltip.destroy()
            self._plugin_tooltip = None

    def _update_priority_charts(self):
        """Update remediation priority visualizations (CVSS vs Age quadrant)."""
        if not HAS_MATPLOTLIB or not hasattr(self, 'priority_ax1'):
            return

        df = self._get_chart_data('lifecycle')
        show_labels = self.settings_manager.settings.show_data_labels

        for ax in [self.priority_ax1, self.priority_ax2, self.priority_ax3, self.priority_ax4]:
            ax.clear()
            ax.set_facecolor(GUI_DARK_THEME['entry_bg'])

        if df.empty:
            self.priority_canvas.draw()
            return

        # Only look at active findings for priority
        active_df = df[df['status'] == 'Active'].copy() if 'status' in df.columns else df.copy()

        # Calculate priority score (CVSS * days_open normalized)
        cvss_col = 'cvss3_base_score' if 'cvss3_base_score' in active_df.columns else 'cvss' if 'cvss' in active_df.columns else None
        if cvss_col and 'days_open' in active_df.columns:
            active_df['cvss'] = pd.to_numeric(active_df[cvss_col], errors='coerce').fillna(5.0)
            active_df['priority_score'] = active_df['cvss'] * (1 + active_df['days_open'] / 30)
        elif 'severity_value' in active_df.columns and 'days_open' in active_df.columns:
            active_df['cvss'] = active_df['severity_value'] * 2.5  # Approximate CVSS from severity
            active_df['priority_score'] = active_df['cvss'] * (1 + active_df['days_open'] / 30)
        else:
            active_df['cvss'] = 5.0
            active_df['priority_score'] = 5.0

        # Chart 1: CVSS vs Days Open scatter (Priority Matrix) with quadrant counts
        if 'days_open' in active_df.columns and len(active_df) > 0:
            sample_df = active_df.head(500)  # Limit for performance
            colors = sample_df['priority_score'].values if 'priority_score' in sample_df.columns else 'red'
            scatter = self.priority_ax1.scatter(
                sample_df['days_open'], sample_df['cvss'],
                c=colors, cmap='RdYlGn_r', alpha=0.6, s=25
            )
            # Draw quadrant lines
            self.priority_ax1.axhline(y=7.0, color='white', linestyle='--', alpha=0.5, linewidth=1)
            self.priority_ax1.axvline(x=30, color='white', linestyle='--', alpha=0.5, linewidth=1)
            # Count findings in each quadrant
            urgent = len(active_df[(active_df['cvss'] >= 7) & (active_df['days_open'] > 30)])
            critical = len(active_df[(active_df['cvss'] >= 7) & (active_df['days_open'] <= 30)])
            schedule = len(active_df[(active_df['cvss'] < 7) & (active_df['days_open'] > 30)])
            monitor = len(active_df[(active_df['cvss'] < 7) & (active_df['days_open'] <= 30)])
            # Label quadrants with counts
            self.priority_ax1.text(0.02, 0.98, f'HIGH ({critical})', fontsize=8, color='#dc3545',
                                  transform=self.priority_ax1.transAxes, va='top')
            self.priority_ax1.text(0.98, 0.98, f'URGENT ({urgent})', fontsize=8, color='#fd7e14',
                                  transform=self.priority_ax1.transAxes, va='top', ha='right')
            self.priority_ax1.text(0.02, 0.02, f'Monitor ({monitor})', fontsize=8, color='#28a745',
                                  transform=self.priority_ax1.transAxes, va='bottom')
            self.priority_ax1.text(0.98, 0.02, f'Schedule ({schedule})', fontsize=8, color='#ffc107',
                                  transform=self.priority_ax1.transAxes, va='bottom', ha='right')
        self.priority_ax1.set_title('Priority Matrix (CVSS vs Age)', color=GUI_DARK_THEME['fg'], fontsize=10)
        self.priority_ax1.set_xlabel('Days Open', color=GUI_DARK_THEME['fg'])
        self.priority_ax1.set_ylabel('CVSS Score', color=GUI_DARK_THEME['fg'])

        # Chart 2: Priority distribution pie with counts
        if 'priority_score' in active_df.columns and len(active_df) > 0:
            def categorize_priority(score):
                if score >= 50:
                    return 'Critical'
                elif score >= 30:
                    return 'High'
                elif score >= 15:
                    return 'Medium'
                else:
                    return 'Low'
            priority_cats = active_df['priority_score'].apply(categorize_priority).value_counts()
            priority_order = ['Critical', 'High', 'Medium', 'Low']
            priority_cats = priority_cats.reindex([p for p in priority_order if p in priority_cats.index])
            colors = {'Critical': '#dc3545', 'High': '#fd7e14', 'Medium': '#ffc107', 'Low': '#28a745'}
            pie_colors = [colors.get(c, 'gray') for c in priority_cats.index]
            labels = [f'{idx}\n({val})' for idx, val in zip(priority_cats.index, priority_cats.values)]
            self.priority_ax2.pie(priority_cats.values, labels=labels, colors=pie_colors,
                                 autopct='%1.1f%%', textprops={'color': 'white', 'fontsize': 8})
        self.priority_ax2.set_title('Priority Distribution', color=GUI_DARK_THEME['fg'], fontsize=10)

        # Chart 3: Top 10 priority findings with data labels
        if 'priority_score' in active_df.columns and len(active_df) > 0:
            top_priority = active_df.nlargest(10, 'priority_score')
            if 'hostname' in top_priority.columns and 'plugin_id' in top_priority.columns:
                labels = [f"{row['hostname'][:8]}-{row['plugin_id']}" for _, row in top_priority.iterrows()]
            else:
                labels = [str(i) for i in range(len(top_priority))]
            bars = self.priority_ax3.barh(range(len(top_priority)), top_priority['priority_score'].values, color='#dc3545')
            self.priority_ax3.set_yticks(range(len(top_priority)))
            self.priority_ax3.set_yticklabels(labels, fontsize=6)
            self.priority_ax3.invert_yaxis()
            if show_labels:
                for bar, val in zip(bars, top_priority['priority_score'].values):
                    self.priority_ax3.annotate(f'{val:.0f}', xy=(val, bar.get_y() + bar.get_height()/2),
                                              xytext=(3, 0), textcoords='offset points',
                                              ha='left', va='center', fontsize=6, color='white')
        self.priority_ax3.set_title('Top 10 Priority Findings', color=GUI_DARK_THEME['fg'], fontsize=10)
        self.priority_ax3.set_xlabel('Priority Score', color=GUI_DARK_THEME['fg'])

        # Chart 4: Priority by severity with data labels
        sev_col = 'severity_text' if 'severity_text' in active_df.columns else 'severity' if 'severity' in active_df.columns else None
        if 'priority_score' in active_df.columns and sev_col:
            active_df_numeric = active_df.copy()
            active_df_numeric['priority_score'] = pd.to_numeric(active_df_numeric['priority_score'], errors='coerce')
            sev_priority = active_df_numeric.groupby(sev_col)['priority_score'].mean()
            sev_order = ['Critical', 'High', 'Medium', 'Low', 'Info']
            sev_priority = sev_priority.reindex([s for s in sev_order if s in sev_priority.index])
            if len(sev_priority) > 0:
                colors = {'Critical': '#dc3545', 'High': '#fd7e14', 'Medium': '#ffc107', 'Low': '#007bff', 'Info': '#6c757d'}
                bar_colors = [colors.get(s, 'gray') for s in sev_priority.index]
                bars = self.priority_ax4.bar(range(len(sev_priority)), sev_priority.values, color=bar_colors)
                self.priority_ax4.set_xticks(range(len(sev_priority)))
                self.priority_ax4.set_xticklabels(sev_priority.index, fontsize=8)
                if show_labels:
                    for bar, val in zip(bars, sev_priority.values):
                        self.priority_ax4.annotate(f'{val:.1f}', xy=(bar.get_x() + bar.get_width()/2, val),
                                                  xytext=(0, 3), textcoords='offset points',
                                                  ha='center', va='bottom', fontsize=7, color='white')
        self.priority_ax4.set_title('Avg Priority by Severity', color=GUI_DARK_THEME['fg'], fontsize=10)
        self.priority_ax4.set_ylabel('Priority Score', color=GUI_DARK_THEME['fg'])

        for ax in [self.priority_ax1, self.priority_ax2, self.priority_ax3, self.priority_ax4]:
            ax.tick_params(colors=GUI_DARK_THEME['fg'])
            for spine in ax.spines.values():
                spine.set_color(GUI_DARK_THEME['fg'])

        self.priority_fig.tight_layout()
        self.priority_canvas.draw()

    def _calculate_sla_status(self, row):
        """Calculate SLA status for a finding based on severity and days open."""
        severity = row.get('severity_text', 'Info')
        days_open = row.get('days_open', 0)

        target = SLA_TARGETS_DAYS.get(severity)
        if target is None:
            return SLA_STATUS_NO_SLA, None, None

        days_remaining = target - days_open
        if days_remaining < 0:
            return SLA_STATUS_OVERDUE, days_remaining, target
        elif days_remaining <= target * SLA_WARNING_THRESHOLD:
            return SLA_STATUS_APPROACHING, days_remaining, target
        else:
            return SLA_STATUS_ON_TRACK, days_remaining, target

    def _update_sla_charts(self):
        """Update SLA compliance visualizations."""
        if not HAS_MATPLOTLIB or not hasattr(self, 'sla_ax1'):
            return

        df = self._get_chart_data('lifecycle')

        for ax in [self.sla_ax1, self.sla_ax2, self.sla_ax3, self.sla_ax4]:
            ax.clear()
            ax.set_facecolor(GUI_DARK_THEME['entry_bg'])

        if df.empty:
            self.sla_canvas.draw()
            return

        # Only active findings for SLA
        active_df = df[df['status'] == 'Active'].copy() if 'status' in df.columns else df.copy()

        if active_df.empty:
            self.sla_canvas.draw()
            return

        # Check if data labels are enabled
        show_labels = self.settings_manager.settings.show_data_labels

        # Calculate SLA status for each finding
        sla_data = active_df.apply(lambda row: self._calculate_sla_status(row), axis=1)
        active_df['sla_status'] = [x[0] for x in sla_data]
        active_df['days_remaining'] = [x[1] for x in sla_data]
        active_df['sla_target'] = [x[2] for x in sla_data]

        # Chart 1: SLA Status overview (pie)
        status_counts = active_df['sla_status'].value_counts()
        if len(status_counts) > 0:
            colors = [SLA_STATUS_COLORS.get(s, '#6c757d') for s in status_counts.index]

            # Create labels with counts if enabled
            if show_labels:
                pie_labels = [f'{s}\n({c})' for s, c in zip(status_counts.index, status_counts.values)]
            else:
                pie_labels = list(status_counts.index)

            wedges, texts, autotexts = self.sla_ax1.pie(
                status_counts.values, labels=pie_labels, colors=colors,
                autopct='%1.1f%%', textprops={'color': GUI_DARK_THEME['fg'], 'fontsize': 8})

            # Style autopct text
            for autotext in autotexts:
                autotext.set_fontsize(7)
                autotext.set_fontweight('bold')

            # Add total count in center
            total_active = len(active_df)
            self.sla_ax1.text(0, 0, f'{total_active}\nactive',
                ha='center', va='center', fontsize=9, fontweight='bold',
                color=GUI_DARK_THEME['fg'])
        self.sla_ax1.set_title('SLA Compliance Status', color=GUI_DARK_THEME['fg'], fontsize=10)
        self.sla_ax1.text(0.5, -0.05, 'Overall SLA compliance breakdown',
            transform=self.sla_ax1.transAxes, ha='center', va='top', fontsize=7, color='#888888')

        # Chart 2: Overdue by severity
        overdue = active_df[active_df['sla_status'] == SLA_STATUS_OVERDUE]
        if not overdue.empty and 'severity_text' in overdue.columns:
            overdue_by_sev = overdue['severity_text'].value_counts()
            sev_order = ['Critical', 'High', 'Medium', 'Low']
            overdue_by_sev = overdue_by_sev.reindex([s for s in sev_order if s in overdue_by_sev.index])
            if len(overdue_by_sev) > 0:
                colors = {'Critical': '#dc3545', 'High': '#fd7e14', 'Medium': '#ffc107', 'Low': '#007bff'}
                bar_colors = [colors.get(s, 'gray') for s in overdue_by_sev.index]
                bars = self.sla_ax2.bar(range(len(overdue_by_sev)), overdue_by_sev.values, color=bar_colors)
                self.sla_ax2.set_xticks(range(len(overdue_by_sev)))
                self.sla_ax2.set_xticklabels(overdue_by_sev.index, fontsize=9)

                # Add data labels
                if show_labels:
                    for bar, val in zip(bars, overdue_by_sev.values):
                        self.sla_ax2.annotate(f'{int(val)}',
                            xy=(bar.get_x() + bar.get_width()/2, val),
                            xytext=(0, 3), textcoords='offset points',
                            ha='center', va='bottom', fontsize=8, color='white', fontweight='bold')
        self.sla_ax2.set_title(f'Overdue Findings ({len(overdue)} total)', color=GUI_DARK_THEME['fg'], fontsize=10)
        self.sla_ax2.set_ylabel('Count', color=GUI_DARK_THEME['fg'])

        # Chart 3: Approaching deadline - show findings closest to SLA breach
        approaching = active_df[active_df['sla_status'] == SLA_STATUS_APPROACHING].copy()
        if not approaching.empty:
            approaching = approaching.nsmallest(15, 'days_remaining')
            if 'hostname' in approaching.columns and 'severity_text' in approaching.columns:
                labels = [f"{row['hostname'][:12]} ({row['severity_text'][:1]})" for _, row in approaching.iterrows()]
            else:
                labels = [str(i) for i in range(len(approaching))]
            days_vals = approaching['days_remaining'].values
            colors = ['#ffc107' if d > 0 else '#dc3545' for d in days_vals]
            bars = self.sla_ax3.barh(range(len(approaching)), days_vals, color=colors)
            self.sla_ax3.set_yticks(range(len(approaching)))
            self.sla_ax3.set_yticklabels(labels, fontsize=7)
            self.sla_ax3.axvline(x=0, color='#dc3545', linestyle='-', linewidth=2)

            # Add data labels
            if show_labels:
                for bar, val in zip(bars, days_vals):
                    label_x = val if val >= 0 else val
                    ha = 'left' if val >= 0 else 'right'
                    offset = (3, 0) if val >= 0 else (-3, 0)
                    self.sla_ax3.annotate(f'{int(val)}d',
                        xy=(val, bar.get_y() + bar.get_height()/2),
                        xytext=offset, textcoords='offset points',
                        ha=ha, va='center', fontsize=7, color='white')

            # Add urgency indicator
            critical_approaching = len(approaching[approaching['days_remaining'] <= 3])
            if critical_approaching > 0:
                self.sla_ax3.text(0.98, 0.98, f'⚠ {critical_approaching} due in ≤3 days',
                    transform=self.sla_ax3.transAxes, fontsize=7, color='#ff6b6b',
                    ha='right', va='top', fontweight='bold')
        self.sla_ax3.set_title(f'Approaching Deadline ({len(approaching)} findings)', color=GUI_DARK_THEME['fg'], fontsize=10)
        self.sla_ax3.set_xlabel('Days Until SLA Breach', color=GUI_DARK_THEME['fg'])

        # Chart 4: Days until/past SLA distribution
        has_sla = active_df[active_df['sla_status'] != SLA_STATUS_NO_SLA]
        if not has_sla.empty and 'days_remaining' in has_sla.columns:
            days_vals = has_sla['days_remaining'].dropna()
            if len(days_vals) > 0:
                # Color by positive (green) or negative (red)
                bins = list(range(int(days_vals.min()) - 5, int(days_vals.max()) + 5, 5))
                if len(bins) < 2:
                    bins = [-30, -15, 0, 15, 30, 45, 60]
                n, bins_out, patches = self.sla_ax4.hist(days_vals, bins=bins, edgecolor='white')
                for i, patch in enumerate(patches):
                    if bins_out[i] < 0:
                        patch.set_facecolor('#dc3545')  # Overdue - red
                    elif bins_out[i] < 10:
                        patch.set_facecolor('#ffc107')  # Approaching - yellow
                    else:
                        patch.set_facecolor('#28a745')  # On track - green
                self.sla_ax4.axvline(x=0, color='white', linestyle='--', linewidth=2)

                # Add data labels on histogram bars
                if show_labels:
                    for patch, count in zip(patches, n):
                        if count > 0:
                            height = patch.get_height()
                            x = patch.get_x() + patch.get_width() / 2
                            self.sla_ax4.annotate(f'{int(count)}',
                                xy=(x, height), xytext=(0, 2), textcoords='offset points',
                                ha='center', va='bottom', fontsize=6, color='white')

                # Add summary stats
                overdue_count = len(days_vals[days_vals < 0])
                on_track_count = len(days_vals[days_vals >= 0])
                self.sla_ax4.text(0.02, 0.98, f'Overdue: {overdue_count}',
                    transform=self.sla_ax4.transAxes, fontsize=7, color='#dc3545',
                    ha='left', va='top', fontweight='bold')
                self.sla_ax4.text(0.98, 0.98, f'On track: {on_track_count}',
                    transform=self.sla_ax4.transAxes, fontsize=7, color='#28a745',
                    ha='right', va='top', fontweight='bold')
        self.sla_ax4.set_title('Days Until/Past SLA Distribution', color=GUI_DARK_THEME['fg'], fontsize=10)
        self.sla_ax4.set_xlabel('Days (negative = overdue)', color=GUI_DARK_THEME['fg'])
        self.sla_ax4.set_ylabel('Finding Count', color=GUI_DARK_THEME['fg'])

        for ax in [self.sla_ax1, self.sla_ax2, self.sla_ax3, self.sla_ax4]:
            ax.tick_params(colors=GUI_DARK_THEME['fg'])
            for spine in ax.spines.values():
                spine.set_color(GUI_DARK_THEME['fg'])

        self.sla_fig.tight_layout()
        self.sla_canvas.draw()

    def _update_host_tracking_charts(self):
        """Update host tracking visualizations."""
        if not HAS_MATPLOTLIB or not hasattr(self, 'host_tracking_ax1'):
            return

        host_df = self.filtered_host_df if not self.filtered_host_df.empty else self.host_presence_df
        hist_df = self._get_chart_data('historical')

        for ax in [self.host_tracking_ax1, self.host_tracking_ax2, self.host_tracking_ax3, self.host_tracking_ax4]:
            ax.clear()
            ax.set_facecolor(GUI_DARK_THEME['entry_bg'])

        if host_df.empty:
            self.host_tracking_canvas.draw()
            return

        # Check if data labels are enabled
        show_labels = self.settings_manager.settings.show_data_labels

        # Chart 1: Hosts missing from recent scans
        if 'status' in host_df.columns:
            missing = host_df[host_df['status'] != 'Active']
            if not missing.empty and 'last_seen' in missing.columns:
                missing = missing.copy()
                missing['last_seen'] = pd.to_datetime(missing['last_seen'])
                missing = missing.nlargest(15, 'last_seen') if len(missing) > 15 else missing
                if 'hostname' in missing.columns:
                    labels = [str(h)[:15] for h in missing['hostname']]
                    # Days since last seen
                    days_missing = (pd.Timestamp.now() - missing['last_seen']).dt.days
                    bars = self.host_tracking_ax1.barh(range(len(missing)), days_missing.values, color='#dc3545')
                    self.host_tracking_ax1.set_yticks(range(len(missing)))
                    self.host_tracking_ax1.set_yticklabels(labels, fontsize=7)

                    # Add data labels
                    if show_labels:
                        for bar, val in zip(bars, days_missing.values):
                            self.host_tracking_ax1.annotate(f'{int(val)}d',
                                xy=(val, bar.get_y() + bar.get_height()/2),
                                xytext=(3, 0), textcoords='offset points',
                                ha='left', va='center', fontsize=7, color='white')

                    # Add summary stats
                    total_missing = len(host_df[host_df['status'] != 'Active'])
                    days_missing_numeric = pd.to_numeric(days_missing, errors='coerce')
                    avg_days = days_missing_numeric.mean() if len(days_missing_numeric) > 0 else 0
                    self.host_tracking_ax1.text(0.98, 0.98, f'Total: {total_missing} | Avg: {avg_days:.0f}d',
                        transform=self.host_tracking_ax1.transAxes, fontsize=7, color='#ff6b6b',
                        ha='right', va='top')
        self.host_tracking_ax1.set_title('Hosts Missing from Recent Scans', color=GUI_DARK_THEME['fg'], fontsize=10)
        self.host_tracking_ax1.set_xlabel('Days Since Last Seen', color=GUI_DARK_THEME['fg'])

        # Chart 2: Host presence over time
        if not hist_df.empty and 'scan_date' in hist_df.columns and 'hostname' in hist_df.columns:
            hist_copy = hist_df.copy()
            hist_copy['scan_date'] = pd.to_datetime(hist_copy['scan_date'])
            hosts_per_scan = hist_copy.groupby(hist_copy['scan_date'].dt.date)['hostname'].nunique()
            if len(hosts_per_scan) > 0:
                line, = self.host_tracking_ax2.plot(range(len(hosts_per_scan)), hosts_per_scan.values, 'c-', marker='o', markersize=4)
                self.host_tracking_ax2.fill_between(range(len(hosts_per_scan)), hosts_per_scan.values, alpha=0.3, color='cyan')

                # Add data labels at key points
                if show_labels and len(hosts_per_scan) > 0:
                    # Label first, last, min, max
                    values = hosts_per_scan.values
                    indices_to_label = {0, len(values)-1}
                    if len(values) > 2:
                        indices_to_label.add(int(values.argmax()))
                        indices_to_label.add(int(values.argmin()))
                    for idx in indices_to_label:
                        self.host_tracking_ax2.annotate(f'{int(values[idx])}',
                            xy=(idx, values[idx]), xytext=(0, 5), textcoords='offset points',
                            ha='center', va='bottom', fontsize=7, color='cyan')

                # Add trend indicator
                if len(hosts_per_scan) > 1:
                    first_val = hosts_per_scan.iloc[0]
                    last_val = hosts_per_scan.iloc[-1]
                    if first_val > 0:
                        change = ((last_val - first_val) / first_val) * 100
                        arrow = '↑' if change > 0 else '↓' if change < 0 else '→'
                        color = '#28a745' if change >= 0 else '#dc3545'
                        self.host_tracking_ax2.text(0.98, 0.98, f'{arrow} {abs(change):.1f}%',
                            transform=self.host_tracking_ax2.transAxes, fontsize=8, color=color,
                            ha='right', va='top', fontweight='bold')
        self.host_tracking_ax2.set_title('Host Presence Over Time', color=GUI_DARK_THEME['fg'], fontsize=10)
        self.host_tracking_ax2.set_ylabel('Unique Hosts', color=GUI_DARK_THEME['fg'])

        # Chart 3: Hosts with declining presence (low presence %)
        if 'presence_percentage' in host_df.columns:
            low_presence = host_df[host_df['presence_percentage'] < 50].nsmallest(15, 'presence_percentage')
            if not low_presence.empty and 'hostname' in low_presence.columns:
                labels = [str(h)[:15] for h in low_presence['hostname']]
                presence_vals = low_presence['presence_percentage'].values

                # Color gradient based on presence percentage
                colors = ['#dc3545' if p < 25 else '#ffc107' for p in presence_vals]
                bars = self.host_tracking_ax3.barh(range(len(low_presence)), presence_vals, color=colors)
                self.host_tracking_ax3.set_yticks(range(len(low_presence)))
                self.host_tracking_ax3.set_yticklabels(labels, fontsize=7)
                self.host_tracking_ax3.axvline(x=50, color='#dc3545', linestyle='--', alpha=0.7, label='Threshold')

                # Add data labels
                if show_labels:
                    for bar, val in zip(bars, presence_vals):
                        self.host_tracking_ax3.annotate(f'{val:.1f}%',
                            xy=(val, bar.get_y() + bar.get_height()/2),
                            xytext=(3, 0), textcoords='offset points',
                            ha='left', va='center', fontsize=7, color='white')

                # Add summary
                total_low = len(host_df[host_df['presence_percentage'] < 50])
                critical_low = len(host_df[host_df['presence_percentage'] < 25])
                self.host_tracking_ax3.text(0.98, 0.02, f'<50%: {total_low} | <25%: {critical_low}',
                    transform=self.host_tracking_ax3.transAxes, fontsize=7, color='#ffc107',
                    ha='right', va='bottom')
        self.host_tracking_ax3.set_title('Hosts with Low Presence (<50%)', color=GUI_DARK_THEME['fg'], fontsize=10)
        self.host_tracking_ax3.set_xlabel('Presence %', color=GUI_DARK_THEME['fg'])

        # Chart 4: Host status distribution
        if 'status' in host_df.columns:
            status_counts = host_df['status'].value_counts()
            if len(status_counts) > 0:
                colors = {'Active': '#28a745', 'Inactive': '#dc3545', 'Intermittent': '#ffc107'}
                pie_colors = [colors.get(s, '#6c757d') for s in status_counts.index]

                # Create labels with counts
                if show_labels:
                    pie_labels = [f'{s}\n({c})' for s, c in zip(status_counts.index, status_counts.values)]
                else:
                    pie_labels = list(status_counts.index)

                wedges, texts, autotexts = self.host_tracking_ax4.pie(
                    status_counts.values, labels=pie_labels, colors=pie_colors,
                    autopct='%1.1f%%', textprops={'color': GUI_DARK_THEME['fg'], 'fontsize': 8})

                # Style autopct text
                for autotext in autotexts:
                    autotext.set_fontsize(7)
                    autotext.set_fontweight('bold')

                # Add total count in center
                total_hosts = len(host_df)
                self.host_tracking_ax4.text(0, 0, f'{total_hosts}\nhosts',
                    ha='center', va='center', fontsize=9, fontweight='bold',
                    color=GUI_DARK_THEME['fg'])
        self.host_tracking_ax4.set_title('Host Status Distribution', color=GUI_DARK_THEME['fg'], fontsize=10)
        self.host_tracking_ax4.text(0.5, -0.05, 'Active/Inactive/Intermittent host counts',
            transform=self.host_tracking_ax4.transAxes, ha='center', va='top', fontsize=7, color='#888888')

        for ax in [self.host_tracking_ax1, self.host_tracking_ax2, self.host_tracking_ax3, self.host_tracking_ax4]:
            ax.tick_params(colors=GUI_DARK_THEME['fg'])
            for spine in ax.spines.values():
                spine.set_color(GUI_DARK_THEME['fg'])

        self.host_tracking_fig.tight_layout()
        self.host_tracking_canvas.draw()

    def _update_metrics_charts(self):
        """Update advanced metrics visualizations with industry KPIs.

        Uses smart filtering: Remediation rate metrics always include both
        Active and Remediated findings regardless of status filter.
        """
        if not HAS_MATPLOTLIB or not hasattr(self, 'metrics_ax1'):
            return

        # Regular filtered data for display
        df = self._get_chart_data('lifecycle')
        hist_df = self._get_chart_data('historical')

        # Smart filtered data for metrics that need both statuses
        # Remediation rate MUST include both Active and Remediated to calculate properly
        df_all_statuses = self._get_chart_data('lifecycle', smart_filter='all_statuses')
        hist_df_all_statuses = self._get_chart_data('historical', smart_filter='all_statuses')

        for ax in [self.metrics_ax1, self.metrics_ax2, self.metrics_ax3, self.metrics_ax4]:
            ax.clear()
            ax.set_facecolor(GUI_DARK_THEME['entry_bg'])

        if df_all_statuses.empty:
            # Reset KPI labels
            for key in self.kpi_labels:
                self.kpi_labels[key].config(text="--")
            self.metrics_canvas.draw()
            return

        # Get SLA targets from settings
        sla_targets = self.settings_manager.settings.get_sla_targets()
        sla_targets = {k: v for k, v in sla_targets.items() if v is not None}

        # Calculate metrics using smart filtered data (both statuses)
        reopen_metrics = calculate_reopen_rate(df_all_statuses)
        remediation_metrics = calculate_remediation_rate(df_all_statuses, hist_df_all_statuses)
        sla_metrics = calculate_sla_breach_tracking(df, sla_targets)
        normalized_metrics = calculate_normalized_metrics(hist_df, df)
        risk_trend = calculate_risk_reduction_trend(hist_df)

        # Update KPI labels
        self.kpi_labels['reopen_rate'].config(text=f"{reopen_metrics['reopen_rate_pct']}%")
        self.kpi_labels['remediation_rate'].config(text=f"{remediation_metrics['remediation_rate_pct']}%")
        self.kpi_labels['breach_rate'].config(text=f"{sla_metrics['breach_rate_pct']}%")
        self.kpi_labels['vulns_per_host'].config(text=f"{normalized_metrics['vulns_per_host']}")
        # Coverage defaults to 100% when no expected hosts list
        coverage_pct = calculate_coverage_metrics(hist_df).get('coverage_pct', 100.0)
        self.kpi_labels['coverage'].config(text=f"{coverage_pct}%")

        # Check if data labels are enabled
        show_labels = self.settings_manager.settings.show_data_labels

        # Chart 1: Remediation Rate by Severity (stacked bar)
        by_sev = remediation_metrics.get('by_severity', {})
        if by_sev:
            severities = ['Critical', 'High', 'Medium', 'Low']
            discovered = [by_sev.get(s, {}).get('discovered', 0) for s in severities]
            remediated = [by_sev.get(s, {}).get('remediated', 0) for s in severities]
            active = [by_sev.get(s, {}).get('active', 0) for s in severities]

            x = range(len(severities))
            width = 0.35
            bars1 = self.metrics_ax1.bar([i - width/2 for i in x], remediated, width, label='Remediated', color='#28a745')
            bars2 = self.metrics_ax1.bar([i + width/2 for i in x], active, width, label='Active', color='#dc3545')
            self.metrics_ax1.set_xticks(x)
            self.metrics_ax1.set_xticklabels(severities, fontsize=8)
            self.metrics_ax1.legend(loc='upper right', fontsize=7)

            # Add data labels if enabled
            if show_labels:
                add_data_labels(self.metrics_ax1, bars1, fontsize=6)
                add_data_labels(self.metrics_ax1, bars2, fontsize=6)

        self.metrics_ax1.set_title('Remediation Status by Severity', color=GUI_DARK_THEME['fg'], fontsize=10)
        self.metrics_ax1.set_ylabel('Count', color=GUI_DARK_THEME['fg'])

        # Chart 2: Risk Trend Over Time (line chart)
        if not risk_trend.empty and len(risk_trend) > 1:
            dates = risk_trend['scan_date']
            risk_scores = risk_trend['total_risk_score']
            self.metrics_ax2.plot(range(len(dates)), risk_scores, marker='o', color='#007bff', linewidth=2)
            self.metrics_ax2.fill_between(range(len(dates)), risk_scores, alpha=0.3, color='#007bff')

            # Show only few date labels to avoid crowding
            if len(dates) > 6:
                step = len(dates) // 6
                tick_positions = list(range(0, len(dates), step))
                self.metrics_ax2.set_xticks(tick_positions)
                tick_labels = [dates.iloc[i].strftime('%m/%d') if hasattr(dates.iloc[i], 'strftime') else str(dates.iloc[i])[:5] for i in tick_positions]
                self.metrics_ax2.set_xticklabels(tick_labels, fontsize=7, rotation=45)
            else:
                self.metrics_ax2.set_xticks(range(len(dates)))
                tick_labels = [d.strftime('%m/%d') if hasattr(d, 'strftime') else str(d)[:5] for d in dates]
                self.metrics_ax2.set_xticklabels(tick_labels, fontsize=7, rotation=45)
        self.metrics_ax2.set_title('Risk Score Trend', color=GUI_DARK_THEME['fg'], fontsize=10)
        self.metrics_ax2.set_ylabel('Risk Score', color=GUI_DARK_THEME['fg'])

        # Chart 3: SLA Status by Severity (stacked bar - breached/at_risk/on_track)
        sla_by_sev = sla_metrics.get('by_severity', {})
        if sla_by_sev:
            severities = ['Critical', 'High', 'Medium', 'Low']
            breached = [sla_by_sev.get(s, {}).get('breached', 0) for s in severities]
            at_risk = [sla_by_sev.get(s, {}).get('at_risk', 0) for s in severities]
            on_track = [sla_by_sev.get(s, {}).get('on_track', 0) for s in severities]

            x = range(len(severities))
            self.metrics_ax3.bar(x, breached, label='Breached', color='#dc3545')
            self.metrics_ax3.bar(x, at_risk, bottom=breached, label='At Risk', color='#ffc107')
            bottom_track = [b + r for b, r in zip(breached, at_risk)]
            self.metrics_ax3.bar(x, on_track, bottom=bottom_track, label='On Track', color='#28a745')
            self.metrics_ax3.set_xticks(x)
            self.metrics_ax3.set_xticklabels(severities, fontsize=8)
            self.metrics_ax3.legend(loc='upper right', fontsize=7)
        self.metrics_ax3.set_title('SLA Status by Severity', color=GUI_DARK_THEME['fg'], fontsize=10)
        self.metrics_ax3.set_ylabel('Count', color=GUI_DARK_THEME['fg'])

        # Chart 4: Vulns per Host Trend (line chart)
        norm_trend = normalized_metrics.get('trend', [])
        if norm_trend and len(norm_trend) > 1:
            dates = [t['scan_date'] for t in norm_trend]
            vpH = [t['vulns_per_host'] for t in norm_trend]
            self.metrics_ax4.plot(range(len(dates)), vpH, marker='s', color='#17a2b8', linewidth=2)

            # Show only few date labels
            if len(dates) > 6:
                step = len(dates) // 6
                tick_positions = list(range(0, len(dates), step))
                self.metrics_ax4.set_xticks(tick_positions)
                tick_labels = [dates[i][:5] for i in tick_positions]
                self.metrics_ax4.set_xticklabels(tick_labels, fontsize=7, rotation=45)
            else:
                self.metrics_ax4.set_xticks(range(len(dates)))
                self.metrics_ax4.set_xticklabels([d[:5] for d in dates], fontsize=7, rotation=45)
        self.metrics_ax4.set_title('Vulnerabilities per Host Trend', color=GUI_DARK_THEME['fg'], fontsize=10)
        self.metrics_ax4.set_ylabel('Vulns/Host', color=GUI_DARK_THEME['fg'])

        for ax in [self.metrics_ax1, self.metrics_ax2, self.metrics_ax3, self.metrics_ax4]:
            ax.tick_params(colors=GUI_DARK_THEME['fg'])
            for spine in ax.spines.values():
                spine.set_color(GUI_DARK_THEME['fg'])

        self.metrics_fig.tight_layout()
        self.metrics_canvas.draw()

    def _update_advanced_charts(self):
        """Update all advanced analytics visualizations."""
        if not HAS_MATPLOTLIB or not hasattr(self, 'heatmap_ax'):
            return

        df = self._get_chart_data('lifecycle')
        hist_df = self._get_chart_data('historical')
        show_labels = self.settings_manager.settings.show_data_labels

        # Clear all axes
        for ax in [self.heatmap_ax, self.bubble_ax, self.sankey_ax, self.treemap_ax,
                   self.gauge_ax, self.prediction_ax, self.comparison_ax]:
            ax.clear()
            ax.set_facecolor(GUI_DARK_THEME['entry_bg'])

        self.radar_ax.clear()
        self.radar_ax.set_facecolor(GUI_DARK_THEME['entry_bg'])

        if df.empty and hist_df.empty:
            for ax in [self.heatmap_ax, self.bubble_ax, self.sankey_ax, self.treemap_ax,
                       self.gauge_ax, self.prediction_ax, self.comparison_ax]:
                ax.text(0.5, 0.5, 'No data available', ha='center', va='center',
                       color=GUI_DARK_THEME['fg'], fontsize=10)
            self.advanced_canvas1.draw()
            self.advanced_canvas2.draw()
            self.advanced_canvas3.draw()
            self.advanced_canvas4.draw()
            return

        # ===== PAGE 1: Risk Analysis =====
        # Chart 1: Risk Heatmap by Subnet/Time
        self._draw_risk_heatmap(df, hist_df, show_labels)

        # Chart 2: Bubble Chart (CVSS vs Age vs Count)
        self._draw_bubble_chart(df, show_labels)

        self.advanced_fig1.tight_layout()
        self.advanced_canvas1.draw()

        # ===== PAGE 2: Composition =====
        # Chart 3: Vulnerability Lifecycle Sankey
        self._draw_sankey_diagram(df, hist_df, show_labels)

        # Chart 4: Plugin Family Treemap
        self._draw_treemap(df, show_labels)

        self.advanced_fig2.tight_layout()
        self.advanced_canvas2.draw()

        # ===== PAGE 3: Health Indicators =====
        # Chart 5: Radar Chart per Subnet
        self._draw_radar_chart(df, show_labels)

        # Chart 6: Remediation Velocity Gauge
        self._draw_velocity_gauge(df, hist_df, show_labels)

        self.advanced_fig3.tight_layout()
        self.advanced_canvas3.draw()

        # ===== PAGE 4: Trends & Prediction =====
        # Chart 7: SLA Breach Prediction
        self._draw_sla_prediction(df, show_labels)

        # Chart 8: Period Comparison
        self._draw_period_comparison(hist_df, show_labels)

        self.advanced_fig4.tight_layout()
        self.advanced_canvas4.draw()

    def _draw_risk_heatmap(self, df, hist_df, show_labels=True):
        """Draw Risk Heatmap by Subnet/Time."""
        ax = self.heatmap_ax

        if hist_df.empty or 'scan_date' not in hist_df.columns:
            ax.text(0.5, 0.5, 'Insufficient historical data\nfor heatmap', ha='center', va='center',
                   color=GUI_DARK_THEME['fg'], fontsize=9)
            ax.set_title('Risk Heatmap by Subnet/Time', color=GUI_DARK_THEME['fg'], fontsize=10)
            return

        # Get IP column
        ip_col = 'ip_address' if 'ip_address' in hist_df.columns else 'ip' if 'ip' in hist_df.columns else None
        if not ip_col:
            ax.text(0.5, 0.5, 'No IP address data', ha='center', va='center', color=GUI_DARK_THEME['fg'])
            ax.set_title('Risk Heatmap by Subnet/Time', color=GUI_DARK_THEME['fg'], fontsize=10)
            return

        hist_copy = hist_df.copy()
        hist_copy['scan_date'] = pd.to_datetime(hist_copy['scan_date'])
        hist_copy['month'] = hist_copy['scan_date'].dt.to_period('M').astype(str)
        hist_copy['subnet'] = hist_copy[ip_col].apply(
            lambda x: '.'.join(str(x).split('.')[:3]) + '.0/24' if pd.notna(x) and '.' in str(x) else 'Unknown'
        )

        # Get top 10 subnets by total vulnerabilities
        top_subnets = hist_copy['subnet'].value_counts().head(10).index.tolist()
        filtered = hist_copy[hist_copy['subnet'].isin(top_subnets)]

        if filtered.empty:
            ax.text(0.5, 0.5, 'No subnet data', ha='center', va='center', color=GUI_DARK_THEME['fg'])
            ax.set_title('Risk Heatmap by Subnet/Time', color=GUI_DARK_THEME['fg'], fontsize=10)
            return

        # Create pivot table
        pivot = filtered.pivot_table(index='subnet', columns='month', aggfunc='size', fill_value=0)

        # Plot heatmap
        im = ax.imshow(pivot.values, cmap='YlOrRd', aspect='auto')

        # Set ticks
        ax.set_xticks(range(len(pivot.columns)))
        ax.set_xticklabels([c[-5:] for c in pivot.columns], fontsize=7, rotation=45, ha='right')
        ax.set_yticks(range(len(pivot.index)))
        ax.set_yticklabels([s[:15] for s in pivot.index], fontsize=7)

        # Add data labels on heatmap cells
        if show_labels and len(pivot.index) <= 8 and len(pivot.columns) <= 8:
            for i in range(len(pivot.index)):
                for j in range(len(pivot.columns)):
                    val = pivot.values[i, j]
                    if val > 0:
                        color = 'white' if val > pivot.values.max() * 0.5 else 'black'
                        ax.text(j, i, str(int(val)), ha='center', va='center', fontsize=6, color=color)

        ax.set_title('Risk Heatmap by Subnet/Time', color=GUI_DARK_THEME['fg'], fontsize=10)

        # Add colorbar
        cbar = self.advanced_fig1.colorbar(im, ax=ax, shrink=0.8)
        cbar.ax.tick_params(colors=GUI_DARK_THEME['fg'], labelsize=7)
        cbar.set_label('Count', color=GUI_DARK_THEME['fg'], fontsize=8)

    def _draw_bubble_chart(self, df, show_labels=True):
        """Draw Bubble Chart: CVSS vs Age vs Impact."""
        ax = self.bubble_ax

        if df.empty or 'days_open' not in df.columns:
            ax.text(0.5, 0.5, 'No vulnerability age data', ha='center', va='center',
                   color=GUI_DARK_THEME['fg'], fontsize=9)
            ax.set_title('CVSS vs Age vs Impact', color=GUI_DARK_THEME['fg'], fontsize=10)
            return

        # Filter to active findings
        active = df[df['status'] == 'Active'].copy() if 'status' in df.columns else df.copy()

        if active.empty:
            ax.text(0.5, 0.5, 'No active findings', ha='center', va='center', color=GUI_DARK_THEME['fg'])
            ax.set_title('CVSS vs Age vs Impact', color=GUI_DARK_THEME['fg'], fontsize=10)
            return

        # Get CVSS scores
        cvss_col = 'cvss3_base_score' if 'cvss3_base_score' in active.columns else 'cvss_base_score' if 'cvss_base_score' in active.columns else None

        if not cvss_col:
            # Use severity_value as fallback
            if 'severity_value' in active.columns:
                active['cvss_proxy'] = active['severity_value'] * 2.5  # Scale to 0-10
                cvss_col = 'cvss_proxy'
            else:
                ax.text(0.5, 0.5, 'No CVSS data available', ha='center', va='center', color=GUI_DARK_THEME['fg'])
                ax.set_title('CVSS vs Age vs Impact', color=GUI_DARK_THEME['fg'], fontsize=10)
                return

        # Group by plugin_id to get aggregated bubbles
        if 'plugin_id' in active.columns:
            # Convert to numeric before aggregation
            active = active.copy()
            active[cvss_col] = pd.to_numeric(active[cvss_col], errors='coerce')
            active['days_open'] = pd.to_numeric(active['days_open'], errors='coerce')
            grouped = active.groupby('plugin_id').agg({
                cvss_col: 'mean',
                'days_open': 'mean',
                'hostname': 'nunique' if 'hostname' in active.columns else 'count'
            }).reset_index()
            grouped.columns = ['plugin_id', 'cvss', 'age', 'hosts']
        else:
            grouped = pd.DataFrame({
                'cvss': active[cvss_col].values,
                'age': active['days_open'].values,
                'hosts': [1] * len(active)
            })

        # Filter out NaN
        grouped = grouped.dropna(subset=['cvss', 'age'])

        if grouped.empty:
            ax.text(0.5, 0.5, 'No data after filtering', ha='center', va='center', color=GUI_DARK_THEME['fg'])
            ax.set_title('CVSS vs Age vs Impact', color=GUI_DARK_THEME['fg'], fontsize=10)
            return

        # Color by severity
        colors = grouped['cvss'].apply(
            lambda x: '#dc3545' if x >= 9 else '#fd7e14' if x >= 7 else '#ffc107' if x >= 4 else '#007bff'
        )

        # Size by host count (scaled)
        sizes = grouped['hosts'] * 50 + 20
        sizes = sizes.clip(upper=500)

        scatter = ax.scatter(grouped['age'], grouped['cvss'], s=sizes, c=colors, alpha=0.6, edgecolors='white', linewidth=0.5)

        # Add data labels for top items
        if show_labels and len(grouped) <= 20:
            for _, row in grouped.nlargest(10, 'hosts').iterrows():
                ax.annotate(f'{int(row["hosts"])}h', xy=(row['age'], row['cvss']),
                           fontsize=6, ha='center', va='center', color='white')

        ax.set_xlabel('Days Open', color=GUI_DARK_THEME['fg'], fontsize=8)
        ax.set_ylabel('CVSS Score', color=GUI_DARK_THEME['fg'], fontsize=8)
        ax.set_title('CVSS vs Age vs Impact', color=GUI_DARK_THEME['fg'], fontsize=10)

        # Add quadrant lines
        ax.axhline(y=7, color='#fd7e14', linestyle='--', alpha=0.5, linewidth=1)
        ax.axvline(x=30, color='#ffc107', linestyle='--', alpha=0.5, linewidth=1)

        # Quadrant labels
        ax.text(0.02, 0.98, 'Monitor', transform=ax.transAxes, fontsize=7, color='#28a745', va='top')
        ax.text(0.98, 0.98, 'URGENT', transform=ax.transAxes, fontsize=7, color='#dc3545', va='top', ha='right')

    def _draw_sankey_diagram(self, df, hist_df, show_labels=True):
        """Draw Vulnerability Lifecycle Flow (simplified Sankey-style)."""
        ax = self.sankey_ax

        if df.empty or 'status' not in df.columns:
            ax.text(0.5, 0.5, 'No lifecycle data available', ha='center', va='center',
                   color=GUI_DARK_THEME['fg'], fontsize=9)
            ax.set_title('Vulnerability Lifecycle Flow', color=GUI_DARK_THEME['fg'], fontsize=10)
            return

        # Count by status
        status_counts = df['status'].value_counts()
        total = len(df)
        active = status_counts.get('Active', 0)
        resolved = status_counts.get('Resolved', 0)
        reopened = df['reappearances'].sum() if 'reappearances' in df.columns else 0

        # Calculate flow percentages
        new_to_active = active / total * 100 if total > 0 else 0
        active_to_resolved = resolved / total * 100 if total > 0 else 0
        resolved_to_reopened = min(reopened / max(resolved, 1) * 100, 100)

        # Draw flow diagram using arrows
        ax.set_xlim(0, 10)
        ax.set_ylim(0, 6)

        # Boxes
        box_style = dict(boxstyle='round,pad=0.3', facecolor='#2d2d2d', edgecolor='white', linewidth=1)

        # New findings box
        ax.text(1, 5, f'Discovered\n{total:,}', ha='center', va='center', fontsize=9,
               color='white', bbox=box_style)

        # Active box
        ax.text(5, 5, f'Active\n{active:,}', ha='center', va='center', fontsize=9,
               color='white', bbox=dict(boxstyle='round,pad=0.3', facecolor='#dc3545', edgecolor='white'))

        # Resolved box
        ax.text(9, 5, f'Resolved\n{resolved:,}', ha='center', va='center', fontsize=9,
               color='white', bbox=dict(boxstyle='round,pad=0.3', facecolor='#28a745', edgecolor='white'))

        # Reopened box (if any)
        if reopened > 0:
            ax.text(5, 2, f'Reopened\n{int(reopened):,}', ha='center', va='center', fontsize=9,
                   color='white', bbox=dict(boxstyle='round,pad=0.3', facecolor='#ffc107', edgecolor='white'))

        # Arrows with flow percentage labels
        ax.annotate('', xy=(3.5, 5), xytext=(2, 5),
                   arrowprops=dict(arrowstyle='->', color='#007bff', lw=2))
        ax.annotate('', xy=(7.5, 5), xytext=(6, 5),
                   arrowprops=dict(arrowstyle='->', color='#28a745', lw=2))

        # Add percentage labels on arrows if enabled
        if show_labels:
            ax.text(2.75, 5.4, f'{new_to_active:.0f}%', fontsize=7, color='#007bff', ha='center')
            ax.text(6.75, 5.4, f'{active_to_resolved:.0f}%', fontsize=7, color='#28a745', ha='center')

        if reopened > 0:
            ax.annotate('', xy=(5, 3.5), xytext=(7.5, 4.5),
                       arrowprops=dict(arrowstyle='->', color='#ffc107', lw=1.5, connectionstyle='arc3,rad=0.3'))
            ax.annotate('', xy=(5, 4.5), xytext=(5, 3),
                       arrowprops=dict(arrowstyle='->', color='#dc3545', lw=1.5))

        ax.axis('off')
        ax.set_title('Vulnerability Lifecycle Flow', color=GUI_DARK_THEME['fg'], fontsize=10)
        ax.text(0.5, -0.02, f'Resolution rate: {active_to_resolved:.1f}%',
            transform=ax.transAxes, ha='center', va='top', fontsize=8, color='#28a745')

    def _draw_treemap(self, df, show_labels=True):
        """Draw Plugin Family Treemap."""
        ax = self.treemap_ax

        # Check for plugin family or create from plugin_name
        if 'plugin_family' not in df.columns and 'plugin_name' not in df.columns:
            ax.text(0.5, 0.5, 'No plugin family data\navailable', ha='center', va='center',
                   color=GUI_DARK_THEME['fg'], fontsize=9)
            ax.set_title('Plugin Family Treemap', color=GUI_DARK_THEME['fg'], fontsize=10)
            return

        if 'plugin_family' in df.columns:
            family_counts = df['plugin_family'].value_counts().head(12)
        else:
            # Group by first word of plugin name as proxy
            df_copy = df.copy()
            df_copy['family_proxy'] = df_copy['plugin_name'].apply(
                lambda x: str(x).split()[0][:15] if pd.notna(x) else 'Unknown'
            )
            family_counts = df_copy['family_proxy'].value_counts().head(12)

        if family_counts.empty:
            ax.text(0.5, 0.5, 'No plugin data', ha='center', va='center', color=GUI_DARK_THEME['fg'])
            ax.set_title('Plugin Family Treemap', color=GUI_DARK_THEME['fg'], fontsize=10)
            return

        # Draw treemap manually using rectangles
        sizes = family_counts.values
        labels = family_counts.index.tolist()
        total = sum(sizes)

        # Use squarify algorithm (simplified version)
        try:
            import squarify
            normalized = squarify.normalize_sizes(sizes, 100, 100)
            rects = squarify.squarify(normalized, 0, 0, 100, 100)

            cmap = plt.cm.get_cmap('Set3')
            for i, (rect, label, size) in enumerate(zip(rects, labels, sizes)):
                color = cmap(i / len(rects))
                ax.add_patch(plt.Rectangle((rect['x'], rect['y']), rect['dx'], rect['dy'],
                            facecolor=color, edgecolor='white', linewidth=1))
                # Add label if box is big enough and labels enabled
                if show_labels and rect['dx'] > 15 and rect['dy'] > 10:
                    ax.text(rect['x'] + rect['dx']/2, rect['y'] + rect['dy']/2,
                           f'{label[:12]}\n{size}', ha='center', va='center',
                           fontsize=6, color='black', fontweight='bold')
        except ImportError:
            # Fallback: simple bar chart
            colors = plt.cm.Set3(np.linspace(0, 1, len(family_counts)))
            bars = ax.barh(range(len(family_counts)), family_counts.values, color=colors)
            ax.set_yticks(range(len(family_counts)))
            ax.set_yticklabels([str(l)[:15] for l in labels], fontsize=7)
            ax.invert_yaxis()
            if show_labels:
                for bar, val in zip(bars, family_counts.values):
                    ax.text(val + 1, bar.get_y() + bar.get_height()/2, f'{int(val)}',
                           va='center', fontsize=6, color='white')

        ax.set_xlim(0, 100)
        ax.set_ylim(0, 100)
        ax.axis('off')
        ax.set_title('Plugin Family Treemap', color=GUI_DARK_THEME['fg'], fontsize=10)

    def _draw_radar_chart(self, df, show_labels=True):
        """Draw Radar/Spider Chart for top subnets."""
        ax = self.radar_ax

        ip_col = 'ip_address' if 'ip_address' in df.columns else 'ip' if 'ip' in df.columns else None
        if not ip_col or df.empty:
            ax.text(0, 0, 'No subnet data', ha='center', va='center', color=GUI_DARK_THEME['fg'])
            ax.set_title('Subnet Risk Profile', color=GUI_DARK_THEME['fg'], fontsize=10, pad=20)
            return

        df_copy = df.copy()
        df_copy['subnet'] = df_copy[ip_col].apply(
            lambda x: '.'.join(str(x).split('.')[:3]) + '.x' if pd.notna(x) and '.' in str(x) else 'Unknown'
        )

        # Get top 5 subnets
        top_subnets = df_copy['subnet'].value_counts().head(5).index.tolist()
        if not top_subnets:
            ax.text(0, 0, 'No subnet data', ha='center', va='center', color=GUI_DARK_THEME['fg'])
            ax.set_title('Subnet Risk Profile', color=GUI_DARK_THEME['fg'], fontsize=10, pad=20)
            return

        # Calculate metrics for each subnet
        categories = ['Total Vulns', 'Critical', 'High', 'Avg Age', 'Hosts']
        num_vars = len(categories)
        angles = [n / float(num_vars) * 2 * np.pi for n in range(num_vars)]
        angles += angles[:1]  # Complete the circle

        colors = ['#dc3545', '#007bff', '#28a745', '#ffc107', '#17a2b8']

        for i, subnet in enumerate(top_subnets[:3]):  # Limit to 3 for readability
            subnet_df = df_copy[df_copy['subnet'] == subnet]

            total = len(subnet_df)
            critical = len(subnet_df[subnet_df.get('severity_text', '') == 'Critical']) if 'severity_text' in subnet_df.columns else 0
            high = len(subnet_df[subnet_df.get('severity_text', '') == 'High']) if 'severity_text' in subnet_df.columns else 0
            avg_age = pd.to_numeric(subnet_df['days_open'], errors='coerce').mean() if 'days_open' in subnet_df.columns else 0
            hosts = subnet_df['hostname'].nunique() if 'hostname' in subnet_df.columns else 0

            # Normalize values (0-100 scale)
            max_total = df_copy.groupby('subnet').size().max()
            max_age = pd.to_numeric(df_copy['days_open'], errors='coerce').max() if 'days_open' in df_copy.columns else 1
            max_hosts = df_copy.groupby('subnet')['hostname'].nunique().max() if 'hostname' in df_copy.columns else 1

            values = [
                total / max_total * 100 if max_total > 0 else 0,
                critical / max(total, 1) * 100,
                high / max(total, 1) * 100,
                min(avg_age / max_age * 100, 100) if max_age > 0 else 0,
                hosts / max_hosts * 100 if max_hosts > 0 else 0
            ]
            values += values[:1]

            ax.plot(angles, values, 'o-', linewidth=1.5, label=subnet[:12], color=colors[i % len(colors)])
            ax.fill(angles, values, alpha=0.15, color=colors[i % len(colors)])

        ax.set_xticks(angles[:-1])
        ax.set_xticklabels(categories, fontsize=7, color=GUI_DARK_THEME['fg'])
        ax.set_ylim(0, 100)
        ax.legend(loc='upper right', bbox_to_anchor=(1.3, 1.0), fontsize=6)
        ax.set_title('Subnet Risk Profile', color=GUI_DARK_THEME['fg'], fontsize=10, pad=20)
        ax.text(0.5, -0.1, 'Multi-dimensional risk comparison across subnets',
            transform=ax.transAxes, ha='center', va='top', fontsize=7, color='#888888')

    def _draw_velocity_gauge(self, df, hist_df, show_labels=True):
        """Draw Remediation Velocity Gauge."""
        ax = self.gauge_ax

        if df.empty or 'status' not in df.columns:
            ax.text(0.5, 0.5, 'No remediation data', ha='center', va='center',
                   color=GUI_DARK_THEME['fg'], fontsize=9)
            ax.set_title('Remediation Velocity', color=GUI_DARK_THEME['fg'], fontsize=10)
            return

        # Calculate remediation rate
        total = len(df)
        resolved = len(df[df['status'] == 'Resolved'])
        rate = resolved / total * 100 if total > 0 else 0

        # Calculate velocity (resolutions per day from historical data)
        velocity = 0
        if not hist_df.empty and 'status' in hist_df.columns:
            hist_copy = hist_df.copy()
            hist_copy['scan_date'] = pd.to_datetime(hist_copy['scan_date'])
            date_range = (hist_copy['scan_date'].max() - hist_copy['scan_date'].min()).days
            if date_range > 0:
                total_resolved = len(hist_df[hist_df.get('status', '') == 'Resolved'])
                velocity = total_resolved / date_range

        # Draw gauge
        ax.set_xlim(-1.5, 1.5)
        ax.set_ylim(-0.5, 1.2)

        # Draw arc for gauge background
        theta = np.linspace(0, np.pi, 100)
        x = np.cos(theta)
        y = np.sin(theta)

        # Background arc (gray)
        ax.plot(x, y, color='#3d3d3d', linewidth=20, solid_capstyle='round')

        # Colored sections
        for i, (start, end, color) in enumerate([
            (0, 0.33, '#dc3545'),    # Red (0-33%)
            (0.33, 0.66, '#ffc107'),  # Yellow (33-66%)
            (0.66, 1.0, '#28a745')    # Green (66-100%)
        ]):
            theta_section = np.linspace(np.pi * (1 - end), np.pi * (1 - start), 50)
            ax.plot(np.cos(theta_section), np.sin(theta_section), color=color, linewidth=18, solid_capstyle='butt')

        # Needle
        needle_angle = np.pi * (1 - rate / 100)
        ax.annotate('', xy=(0.8 * np.cos(needle_angle), 0.8 * np.sin(needle_angle)), xytext=(0, 0),
                   arrowprops=dict(arrowstyle='->', color='white', lw=3))

        # Center circle
        circle = plt.Circle((0, 0), 0.15, color='#2d2d2d', ec='white', linewidth=2)
        ax.add_patch(circle)

        # Labels (always show main rate)
        ax.text(0, 0.5, f'{rate:.1f}%', ha='center', va='center', fontsize=16,
               color='white', fontweight='bold')
        ax.text(0, 0.25, 'Remediation\nRate', ha='center', va='center', fontsize=8, color='#888888')

        # Velocity indicator and scale labels
        velocity_color = '#28a745' if velocity > 1 else '#ffc107' if velocity > 0.5 else '#dc3545'
        ax.text(0, -0.3, f'Velocity: {velocity:.1f}/day', ha='center', fontsize=9, color=velocity_color)

        if show_labels:
            ax.text(-1.0, 0.1, '0%', ha='center', fontsize=7, color='white')
            ax.text(0, 1.1, '50%', ha='center', fontsize=7, color='white')
            ax.text(1.0, 0.1, '100%', ha='center', fontsize=7, color='white')

        ax.axis('off')
        ax.set_aspect('equal')
        ax.set_title('Remediation Velocity', color=GUI_DARK_THEME['fg'], fontsize=10)
        ax.text(0.5, -0.15, 'Percentage of findings resolved',
            transform=ax.transAxes, ha='center', va='top', fontsize=7, color='#888888')

    def _draw_sla_prediction(self, df, show_labels=True):
        """Draw SLA Breach Prediction Chart."""
        ax = self.prediction_ax

        if df.empty or 'status' not in df.columns:
            ax.text(0.5, 0.5, 'No SLA data available', ha='center', va='center',
                   color=GUI_DARK_THEME['fg'], fontsize=9)
            ax.set_title('SLA Breach Prediction', color=GUI_DARK_THEME['fg'], fontsize=10)
            return

        active = df[df['status'] == 'Active'].copy() if 'status' in df.columns else df.copy()

        if active.empty or 'days_open' not in active.columns:
            ax.text(0.5, 0.5, 'No active findings with age data', ha='center', va='center',
                   color=GUI_DARK_THEME['fg'], fontsize=9)
            ax.set_title('SLA Breach Prediction', color=GUI_DARK_THEME['fg'], fontsize=10)
            return

        # Get SLA targets from settings or use defaults
        sla_targets = {'Critical': 7, 'High': 30, 'Medium': 60, 'Low': 90}

        # Calculate days until SLA breach for each finding
        if 'severity_text' in active.columns:
            active['sla_target'] = active['severity_text'].map(sla_targets).fillna(90)
        else:
            active['sla_target'] = 60  # Default

        active['days_until_breach'] = active['sla_target'] - active['days_open']

        # Group by days until breach
        breach_timeline = []
        for days in range(0, 31):  # Next 30 days
            at_risk = len(active[active['days_until_breach'] <= days])
            breach_timeline.append(at_risk)

        # Current breaches
        current_breaches = len(active[active['days_until_breach'] <= 0])

        # Plot
        x = range(31)
        ax.fill_between(x, breach_timeline, alpha=0.3, color='#dc3545')
        ax.plot(x, breach_timeline, color='#dc3545', linewidth=2, marker='o', markersize=3)

        # Add data labels at key points
        if show_labels:
            key_days = [0, 7, 14, 30]
            for day in key_days:
                if day < len(breach_timeline):
                    ax.annotate(f'{breach_timeline[day]}', xy=(day, breach_timeline[day]),
                               xytext=(0, 5), textcoords='offset points',
                               ha='center', fontsize=7, color='white')

        # Highlight critical zone
        ax.axhline(y=current_breaches, color='#ffc107', linestyle='--', linewidth=1, alpha=0.7)
        ax.axvline(x=7, color='#fd7e14', linestyle=':', linewidth=1, alpha=0.7)
        ax.axvline(x=14, color='#ffc107', linestyle=':', linewidth=1, alpha=0.7)

        ax.set_xlabel('Days from Now', color=GUI_DARK_THEME['fg'], fontsize=8)
        ax.set_ylabel('Cumulative At-Risk', color=GUI_DARK_THEME['fg'], fontsize=8)
        ax.set_title('SLA Breach Prediction', color=GUI_DARK_THEME['fg'], fontsize=10)
        ax.text(0.5, 1.02, f'Current breaches: {current_breaches} | 7-day forecast: {breach_timeline[7]}',
            transform=ax.transAxes, ha='center', va='bottom', fontsize=7, color='#dc3545')

        ax.tick_params(colors=GUI_DARK_THEME['fg'], labelsize=7)

    def _draw_period_comparison(self, hist_df, show_labels=True):
        """Draw Period Comparison Chart."""
        ax = self.comparison_ax

        if hist_df.empty or 'scan_date' not in hist_df.columns:
            ax.text(0.5, 0.5, 'Insufficient historical data\nfor comparison', ha='center', va='center',
                   color=GUI_DARK_THEME['fg'], fontsize=9)
            ax.set_title('Period Comparison', color=GUI_DARK_THEME['fg'], fontsize=10)
            return

        hist_copy = hist_df.copy()
        hist_copy['scan_date'] = pd.to_datetime(hist_copy['scan_date'])

        # Get date range
        max_date = hist_copy['scan_date'].max()
        min_date = hist_copy['scan_date'].min()
        total_days = (max_date - min_date).days

        if total_days < 14:
            ax.text(0.5, 0.5, 'Need at least 2 weeks\nof data for comparison', ha='center', va='center',
                   color=GUI_DARK_THEME['fg'], fontsize=9)
            ax.set_title('Period Comparison', color=GUI_DARK_THEME['fg'], fontsize=10)
            return

        # Split into two periods
        mid_date = min_date + timedelta(days=total_days // 2)

        period1 = hist_copy[hist_copy['scan_date'] <= mid_date]
        period2 = hist_copy[hist_copy['scan_date'] > mid_date]

        # Calculate metrics for each period
        metrics = ['Total', 'Critical', 'High', 'Medium', 'Avg Age']

        p1_values = [
            len(period1),
            len(period1[period1.get('severity_text', '') == 'Critical']) if 'severity_text' in period1.columns else 0,
            len(period1[period1.get('severity_text', '') == 'High']) if 'severity_text' in period1.columns else 0,
            len(period1[period1.get('severity_text', '') == 'Medium']) if 'severity_text' in period1.columns else 0,
            pd.to_numeric(period1['days_open'], errors='coerce').mean() if 'days_open' in period1.columns and not period1.empty else 0
        ]

        p2_values = [
            len(period2),
            len(period2[period2.get('severity_text', '') == 'Critical']) if 'severity_text' in period2.columns else 0,
            len(period2[period2.get('severity_text', '') == 'High']) if 'severity_text' in period2.columns else 0,
            len(period2[period2.get('severity_text', '') == 'Medium']) if 'severity_text' in period2.columns else 0,
            pd.to_numeric(period2['days_open'], errors='coerce').mean() if 'days_open' in period2.columns and not period2.empty else 0
        ]

        x = np.arange(len(metrics))
        width = 0.35

        bars1 = ax.bar(x - width/2, p1_values, width, label='Earlier Period', color='#6c757d', alpha=0.8)
        bars2 = ax.bar(x + width/2, p2_values, width, label='Recent Period', color='#007bff', alpha=0.8)

        # Add data labels on bars
        if show_labels:
            for idx, (bar, val) in enumerate(zip(bars1, p1_values)):
                if val > 0:
                    ax.annotate(f'{int(val) if isinstance(val, int) or val == int(val) else val:.1f}',
                               xy=(bar.get_x() + bar.get_width()/2, val),
                               xytext=(0, 2), textcoords='offset points',
                               ha='center', fontsize=6, color='white')
            for idx, (bar, val) in enumerate(zip(bars2, p2_values)):
                if val > 0:
                    ax.annotate(f'{int(val) if isinstance(val, int) or val == int(val) else val:.1f}',
                               xy=(bar.get_x() + bar.get_width()/2, val),
                               xytext=(0, 2), textcoords='offset points',
                               ha='center', fontsize=6, color='white')

        # Add change indicators
        for i, (v1, v2) in enumerate(zip(p1_values, p2_values)):
            if v1 > 0:
                change = ((v2 - v1) / v1) * 100
                color = '#28a745' if change < 0 else '#dc3545'  # Green if decrease (good)
                arrow = '↓' if change < 0 else '↑'
                ax.text(i, max(v1, v2) + max(p1_values + p2_values) * 0.05,
                       f'{arrow}{abs(change):.0f}%', ha='center', fontsize=7, color=color)

        ax.set_xticks(x)
        ax.set_xticklabels(metrics, fontsize=7)
        ax.legend(fontsize=7, loc='upper right')
        ax.set_title('Period Comparison', color=GUI_DARK_THEME['fg'], fontsize=10)
        ax.tick_params(colors=GUI_DARK_THEME['fg'], labelsize=7)

    def _update_all_visualizations(self):
        """Update all visualization tabs."""
        self._update_trends_chart()
        self._update_timeline_charts()
        self._update_risk_charts()
        self._update_opdir_charts()
        self._update_efficiency_charts()
        self._update_network_charts()
        self._update_plugin_charts()
        self._update_priority_charts()
        self._update_sla_charts()
        self._update_metrics_charts()
        self._update_host_tracking_charts()
        self._update_advanced_charts()

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
                self.opdir_df, filepath,
                iavm_df=self.iavm_df
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

    def _apply_settings_to_ui(self):
        """Apply loaded settings to UI elements."""
        settings = self.settings_manager.settings

        # Apply default filter settings
        self.filter_include_info.set(settings.default_include_info)

        # Apply page size
        self.lifecycle_page_size.set(settings.default_page_size)

        # Load recent files if they exist
        if settings.recent_plugins_db and os.path.exists(settings.recent_plugins_db):
            self.plugins_db_path = settings.recent_plugins_db
            self.plugins_label.config(text=self._truncate_filename(os.path.basename(settings.recent_plugins_db)), foreground="white")
        if settings.recent_opdir_file and os.path.exists(settings.recent_opdir_file):
            self.opdir_file_path = settings.recent_opdir_file
            self.opdir_label.config(text=self._truncate_filename(os.path.basename(settings.recent_opdir_file)), foreground="white")
        if settings.recent_iavm_file and os.path.exists(settings.recent_iavm_file):
            self.iavm_file_path = settings.recent_iavm_file
            self.iavm_label.config(text=self._truncate_filename(os.path.basename(settings.recent_iavm_file)), foreground="white")
        if settings.recent_sqlite_db and os.path.exists(settings.recent_sqlite_db):
            self.existing_db_path = settings.recent_sqlite_db
            self.existing_db_label.config(text=self._truncate_filename(os.path.basename(settings.recent_sqlite_db)), foreground="white")

    def _show_environment_config(self):
        """Show environment mapping configuration dialog."""
        settings = self.settings_manager.settings

        dialog = tk.Toplevel(self.window)
        dialog.title("Environment Configuration")
        dialog.geometry("900x650")
        dialog.configure(bg=GUI_DARK_THEME['bg'])
        dialog.transient(self.window)
        dialog.grab_set()
        dialog.resizable(True, True)
        dialog.minsize(700, 500)

        # Create notebook for tabbed configuration
        notebook = ttk.Notebook(dialog)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # === Environment Types Tab ===
        types_frame = ttk.Frame(notebook, padding=10)
        notebook.add(types_frame, text="Environment Types")

        ttk.Label(types_frame, text="Define custom environment types (one per line):").pack(anchor=tk.W, pady=(0, 5))
        ttk.Label(types_frame, text="These will appear in the Environment filter dropdown.",
                 foreground='gray').pack(anchor=tk.W, pady=(0, 10))

        # Text widget for environment types
        env_types_text = tk.Text(types_frame, height=10, width=40,
                                bg=GUI_DARK_THEME['entry_bg'], fg=GUI_DARK_THEME['fg'],
                                insertbackground=GUI_DARK_THEME['fg'])
        env_types_text.pack(fill=tk.BOTH, expand=True, pady=5)

        # Pre-populate with current environment types
        current_types = settings.environment_types
        env_types_text.insert('1.0', '\n'.join(current_types))

        # === Hostname Mappings Tab ===
        mappings_frame = ttk.Frame(notebook, padding=10)
        notebook.add(mappings_frame, text="Hostname Mappings")

        # Get all hostnames from loaded data
        all_hostnames = self._get_all_hostnames()
        current_mappings = dict(settings.environment_mappings)
        env_options = settings.environment_types + ['Unknown']

        # Store mapping state
        mapping_state = {'mappings': current_mappings.copy()}

        # Top controls - bulk assignment
        bulk_frame = ttk.Frame(mappings_frame)
        bulk_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(bulk_frame, text="Bulk assign selected hosts to:").pack(side=tk.LEFT)
        bulk_env_var = tk.StringVar(value=env_options[0] if env_options else "Production")
        bulk_combo = ttk.Combobox(bulk_frame, textvariable=bulk_env_var,
                                  values=env_options, state="readonly", width=15)
        bulk_combo.pack(side=tk.LEFT, padx=5)

        # Main content - two columns
        content_frame = ttk.Frame(mappings_frame)
        content_frame.pack(fill=tk.BOTH, expand=True)
        content_frame.columnconfigure(0, weight=1)
        content_frame.columnconfigure(1, weight=1)
        content_frame.rowconfigure(0, weight=1)

        # Left side: Host list with checkboxes and dropdowns
        left_frame = ttk.LabelFrame(content_frame, text="All Hosts", padding=5)
        left_frame.grid(row=0, column=0, sticky='nsew', padx=(0, 5))

        # Search filter row
        search_frame = ttk.Frame(left_frame)
        search_frame.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(search_frame, text="Filter:").pack(side=tk.LEFT)
        search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=search_var, width=15)
        search_entry.pack(side=tk.LEFT, padx=5)

        # Environment filter dropdown
        ttk.Label(search_frame, text="Env:").pack(side=tk.LEFT, padx=(10, 0))
        env_filter_var = tk.StringVar(value="All")
        env_filter_options = ["All"] + env_options
        env_filter_combo = ttk.Combobox(search_frame, textvariable=env_filter_var,
                                        values=env_filter_options, state="readonly", width=12)
        env_filter_combo.pack(side=tk.LEFT, padx=5)

        # Scrollable host list
        host_canvas = tk.Canvas(left_frame, bg=GUI_DARK_THEME['entry_bg'], highlightthickness=0)
        host_scrollbar = ttk.Scrollbar(left_frame, orient="vertical", command=host_canvas.yview)
        host_list_frame = ttk.Frame(host_canvas)

        host_canvas.configure(yscrollcommand=host_scrollbar.set)
        host_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        host_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        host_canvas_window = host_canvas.create_window((0, 0), window=host_list_frame, anchor="nw")

        # Store checkbox and combo references
        host_widgets = {}

        def get_current_env(hostname):
            """Get current environment for a hostname."""
            h_lower = hostname.lower()
            if h_lower in mapping_state['mappings']:
                return mapping_state['mappings'][h_lower]
            return self._get_environment_type(hostname)

        def update_mapping(hostname, env, rebuild_list=True):
            """Update mapping for a hostname."""
            h_lower = hostname.lower()
            if env and env != 'Unknown':
                mapping_state['mappings'][h_lower] = env
            elif h_lower in mapping_state['mappings']:
                del mapping_state['mappings'][h_lower]
            update_env_lists()
            # Rebuild host list if filtering by environment (host may need to disappear)
            if rebuild_list and env_filter_var.get() != "All":
                build_host_list(search_var.get(), env_filter_var.get())

        def build_host_list(filter_text="", env_filter="All"):
            """Build/rebuild the host list with checkboxes."""
            # Clear existing widgets
            for widget in host_list_frame.winfo_children():
                widget.destroy()
            host_widgets.clear()

            # Filter by text
            filtered_hosts = [h for h in all_hostnames if filter_text.lower() in h.lower()]

            # Filter by environment if specified
            if env_filter and env_filter != "All":
                filtered_hosts = [h for h in filtered_hosts if get_current_env(h) == env_filter]

            for i, hostname in enumerate(sorted(filtered_hosts)):
                row_frame = ttk.Frame(host_list_frame)
                row_frame.pack(fill=tk.X, pady=1)

                # Checkbox for selection
                check_var = tk.BooleanVar(value=False)
                check = ttk.Checkbutton(row_frame, variable=check_var)
                check.pack(side=tk.LEFT)

                # Hostname label
                ttk.Label(row_frame, text=hostname[:25], width=25).pack(side=tk.LEFT)

                # Environment dropdown
                current_env = get_current_env(hostname)
                env_var = tk.StringVar(value=current_env)
                env_combo = ttk.Combobox(row_frame, textvariable=env_var,
                                        values=env_options, state="readonly", width=12)
                env_combo.pack(side=tk.LEFT, padx=2)
                env_combo.bind('<<ComboboxSelected>>', lambda e, h=hostname, v=env_var: update_mapping(h, v.get()))

                host_widgets[hostname] = {'check': check_var, 'env': env_var}

            # Update canvas scroll region
            host_list_frame.update_idletasks()
            host_canvas.configure(scrollregion=host_canvas.bbox("all"))

        def apply_bulk_assignment():
            """Apply bulk environment assignment to selected hosts."""
            env = bulk_env_var.get()
            changed_hosts = []
            for hostname, widgets in host_widgets.items():
                if widgets['check'].get():
                    widgets['env'].set(env)
                    # Update mapping without rebuilding list each time
                    update_mapping(hostname, env, rebuild_list=False)
                    changed_hosts.append(hostname)
                    # Uncheck after assignment
                    widgets['check'].set(False)

            # Rebuild host list once at the end if we're filtering by environment
            if changed_hosts and env_filter_var.get() != "All":
                build_host_list(search_var.get(), env_filter_var.get())

        ttk.Button(bulk_frame, text="Apply", command=apply_bulk_assignment).pack(side=tk.LEFT, padx=5)

        # Bind search and environment filter
        def on_filter_change(*args):
            build_host_list(search_var.get(), env_filter_var.get())
        search_var.trace('w', on_filter_change)
        env_filter_combo.bind('<<ComboboxSelected>>', on_filter_change)

        # Right side: Environment lists showing hosts in each environment
        right_frame = ttk.LabelFrame(content_frame, text="Hosts by Environment", padding=5)
        right_frame.grid(row=0, column=1, sticky='nsew', padx=(5, 0))

        # Create scrollable text for each environment
        env_list_canvas = tk.Canvas(right_frame, bg=GUI_DARK_THEME['entry_bg'], highlightthickness=0)
        env_list_scrollbar = ttk.Scrollbar(right_frame, orient="vertical", command=env_list_canvas.yview)
        env_lists_frame = ttk.Frame(env_list_canvas)

        env_list_canvas.configure(yscrollcommand=env_list_scrollbar.set)
        env_list_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        env_list_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        env_list_canvas.create_window((0, 0), window=env_lists_frame, anchor="nw")

        env_text_widgets = {}

        def update_env_lists():
            """Update the environment lists on the right side."""
            # Clear existing
            for widget in env_lists_frame.winfo_children():
                widget.destroy()
            env_text_widgets.clear()

            # Group hosts by environment
            env_hosts = {env: [] for env in env_options}
            for hostname in all_hostnames:
                env = get_current_env(hostname)
                if env in env_hosts:
                    env_hosts[env].append(hostname)
                else:
                    env_hosts.setdefault('Unknown', []).append(hostname)

            # Create collapsible sections for each environment
            for env in env_options:
                hosts = sorted(env_hosts.get(env, []))
                if not hosts:
                    continue

                env_frame = ttk.LabelFrame(env_lists_frame, text=f"{env} ({len(hosts)})")
                env_frame.pack(fill=tk.X, pady=2, padx=2)

                text_widget = tk.Text(env_frame, height=4, width=30,
                                     bg=GUI_DARK_THEME['entry_bg'], fg=GUI_DARK_THEME['fg'],
                                     state='disabled')
                text_scrollbar = ttk.Scrollbar(env_frame, command=text_widget.yview)
                text_widget.configure(yscrollcommand=text_scrollbar.set)

                text_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
                text_widget.pack(fill=tk.BOTH, expand=True)

                text_widget.configure(state='normal')
                text_widget.insert('1.0', '\n'.join(hosts))
                text_widget.configure(state='disabled')

                env_text_widgets[env] = text_widget

            env_lists_frame.update_idletasks()
            env_list_canvas.configure(scrollregion=env_list_canvas.bbox("all"))

        # Initial build
        build_host_list()
        update_env_lists()

        # Store reference to mapping_state for save function
        mappings_text = mapping_state  # Reference for save function

        # === Pattern Mappings Tab ===
        patterns_frame = ttk.Frame(notebook, padding=10)
        notebook.add(patterns_frame, text="Pattern Mappings")

        ttk.Label(patterns_frame, text="Map hostname patterns (regex) to environments:").pack(anchor=tk.W, pady=(0, 5))
        ttk.Label(patterns_frame, text="Format: pattern = EnvironmentType (e.g., ^prod-.* = Production)",
                 foreground='gray').pack(anchor=tk.W, pady=(0, 10))

        # Text widget for pattern mappings
        patterns_text = tk.Text(patterns_frame, height=10, width=50,
                               bg=GUI_DARK_THEME['entry_bg'], fg=GUI_DARK_THEME['fg'],
                               insertbackground=GUI_DARK_THEME['fg'])
        patterns_text.pack(fill=tk.BOTH, expand=True, pady=5)

        # Pre-populate with current patterns
        current_patterns = settings.environment_patterns
        pattern_lines = [f"{pattern} = {env}" for pattern, env in current_patterns.items()]
        patterns_text.insert('1.0', '\n'.join(pattern_lines))

        # === Auto-Detection Tab ===
        auto_frame = ttk.Frame(notebook, padding=10)
        notebook.add(auto_frame, text="Auto-Detection")

        ttk.Label(auto_frame, text="Automatic environment detection rules:",
                 font=('Arial', 10, 'bold')).pack(anchor=tk.W, pady=(0, 10))

        # Configurable hostname length
        length_frame = ttk.Frame(auto_frame)
        length_frame.pack(fill=tk.X, pady=5)
        ttk.Label(length_frame, text="Expected hostname length:").pack(side=tk.LEFT)
        current_length = getattr(settings, 'hostname_length', 9)
        auto_frame.hostname_length_var = tk.StringVar(value=str(current_length))
        length_entry = ttk.Entry(length_frame, textvariable=auto_frame.hostname_length_var, width=5)
        length_entry.pack(side=tk.LEFT, padx=5)
        ttk.Label(length_frame, text="characters (default: 9)").pack(side=tk.LEFT)

        ttk.Separator(auto_frame, orient='horizontal').pack(fill=tk.X, pady=10)

        ttk.Label(auto_frame, text="Standard hostname format: LLLLTTCEP",
                 font=('Arial', 9, 'bold')).pack(anchor=tk.W, pady=2)
        ttk.Label(auto_frame, text="(Customize positions based on your hostname structure)").pack(anchor=tk.W, pady=(0, 5))

        # Position configuration
        pos_frame = ttk.LabelFrame(auto_frame, text="Position Configuration", padding=5)
        pos_frame.pack(fill=tk.X, pady=5)

        ttk.Label(pos_frame, text="Position 1-4: Location code (e.g., LANT, PACF)").pack(anchor=tk.W, padx=10)
        ttk.Label(pos_frame, text="Position 5-6: Tier/type code").pack(anchor=tk.W, padx=10)
        ttk.Label(pos_frame, text="Position 7: Cluster identifier").pack(anchor=tk.W, padx=10)
        ttk.Label(pos_frame, text="Position 8: Environment indicator").pack(anchor=tk.W, padx=10)
        ttk.Label(pos_frame, text="    • Letter (A-Z) = Production").pack(anchor=tk.W, padx=30)
        ttk.Label(pos_frame, text="    • Number (0-9) = PSS/Pre-Production").pack(anchor=tk.W, padx=30)
        ttk.Label(pos_frame, text="Position 9: Host type").pack(anchor=tk.W, padx=10)
        ttk.Label(pos_frame, text="    • 'p' = Physical, 'v' = Virtual").pack(anchor=tk.W, padx=30)

        ttk.Separator(auto_frame, orient='horizontal').pack(fill=tk.X, pady=10)

        ttk.Label(auto_frame, text="Detection priority:", font=('Arial', 9, 'bold')).pack(anchor=tk.W, pady=5)
        ttk.Label(auto_frame, text="  1. Explicit hostname mappings (Hostname Mappings tab)").pack(anchor=tk.W, padx=20)
        ttk.Label(auto_frame, text="  2. Pattern matching (Pattern Mappings tab)").pack(anchor=tk.W, padx=20)
        ttk.Label(auto_frame, text="  3. Auto-detection from hostname format").pack(anchor=tk.W, padx=20)
        ttk.Label(auto_frame, text="  4. Default to 'Unknown'").pack(anchor=tk.W, padx=20)

        # Buttons
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)

        def save_config():
            # Parse environment types
            types_content = env_types_text.get('1.0', tk.END).strip()
            new_types = [t.strip() for t in types_content.split('\n') if t.strip()]
            if not new_types:
                new_types = ['Production', 'PSS', 'Shared', 'Unknown']

            # Get hostname mappings from the interactive state
            new_mappings = dict(mapping_state['mappings'])

            # Parse pattern mappings
            patterns_content = patterns_text.get('1.0', tk.END).strip()
            new_patterns = {}
            for line in patterns_content.split('\n'):
                if '=' in line:
                    parts = line.split('=', 1)
                    if len(parts) == 2:
                        pattern = parts[0].strip()
                        env = parts[1].strip()
                        if pattern and env:
                            new_patterns[pattern] = env

            # Get hostname length from auto-detection settings
            if hasattr(auto_frame, 'hostname_length_var'):
                try:
                    settings.hostname_length = int(auto_frame.hostname_length_var.get())
                except ValueError:
                    pass

            # Update settings
            settings.environment_types = new_types
            settings.environment_mappings = new_mappings
            settings.environment_patterns = new_patterns

            # Save settings
            self.settings_manager.save()

            # Update the environment filter dropdown
            env_types = ["All Combined", "All Separate"] + new_types
            self.env_combo['values'] = env_types

            self._log(f"Saved environment config: {len(new_types)} types, {len(new_mappings)} mappings, {len(new_patterns)} patterns")
            messagebox.showinfo("Saved", "Environment configuration saved successfully.")
            dialog.destroy()

        ttk.Button(btn_frame, text="Save", command=save_config, width=10).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=dialog.destroy, width=10).pack(side=tk.RIGHT)

    def _show_settings_dialog(self):
        """Show settings configuration dialog."""
        settings = self.settings_manager.settings

        dialog = tk.Toplevel(self.window)
        dialog.title("Settings")
        dialog.geometry("500x600")
        dialog.configure(bg=GUI_DARK_THEME['bg'])
        dialog.transient(self.window)
        dialog.grab_set()

        # Create notebook for tabbed settings
        notebook = ttk.Notebook(dialog)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # === SLA Tab ===
        sla_frame = ttk.Frame(notebook, padding=10)
        notebook.add(sla_frame, text="SLA Targets")

        ttk.Label(sla_frame, text="Days to remediate by severity:").pack(anchor=tk.W, pady=(0, 10))

        sla_vars = {}
        for severity, default in [('Critical', settings.sla_critical),
                                   ('High', settings.sla_high),
                                   ('Medium', settings.sla_medium),
                                   ('Low', settings.sla_low)]:
            row = ttk.Frame(sla_frame)
            row.pack(fill=tk.X, pady=2)
            ttk.Label(row, text=f"{severity}:", width=12).pack(side=tk.LEFT)
            var = tk.StringVar(value=str(default))
            sla_vars[severity] = var
            ttk.Entry(row, textvariable=var, width=10).pack(side=tk.LEFT)
            ttk.Label(row, text="days").pack(side=tk.LEFT, padx=5)

        # Info has no SLA checkbox
        info_row = ttk.Frame(sla_frame)
        info_row.pack(fill=tk.X, pady=2)
        ttk.Label(info_row, text="Info:", width=12).pack(side=tk.LEFT)
        ttk.Label(info_row, text="No SLA (informational)").pack(side=tk.LEFT)

        # Warning threshold
        warn_row = ttk.Frame(sla_frame)
        warn_row.pack(fill=tk.X, pady=(15, 2))
        ttk.Label(warn_row, text="Warning threshold:").pack(side=tk.LEFT)
        warn_var = tk.StringVar(value=str(int(settings.sla_warning_threshold * 100)))
        ttk.Entry(warn_row, textvariable=warn_var, width=5).pack(side=tk.LEFT, padx=5)
        ttk.Label(warn_row, text="% remaining").pack(side=tk.LEFT)

        # === Colors Tab ===
        colors_frame = ttk.Frame(notebook, padding=10)
        notebook.add(colors_frame, text="Colors")

        ttk.Label(colors_frame, text="Severity colors (hex values):").pack(anchor=tk.W, pady=(0, 10))

        color_vars = {}
        for severity, color_attr in [('Critical', 'color_critical'),
                                      ('High', 'color_high'),
                                      ('Medium', 'color_medium'),
                                      ('Low', 'color_low'),
                                      ('Info', 'color_info')]:
            row = ttk.Frame(colors_frame)
            row.pack(fill=tk.X, pady=2)
            ttk.Label(row, text=f"{severity}:", width=12).pack(side=tk.LEFT)
            var = tk.StringVar(value=getattr(settings, color_attr))
            color_vars[severity] = var
            entry = ttk.Entry(row, textvariable=var, width=10)
            entry.pack(side=tk.LEFT)
            # Color preview label
            preview = tk.Label(row, text="  ", bg=getattr(settings, color_attr), width=3)
            preview.pack(side=tk.LEFT, padx=5)
            # Update preview on change
            var.trace('w', lambda *args, v=var, p=preview: self._update_color_preview(v, p))

        # === Defaults Tab ===
        defaults_frame = ttk.Frame(notebook, padding=10)
        notebook.add(defaults_frame, text="Defaults")

        ttk.Label(defaults_frame, text="Default filter settings:").pack(anchor=tk.W, pady=(0, 10))

        # Include Info default
        include_info_var = tk.BooleanVar(value=settings.default_include_info)
        ttk.Checkbutton(defaults_frame, text="Include Info severity by default",
                        variable=include_info_var).pack(anchor=tk.W, pady=2)

        # Show data labels
        show_labels_var = tk.BooleanVar(value=settings.show_data_labels)
        ttk.Checkbutton(defaults_frame, text="Show data labels on charts",
                        variable=show_labels_var).pack(anchor=tk.W, pady=2)

        # Default page size
        page_row = ttk.Frame(defaults_frame)
        page_row.pack(fill=tk.X, pady=(15, 2))
        ttk.Label(page_row, text="Default page size:").pack(side=tk.LEFT)
        page_var = tk.StringVar(value=str(settings.default_page_size))
        ttk.Combobox(page_row, textvariable=page_var,
                     values=['50', '100', '250', '500', '1000'],
                     width=8, state="readonly").pack(side=tk.LEFT, padx=5)

        # === Recent Files Tab ===
        recent_frame = ttk.Frame(notebook, padding=10)
        notebook.add(recent_frame, text="Recent Files")

        ttk.Label(recent_frame, text="Recently used files (auto-loaded on startup):").pack(anchor=tk.W, pady=(0, 10))

        for label, attr in [('Plugins DB:', 'recent_plugins_db'),
                            ('OPDIR File:', 'recent_opdir_file'),
                            ('SQLite DB:', 'recent_sqlite_db')]:
            row = ttk.Frame(recent_frame)
            row.pack(fill=tk.X, pady=2)
            ttk.Label(row, text=label, width=12).pack(side=tk.LEFT)
            path = getattr(settings, attr) or "(none)"
            ttk.Label(row, text=path[:40] + "..." if len(path) > 40 else path,
                      foreground="gray").pack(side=tk.LEFT)

        ttk.Button(recent_frame, text="Clear Recent Files",
                   command=lambda: self._clear_recent_files(dialog)).pack(anchor=tk.W, pady=15)

        # === Action Buttons ===
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)

        def save_settings():
            try:
                # Update SLA settings
                settings.sla_critical = int(sla_vars['Critical'].get())
                settings.sla_high = int(sla_vars['High'].get())
                settings.sla_medium = int(sla_vars['Medium'].get())
                settings.sla_low = int(sla_vars['Low'].get())
                settings.sla_warning_threshold = int(warn_var.get()) / 100.0

                # Update colors
                settings.color_critical = color_vars['Critical'].get()
                settings.color_high = color_vars['High'].get()
                settings.color_medium = color_vars['Medium'].get()
                settings.color_low = color_vars['Low'].get()
                settings.color_info = color_vars['Info'].get()

                # Update defaults
                settings.default_include_info = include_info_var.get()
                settings.show_data_labels = show_labels_var.get()
                settings.default_page_size = int(page_var.get())

                # Save to file
                self.settings_manager.save()
                self._apply_settings_to_ui()
                self._log("Settings saved")
                dialog.destroy()

            except ValueError as e:
                messagebox.showerror("Invalid Input", f"Please enter valid numbers: {e}")

        ttk.Button(btn_frame, text="Save", command=save_settings, width=10).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=dialog.destroy, width=10).pack(side=tk.RIGHT)
        ttk.Button(btn_frame, text="Reset Defaults",
                   command=lambda: self._reset_settings_to_defaults(dialog)).pack(side=tk.LEFT)

    def _update_color_preview(self, var: tk.StringVar, preview: tk.Label):
        """Update color preview label."""
        try:
            color = var.get()
            if color.startswith('#') and len(color) == 7:
                preview.configure(bg=color)
        except:
            pass

    def _clear_recent_files(self, dialog: tk.Toplevel):
        """Clear recent files from settings."""
        self.settings_manager.settings.recent_plugins_db = ''
        self.settings_manager.settings.recent_opdir_file = ''
        self.settings_manager.settings.recent_sqlite_db = ''
        self.settings_manager.save()
        self._log("Cleared recent files")
        dialog.destroy()
        self._show_settings_dialog()  # Refresh dialog

    def _reset_settings_to_defaults(self, dialog: tk.Toplevel):
        """Reset settings to defaults."""
        if messagebox.askyesno("Reset Settings", "Reset all settings to defaults?"):
            self.settings_manager.reset_to_defaults()
            self._apply_settings_to_ui()
            self._log("Settings reset to defaults")
            dialog.destroy()
            self._show_settings_dialog()  # Refresh dialog

    def _log(self, message: str):
        """Add message to status log and update status bar."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.status_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.status_text.see(tk.END)
        # Update status bar with latest message (truncated)
        self._set_status(message[:80] if len(message) > 80 else message)
        self.window.update_idletasks()

    def _set_status(self, message: str, progress: str = ""):
        """Update the status bar at the bottom of the window."""
        if hasattr(self, 'status_label'):
            self.status_label.config(text=message)
        if hasattr(self, 'progress_label'):
            self.progress_label.config(text=progress)

    def _set_processing(self, is_processing: bool, message: str = ""):
        """Set processing state - updates status bar and optionally disables/enables buttons."""
        if is_processing:
            self._set_status(message, "⏳ Processing...")
            if hasattr(self, 'status_label'):
                self.status_label.config(fg='#17a2b8')  # Cyan for active
        else:
            self._set_status(message if message else "Ready", "")
            if hasattr(self, 'status_label'):
                self.status_label.config(fg='#888888')  # Gray for idle

    # =========================================================================
    # Package Version Impact Analysis
    # =========================================================================

    def _show_package_impact(self):
        """Show the Package Version Impact analysis dialog."""
        if self.lifecycle_df is None or self.lifecycle_df.empty:
            messagebox.showwarning("No Data", "Please load vulnerability data first.")
            return

        self._log("Opening Package Version Impact dialog...")
        show_package_impact_dialog(self.window, self.lifecycle_df)

    # =========================================================================
    # Filter Defaults Configuration
    # =========================================================================

    def _show_filter_defaults(self):
        """Show dialog to configure default filter settings."""
        dialog = tk.Toplevel(self.window)
        dialog.title("Default Filter Settings")
        dialog.geometry("450x550")
        dialog.configure(bg=GUI_DARK_THEME['bg'])
        dialog.transient(self.window)
        dialog.grab_set()

        # Main frame with scrollable content
        main_frame = ttk.Frame(dialog, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text="Configure default filter values for new sessions:",
                 font=('TkDefaultFont', 10, 'bold')).pack(anchor=tk.W, pady=(0, 10))

        # Severity defaults
        sev_frame = ttk.LabelFrame(main_frame, text="Default Severity Filters", padding=10)
        sev_frame.pack(fill=tk.X, pady=5)

        sev_vars = {}
        current_severities = {
            'Critical': self.severity_toggles['Critical'].get(),
            'High': self.severity_toggles['High'].get(),
            'Medium': self.severity_toggles['Medium'].get(),
            'Low': self.severity_toggles['Low'].get(),
            'Info': self.severity_toggles['Info'].get(),
        }
        for sev in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            var = tk.BooleanVar(value=current_severities.get(sev, True))
            sev_vars[sev] = var
            ttk.Checkbutton(sev_frame, text=sev, variable=var).pack(anchor=tk.W)

        # Status default
        status_frame = ttk.LabelFrame(main_frame, text="Default Status Filter", padding=10)
        status_frame.pack(fill=tk.X, pady=5)

        status_var = tk.StringVar(value=self.filter_status.get())
        for status in ['All', 'Active', 'Resolved']:
            ttk.Radiobutton(status_frame, text=status, variable=status_var, value=status).pack(anchor=tk.W)

        # CVSS Range defaults
        cvss_frame = ttk.LabelFrame(main_frame, text="Default CVSS Range", padding=10)
        cvss_frame.pack(fill=tk.X, pady=5)

        cvss_row = ttk.Frame(cvss_frame)
        cvss_row.pack(fill=tk.X)
        ttk.Label(cvss_row, text="Min:").pack(side=tk.LEFT)
        cvss_min_var = tk.StringVar(value=self.filter_cvss_min.get())
        ttk.Entry(cvss_row, textvariable=cvss_min_var, width=8).pack(side=tk.LEFT, padx=5)
        ttk.Label(cvss_row, text="Max:").pack(side=tk.LEFT, padx=(10, 0))
        cvss_max_var = tk.StringVar(value=self.filter_cvss_max.get())
        ttk.Entry(cvss_row, textvariable=cvss_max_var, width=8).pack(side=tk.LEFT, padx=5)

        # Environment default
        env_frame = ttk.LabelFrame(main_frame, text="Default Environment Filter", padding=10)
        env_frame.pack(fill=tk.X, pady=5)

        env_var = tk.StringVar(value=self.filter_env_type.get())
        env_options = ['All Combined', 'Production', 'PSS', 'Shared', 'Unknown']
        ttk.OptionMenu(env_frame, env_var, env_var.get(), *env_options).pack(anchor=tk.W)

        # OPDIR Status default
        opdir_frame = ttk.LabelFrame(main_frame, text="Default OPDIR Status Filter", padding=10)
        opdir_frame.pack(fill=tk.X, pady=5)

        opdir_var = tk.StringVar(value=self.filter_opdir_status.get())
        opdir_options = ['All', 'On Track', 'Due Soon', 'Overdue', 'Unknown']
        ttk.OptionMenu(opdir_frame, opdir_var, opdir_var.get(), *opdir_options).pack(anchor=tk.W)

        # Auto-apply on startup
        auto_frame = ttk.LabelFrame(main_frame, text="Behavior", padding=10)
        auto_frame.pack(fill=tk.X, pady=5)

        auto_apply_var = tk.BooleanVar(value=getattr(self.settings_manager.settings, 'auto_apply_filters', True))
        ttk.Checkbutton(auto_frame, text="Auto-apply filters on data load", variable=auto_apply_var).pack(anchor=tk.W)

        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=(15, 0))

        def save_defaults():
            """Save the default filter settings."""
            try:
                # Update severity defaults
                for sev, var in sev_vars.items():
                    self.severity_toggles[sev].set(var.get())

                # Update other defaults
                self.filter_status.set(status_var.get())
                self.filter_cvss_min.set(cvss_min_var.get())
                self.filter_cvss_max.set(cvss_max_var.get())
                self.filter_env_type.set(env_var.get())
                self.filter_opdir_status.set(opdir_var.get())

                # Save to settings file
                settings = self.settings_manager.settings
                settings.default_severity_critical = sev_vars['Critical'].get()
                settings.default_severity_high = sev_vars['High'].get()
                settings.default_severity_medium = sev_vars['Medium'].get()
                settings.default_severity_low = sev_vars['Low'].get()
                settings.default_severity_info = sev_vars['Info'].get()
                settings.default_status = status_var.get()
                settings.default_cvss_min = float(cvss_min_var.get())
                settings.default_cvss_max = float(cvss_max_var.get())
                settings.default_env_type = env_var.get()
                settings.default_opdir_status = opdir_var.get()
                settings.auto_apply_filters = auto_apply_var.get()

                self.settings_manager.save()
                self._log("Default filter settings saved")
                messagebox.showinfo("Saved", "Default filter settings saved successfully.")
                dialog.destroy()

            except ValueError as e:
                messagebox.showerror("Invalid Input", f"Please enter valid values: {e}")

        def apply_now():
            """Apply the current settings immediately."""
            save_defaults()
            self._apply_filters()

        ttk.Button(btn_frame, text="Save", command=save_defaults, width=10).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Apply Now", command=apply_now, width=10).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=dialog.destroy, width=10).pack(side=tk.RIGHT)

    # =========================================================================
    # AI Predictions Integration
    # =========================================================================

    def _init_ai_client_async(self):
        """Initialize AI client asynchronously on startup."""
        import threading

        def _check_ai():
            if self.settings_manager.is_ai_configured():
                try:
                    from ..ai.openwebui_client import OpenWebUIClient, OpenWebUIConfig

                    ai_settings = self.settings_manager.ai_settings
                    config = OpenWebUIConfig(
                        base_url=ai_settings.base_url,
                        api_key=ai_settings.api_key,
                        model=ai_settings.model
                    )
                    client = OpenWebUIClient(config)

                    # Test connection and refresh models
                    if client.test_connection():
                        models = client.refresh_models()
                        model_count = len(models)

                        # Check if configured model is available
                        if ai_settings.model and ai_settings.model not in models:
                            self.window.after(0, lambda: self._update_ai_status(
                                f"AI: Model '{ai_settings.model}' not found",
                                "orange"
                            ))
                        else:
                            self.window.after(0, lambda: self._update_ai_status(
                                f"AI: Ready ({model_count} models)",
                                "green"
                            ))
                    else:
                        self.window.after(0, lambda: self._update_ai_status(
                            "AI: Connection failed",
                            "red"
                        ))
                except Exception as e:
                    self.window.after(0, lambda: self._update_ai_status(
                        f"AI: Error - {str(e)[:30]}",
                        "red"
                    ))
            else:
                self.window.after(0, lambda: self._update_ai_status(
                    "AI: Not configured",
                    "gray"
                ))

        thread = threading.Thread(target=_check_ai, daemon=True)
        thread.start()

    def _update_ai_status(self, message: str, color: str):
        """Update AI status label."""
        if hasattr(self, 'ai_status_label'):
            self.ai_status_label.config(text=message, foreground=color)

    def _run_ai_analysis(self):
        """Run AI analysis from button click."""
        if hasattr(self, 'menu_bar') and self.menu_bar:
            self.menu_bar._run_ai_analysis()

    def _show_ai_settings(self):
        """Show AI settings dialog."""
        try:
            from .ai_settings_dialog import show_ai_settings_dialog
        except ImportError:
            from refactored_app.gui.ai_settings_dialog import show_ai_settings_dialog

        def on_save():
            self._log("AI settings saved")
            self._init_ai_client_async()  # Re-check connection

        show_ai_settings_dialog(
            parent=self.window,
            settings_manager=self.settings_manager,
            on_save=on_save
        )

    def _show_threat_intel_dialog(self):
        """Show threat intel configuration dialog."""
        try:
            from .threat_intel_dialog import show_threat_intel_dialog
        except ImportError:
            from refactored_app.gui.threat_intel_dialog import show_threat_intel_dialog

        show_threat_intel_dialog(
            parent=self.window,
            settings_manager=self.settings_manager,
            on_sync_complete=lambda stats: self._log(
                f"Threat intel sync: {stats.get('total_records', 0)} records synced"
            )
        )

    def _quick_sync_threat_intel(self):
        """Quick sync threat intelligence."""
        if not self.settings_manager.is_ai_configured():
            messagebox.showwarning(
                "Not Configured",
                "Please configure AI settings first."
            )
            self._show_ai_settings()
            return

        self._show_threat_intel_dialog()

    def run(self):
        """Run the application."""
        self._log("Nessus History Tracker v2.0 started")
        self._log("Select archives or load existing database to begin")
        self.window.mainloop()
