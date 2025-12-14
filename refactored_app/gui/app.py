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
        self.filter_env_type = tk.StringVar(value="All")  # Production/Pre-Production
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
        self._apply_settings_to_ui()

        # Build UI
        self._setup_styles()
        self._build_ui()

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

        # Row 3: Severity toggle buttons with colored highlights
        sev_row = ttk.Frame(filter_frame)
        sev_row.pack(fill=tk.X, pady=3)
        ttk.Label(sev_row, text="Severity:", width=8).pack(side=tk.LEFT)

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

        # Row 3b: Status filter
        status_row = ttk.Frame(filter_frame)
        status_row.pack(fill=tk.X, pady=3)
        ttk.Label(status_row, text="Status:", width=8).pack(side=tk.LEFT)
        ttk.Combobox(status_row, textvariable=self.filter_status,
                    values=["All", "Active", "Resolved"], state="readonly", width=10).pack(side=tk.LEFT, padx=1)

        # Row 4: Host Type + Env Type (inline)
        host_row = ttk.Frame(filter_frame)
        host_row.pack(fill=tk.X, pady=3)
        ttk.Label(host_row, text="Type:", width=8).pack(side=tk.LEFT)
        ttk.Combobox(host_row, textvariable=self.filter_host_type,
                    values=["All", "Physical", "Virtual", "ILOM"], state="readonly", width=8).pack(side=tk.LEFT, padx=1)
        ttk.Label(host_row, text="Env:").pack(side=tk.LEFT, padx=(5, 0))
        ttk.Combobox(host_row, textvariable=self.filter_env_type,
                    values=["All", "Production", "PSS", "Shared"], state="readonly", width=9).pack(side=tk.LEFT, padx=1)

        # Row 5: Location + Host Pattern (inline)
        loc_row = ttk.Frame(filter_frame)
        loc_row.pack(fill=tk.X, pady=3)
        ttk.Label(loc_row, text="Loc:", width=8).pack(side=tk.LEFT)
        ttk.Entry(loc_row, textvariable=self.filter_location, width=6).pack(side=tk.LEFT, padx=1)
        ttk.Label(loc_row, text="Host:").pack(side=tk.LEFT, padx=(5, 0))
        ttk.Entry(loc_row, textvariable=self.filter_host, width=10).pack(side=tk.LEFT, padx=1)
        ttk.Button(loc_row, text="...", command=self._show_host_selector, width=2).pack(side=tk.LEFT, padx=1)
        self.host_count_label = ttk.Label(loc_row, text="", foreground="cyan", width=6)
        self.host_count_label.pack(side=tk.LEFT)

        # Row 6: CVSS Range (inline)
        cvss_row = ttk.Frame(filter_frame)
        cvss_row.pack(fill=tk.X, pady=3)
        ttk.Label(cvss_row, text="CVSS:", width=8).pack(side=tk.LEFT)
        ttk.Entry(cvss_row, textvariable=self.filter_cvss_min, width=5).pack(side=tk.LEFT, padx=1)
        ttk.Label(cvss_row, text="-").pack(side=tk.LEFT)
        ttk.Entry(cvss_row, textvariable=self.filter_cvss_max, width=5).pack(side=tk.LEFT, padx=1)

        # Row 7: OPDIR Status filter
        opdir_row = ttk.Frame(filter_frame)
        opdir_row.pack(fill=tk.X, pady=3)
        ttk.Label(opdir_row, text="OPDIR:", width=8).pack(side=tk.LEFT)
        opdir_options = ["All", "Overdue", "Due Soon", "On Track", "OPDIR Mapped", "No OPDIR"]
        ttk.Combobox(opdir_row, textvariable=self.filter_opdir_status,
                    values=opdir_options, state="readonly", width=12).pack(side=tk.LEFT, padx=1)

        # Row 8: CVE and IAVX filters
        vuln_row = ttk.Frame(filter_frame)
        vuln_row.pack(fill=tk.X, pady=3)
        ttk.Label(vuln_row, text="CVE:", width=8).pack(side=tk.LEFT)
        ttk.Entry(vuln_row, textvariable=self.filter_cve, width=15).pack(side=tk.LEFT, padx=1)

        iavx_row = ttk.Frame(filter_frame)
        iavx_row.pack(fill=tk.X, pady=3)
        ttk.Label(iavx_row, text="IAV:", width=8).pack(side=tk.LEFT)
        ttk.Entry(iavx_row, textvariable=self.filter_iavx, width=15).pack(side=tk.LEFT, padx=1)

        # Row 9: Apply and Reset buttons
        btn_row = ttk.Frame(filter_frame)
        btn_row.pack(fill=tk.X, pady=3)
        ttk.Button(btn_row, text="Apply", command=self._apply_filters, width=10).pack(side=tk.LEFT, padx=1)
        ttk.Button(btn_row, text="Reset", command=self._reset_filters, width=10).pack(side=tk.LEFT, padx=1)

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

            # Top risky hosts
            self.risk_ax4 = self.risk_fig.add_subplot(224)
            self.risk_ax4.set_title('Top 10 Risky Hosts', color=GUI_DARK_THEME['fg'])

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

            # Top recurring plugins
            self.plugin_ax1 = self.plugin_fig.add_subplot(221)
            self.plugin_ax1.set_title('Top 15 Most Common Plugins', color=GUI_DARK_THEME['fg'])

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

            # Bind double-click for pop-out
            hint = ttk.Label(plugin_frame, text="Double-click chart to pop-out",
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

    def _get_environment_type(self, hostname: str) -> str:
        """
        Classify hostname by environment type (Production/PSS/Shared/Unknown).

        Args:
            hostname: The hostname to classify

        Returns:
            Environment label string
        """
        if not isinstance(hostname, str) or not hostname:
            return 'Unknown'

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
        """Process selected archives."""
        if not self.archive_paths and not self.existing_db_path:
            messagebox.showwarning("No Data", "Please select archives or an existing database")
            return

        try:
            self._log("Starting processing...")

            # Load plugins database first (needed for processing new archives)
            if self.plugins_db_path:
                self._log("Loading plugins database...")
                self.plugins_dict = load_plugins_database(self.plugins_db_path)

            # Process archives or load existing DB FIRST
            if self.existing_db_path and not self.archive_paths:
                self._load_existing_database()
            else:
                self._process_new_archives()

            # After loading database, check if we need to load OPDIR from file
            # Only load from file if: file selected AND (no data in DB OR file is different)
            if self.opdir_file_path:
                if self.opdir_df.empty:
                    self._log("Loading OPDIR mapping from file...")
                    self.opdir_df = load_opdir_mapping(self.opdir_file_path)
                    if not self.opdir_df.empty:
                        self._log(f"Loaded {len(self.opdir_df)} OPDIR mappings from file")
                else:
                    self._log(f"Using {len(self.opdir_df)} OPDIR mappings from database")

            # Same for IAVM notices
            if self.iavm_file_path:
                if self.iavm_df.empty:
                    self._log("Loading IAVM notice summaries from file...")
                    self.iavm_df = load_iavm_summaries(self.iavm_file_path)
                    if not self.iavm_df.empty:
                        self._log(f"Loaded {len(self.iavm_df)} IAVM notices from file")
                else:
                    self._log(f"Using {len(self.iavm_df)} IAVM notices from database")

            # Set date filter defaults
            if not self.historical_df.empty and 'scan_date' in self.historical_df.columns:
                # Ensure scan_date is datetime for min/max operations
                scan_dates = pd.to_datetime(self.historical_df['scan_date'])
                start_date = scan_dates.min().strftime('%Y-%m-%d')
                end_date = scan_dates.max().strftime('%Y-%m-%d')
                self.filter_start_date.set(start_date)
                self.filter_end_date.set(end_date)

            # Auto-save informational findings to yearly databases
            self._auto_save_info_findings()

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
        self._update_dashboard()
        self._update_lifecycle_tree()
        self._update_host_tree()
        self._update_all_visualizations()

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
        env_type = self.filter_env_type.get()
        if env_type != "All" and 'hostname' in filtered.columns:
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

        # Update filter status label
        if filter_descriptions:
            status_text = " | ".join(filter_descriptions)
            self.filter_status_label.config(text=status_text, foreground="#00ff00")
        else:
            self.filter_status_label.config(text="No filters applied", foreground="gray")

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
        self.filter_env_type.set("All")
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
        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df

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

        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df

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
        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df
        total = len(df)
        page_size = self.lifecycle_page_size.get()
        if page_size > 0:
            new_start = self.lifecycle_current_start + page_size
            if new_start < total:
                self.lifecycle_current_start = new_start
                self._update_lifecycle_tree()

    def _lifecycle_last_page(self):
        """Navigate to last page."""
        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df
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
            df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df
            total = len(df)
            if 0 <= target < total:
                self.lifecycle_current_start = target
                self._update_lifecycle_tree()
            else:
                messagebox.showwarning("Invalid Row", f"Row number must be between 1 and {total}")
        except ValueError:
            messagebox.showwarning("Invalid Input", "Please enter a valid row number")

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

        # Use scan_changes_df to show trends over time
        if not self.scan_changes_df.empty and 'scan_date' in self.scan_changes_df.columns:
            df = self.scan_changes_df.copy()
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
        elif not self.historical_df.empty and 'scan_date' in self.historical_df.columns:
            df = self.historical_df.copy()
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

        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df
        hist_df = self.historical_df
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
        self.timeline_ax1.text(0.5, 1.02, f'Vulnerability count trend ({interval_label.lower()}ly grouping)',
            transform=self.timeline_ax1.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')
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
        self.timeline_ax2.text(0.5, 1.02, 'Critical/High/Medium/Low breakdown over time',
            transform=self.timeline_ax2.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')

        # Chart 3: New vs Resolved with data labels (grouped by interval)
        if not self.scan_changes_df.empty and 'change_type' in self.scan_changes_df.columns:
            changes = self.scan_changes_df.copy()
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
        self.timeline_ax3.text(0.5, 1.02, f'{interval_label}ly new vs resolved vulnerability comparison',
            transform=self.timeline_ax3.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')

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
        self.timeline_ax4.text(0.5, 1.02, 'Running total of severity-weighted risk score',
            transform=self.timeline_ax4.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')

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

        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df

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
        self.risk_ax1.text(0.5, 1.02, 'Distribution of CVSS v3 scores by severity level',
            transform=self.risk_ax1.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')
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
        self.risk_ax2.text(0.5, 1.02, 'Average days to resolve by severity level',
            transform=self.risk_ax2.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')
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
        self.risk_ax3.text(0.5, 1.02, 'Urgency buckets for unresolved vulnerabilities',
            transform=self.risk_ax3.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')
        self.risk_ax3.set_xlabel('Days Open', color=GUI_DARK_THEME['fg'])

        # Chart 4: Top risky hosts colored by environment type
        if 'hostname' in df.columns and 'severity_value' in df.columns:
            host_risk = df.groupby('hostname')['severity_value'].sum().nlargest(10)
            if len(host_risk) > 0:
                # Color by environment type
                env_colors = {'Production': '#28a745', 'PSS': '#007bff', 'Shared': '#ffc107', 'Unknown': '#6c757d'}
                colors = [env_colors.get(self._get_environment_type(h), '#6c757d') for h in host_risk.index]
                bars = self.risk_ax4.barh(range(len(host_risk)), host_risk.values, color=colors)
                self.risk_ax4.set_yticks(range(len(host_risk)))
                self.risk_ax4.set_yticklabels([h[:15] for h in host_risk.index], fontsize=7)
                if show_labels:
                    for bar, val in zip(bars, host_risk.values):
                        self.risk_ax4.annotate(f'{int(val)}', xy=(val, bar.get_y() + bar.get_height()/2),
                                              xytext=(3, 0), textcoords='offset points',
                                              ha='left', va='center', fontsize=6, color='white')
                self.risk_ax4.invert_yaxis()
                # Add legend for environment colors
                from matplotlib.patches import Patch
                legend_elements = [Patch(facecolor='#28a745', label='Prod'),
                                   Patch(facecolor='#007bff', label='PSS'),
                                   Patch(facecolor='#ffc107', label='Shared')]
                self.risk_ax4.legend(handles=legend_elements, loc='lower right', fontsize=6,
                                    facecolor=GUI_DARK_THEME['bg'], labelcolor=GUI_DARK_THEME['fg'])
        self.risk_ax4.set_title('Top 10 Risky Hosts by Environment', color=GUI_DARK_THEME['fg'], fontsize=10)
        self.risk_ax4.text(0.5, 1.02, 'Green=Prod, Blue=PSS, Yellow=Shared',
            transform=self.risk_ax4.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')
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

    def _draw_cvss_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw CVSS distribution chart for pop-out."""
        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df
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
        """Draw MTTR by severity chart for pop-out."""
        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df
        if df.empty or 'severity_text' not in df.columns or 'days_open' not in df.columns:
            ax.text(0.5, 0.5, 'No MTTR data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        resolved = df[df['status'] == 'Resolved']
        if resolved.empty:
            ax.text(0.5, 0.5, 'No resolved findings', ha='center', va='center',
                   color='white', fontsize=12)
            return

        resolved = resolved.copy()
        resolved['days_open'] = pd.to_numeric(resolved['days_open'], errors='coerce')
        mttr = resolved.groupby('severity_text')['days_open'].mean()
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
        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df
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
        """Draw top risky hosts chart for pop-out."""
        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df
        if df.empty or 'hostname' not in df.columns or 'severity_value' not in df.columns:
            ax.text(0.5, 0.5, 'No host risk data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        # Show more hosts in pop-out
        num_hosts = 15 if enlarged else 10
        host_risk = df.groupby('hostname')['severity_value'].sum().nlargest(num_hosts)

        if len(host_risk) == 0:
            ax.text(0.5, 0.5, 'No host data', ha='center', va='center',
                   color='white', fontsize=12)
            return

        # Color gradient
        max_risk = host_risk.max()
        colors = ['#dc3545' if r > max_risk * 0.7 else '#fd7e14' if r > max_risk * 0.4 else '#ffc107'
                 for r in host_risk.values]

        bars = ax.barh(range(len(host_risk)), host_risk.values, color=colors)
        ax.set_yticks(range(len(host_risk)))
        ax.set_yticklabels([h[:20] for h in host_risk.index], fontsize=9)

        if show_labels:
            for bar, val in zip(bars, host_risk.values):
                ax.annotate(f'{int(val)}',
                           xy=(val, bar.get_y() + bar.get_height() / 2),
                           xytext=(3, 0), textcoords='offset points',
                           ha='left', va='center', fontsize=9, color='white')

        ax.set_title(f'Top {num_hosts} Risky Hosts (by Severity Score)')
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
        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df
        hist_df = self.historical_df

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
        hist_df = self.historical_df

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
        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df

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
        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df
        hist_df = self.historical_df

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
        hist_df = self.historical_df

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
        hist_df = self.historical_df

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
        df = self.lifecycle_df

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
        hist_df = self.historical_df

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
        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df

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
        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df

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
        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df

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
        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df

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
        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df

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
        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df

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
        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df

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
        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df

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
        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df

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
        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df

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
        df = self.lifecycle_df

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
                ('Network Segment Analysis', self._draw_network_segment_popout),
            ]
            title, redraw_func = chart_info[quadrant]
            ChartPopoutModal(self.window, title, redraw_func)

        self.network_canvas.get_tk_widget().bind('<Double-Button-1>', on_double_click)

    def _draw_top_subnets_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw top subnets by vulnerability count for pop-out."""
        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df

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
        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df

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
        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df

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
        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df

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
        """Draw top most common plugins for pop-out."""
        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df

        if df.empty or 'plugin_id' not in df.columns:
            ax.text(0.5, 0.5, 'No plugin data available', ha='center', va='center',
                   color='white', fontsize=12)
            return

        num_plugins = 20 if enlarged else 15
        plugin_counts = df['plugin_id'].value_counts().head(num_plugins)

        if len(plugin_counts) == 0:
            ax.text(0.5, 0.5, 'No plugin data', ha='center', va='center', color='white', fontsize=12)
            return

        bars = ax.barh(range(len(plugin_counts)), plugin_counts.values, color='#17a2b8')
        ax.set_yticks(range(len(plugin_counts)))

        # Try to get plugin names if available
        if 'plugin_name' in df.columns:
            plugin_names = df.groupby('plugin_id')['plugin_name'].first()
            labels = [str(plugin_names.get(pid, pid))[:30] for pid in plugin_counts.index]
        else:
            labels = [str(pid) for pid in plugin_counts.index]

        ax.set_yticklabels(labels, fontsize=7)

        if show_labels:
            for bar, val in zip(bars, plugin_counts.values):
                ax.annotate(f'{int(val)}', xy=(val, bar.get_y() + bar.get_height()/2),
                           xytext=(3, 0), textcoords='offset points',
                           ha='left', va='center', fontsize=7, color='white')

        ax.set_title(f'Top {num_plugins} Most Common Plugins')
        ax.set_xlabel('Finding Count')
        ax.invert_yaxis()

    def _draw_plugin_severity_popout(self, fig, ax, enlarged=False, show_labels=True):
        """Draw plugin severity distribution for pop-out."""
        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df

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
        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df

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
        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df

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
        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df

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
        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df

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
        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df

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
        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df

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
        hist_df = self.historical_df

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
        hist_df = self.historical_df

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
        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df

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
        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df
        hist_df = self.historical_df

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
        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df

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
        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df

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
        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df
        hist_df = self.historical_df

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
        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df

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
        hist_df = self.historical_df

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

        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df

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
        self.opdir_ax1.text(0.5, 1.02, 'Findings linked to OPDIR directives vs unmapped',
            transform=self.opdir_ax1.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')

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
        self.opdir_ax2.text(0.5, 1.02, 'Compliance status: Overdue/Due Soon/On Track',
            transform=self.opdir_ax2.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')
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
        self.opdir_ax3.text(0.5, 1.02, 'Age distribution of findings with OPDIR assignments',
            transform=self.opdir_ax3.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')
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
        self.opdir_ax4.text(0.5, 1.02, 'Status breakdown by directive release year',
            transform=self.opdir_ax4.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')
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

        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df
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
        self.efficiency_ax1.text(0.5, 1.02, 'How consistently hosts appear across scans',
            transform=self.efficiency_ax1.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')
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
        self.efficiency_ax2.text(0.5, 1.02, 'Vulnerabilities recurring after remediation',
            transform=self.efficiency_ax2.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')
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
        self.efficiency_ax3.text(0.5, 1.02, 'Number of vulnerabilities per host distribution',
            transform=self.efficiency_ax3.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')
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
        self.efficiency_ax4.text(0.5, 1.02, 'How quickly vulnerabilities are resolved',
            transform=self.efficiency_ax4.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')
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

        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df
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
        self.network_ax1.text(0.5, 1.02, 'Network segments with most vulnerabilities',
            transform=self.network_ax1.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')
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
        self.network_ax2.text(0.5, 1.02, 'Severity-weighted risk by network segment',
            transform=self.network_ax2.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')
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
        self.network_ax3.text(0.5, 1.02, 'Distribution of host-level risk scores',
            transform=self.network_ax3.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')
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
        self.network_ax4.text(0.5, 1.02, 'Findings by environment type (Prod/PSS/Shared)',
            transform=self.network_ax4.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')

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

        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df
        show_labels = self.settings_manager.settings.show_data_labels

        for ax in [self.plugin_ax1, self.plugin_ax2, self.plugin_ax3, self.plugin_ax4]:
            ax.clear()
            ax.set_facecolor(GUI_DARK_THEME['entry_bg'])

        if df.empty:
            self.plugin_canvas.draw()
            return

        # Chart 1: Top 15 most common plugins with data labels
        if 'plugin_id' in df.columns:
            plugin_counts = df.groupby('plugin_id').size().nlargest(15)
            if len(plugin_counts) > 0:
                # Get plugin names if available
                if 'plugin_name' in df.columns:
                    names = df.groupby('plugin_id')['plugin_name'].first()
                    labels = [str(names.get(pid, pid))[:22] for pid in plugin_counts.index]
                else:
                    labels = [str(pid) for pid in plugin_counts.index]
                bars = self.plugin_ax1.barh(range(len(plugin_counts)), plugin_counts.values, color='#007bff')
                self.plugin_ax1.set_yticks(range(len(plugin_counts)))
                self.plugin_ax1.set_yticklabels(labels, fontsize=6)
                self.plugin_ax1.invert_yaxis()
                if show_labels:
                    for bar, val in zip(bars, plugin_counts.values):
                        self.plugin_ax1.annotate(f'{int(val)}', xy=(val, bar.get_y() + bar.get_height()/2),
                                                xytext=(3, 0), textcoords='offset points',
                                                ha='left', va='center', fontsize=5, color='white')
                # Total unique plugins
                total_plugins = df['plugin_id'].nunique()
                self.plugin_ax1.text(0.98, 0.98, f'Total: {total_plugins}', transform=self.plugin_ax1.transAxes,
                                    fontsize=7, va='top', ha='right', color='white')
        self.plugin_ax1.set_title('Top 15 Most Common Plugins', color=GUI_DARK_THEME['fg'], fontsize=10)
        self.plugin_ax1.text(0.5, 1.02, 'Most frequently detected vulnerabilities',
            transform=self.plugin_ax1.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')
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
        self.plugin_ax2.text(0.5, 1.02, 'Vulnerability severity level breakdown',
            transform=self.plugin_ax2.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')
        self.plugin_ax2.set_ylabel('Count', color=GUI_DARK_THEME['fg'])

        # Chart 3: Plugins affecting most hosts with data labels
        if 'plugin_id' in df.columns and 'hostname' in df.columns:
            plugin_hosts = df.groupby('plugin_id')['hostname'].nunique().nlargest(10)
            if len(plugin_hosts) > 0:
                if 'plugin_name' in df.columns:
                    names = df.groupby('plugin_id')['plugin_name'].first()
                    labels = [str(names.get(pid, pid))[:18] for pid in plugin_hosts.index]
                else:
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
        self.plugin_ax3.set_title('Plugins Affecting Most Hosts', color=GUI_DARK_THEME['fg'], fontsize=10)
        self.plugin_ax3.text(0.5, 1.02, 'Widespread vulnerabilities across environment',
            transform=self.plugin_ax3.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')
        self.plugin_ax3.set_xlabel('Host Count', color=GUI_DARK_THEME['fg'])

        # Chart 4: Plugin average age with color coding
        if 'plugin_id' in df.columns and 'days_open' in df.columns:
            df_age = df.copy()
            df_age['days_open'] = pd.to_numeric(df_age['days_open'], errors='coerce')
            plugin_age = df_age.groupby('plugin_id')['days_open'].mean().nlargest(10)
            if len(plugin_age) > 0:
                if 'plugin_name' in df.columns:
                    names = df.groupby('plugin_id')['plugin_name'].first()
                    labels = [str(names.get(pid, pid))[:18] for pid in plugin_age.index]
                else:
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
        self.plugin_ax4.set_title('Plugins with Longest Avg Age', color=GUI_DARK_THEME['fg'], fontsize=10)
        self.plugin_ax4.text(0.5, 1.02, 'Vulnerabilities persisting the longest',
            transform=self.plugin_ax4.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')
        self.plugin_ax4.set_xlabel('Days Open', color=GUI_DARK_THEME['fg'])

        for ax in [self.plugin_ax1, self.plugin_ax2, self.plugin_ax3, self.plugin_ax4]:
            ax.tick_params(colors=GUI_DARK_THEME['fg'])
            for spine in ax.spines.values():
                spine.set_color(GUI_DARK_THEME['fg'])

        self.plugin_fig.tight_layout()
        self.plugin_canvas.draw()

    def _update_priority_charts(self):
        """Update remediation priority visualizations (CVSS vs Age quadrant)."""
        if not HAS_MATPLOTLIB or not hasattr(self, 'priority_ax1'):
            return

        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df
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
        self.priority_ax1.text(0.5, 1.02, 'Prioritize by CVSS score and age combination',
            transform=self.priority_ax1.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')
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
        self.priority_ax2.text(0.5, 1.02, 'Breakdown by urgency level',
            transform=self.priority_ax2.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')

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
        self.priority_ax3.text(0.5, 1.02, 'Most urgent vulnerabilities to address',
            transform=self.priority_ax3.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')
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
        self.priority_ax4.text(0.5, 1.02, 'Average urgency score by severity level',
            transform=self.priority_ax4.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')
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

        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df

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
        self.sla_ax2.text(0.5, 1.02, 'SLA breaches by severity level',
            transform=self.sla_ax2.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')
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
        self.sla_ax3.text(0.5, 1.02, 'Findings nearing SLA expiration',
            transform=self.sla_ax3.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')
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
        self.sla_ax4.text(0.5, 1.02, 'Time to deadline distribution (neg=overdue)',
            transform=self.sla_ax4.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')
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
        hist_df = self.historical_df

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
        self.host_tracking_ax1.text(0.5, 1.02, 'Hosts not seen in recent vulnerability scans',
            transform=self.host_tracking_ax1.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')
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
        self.host_tracking_ax2.text(0.5, 1.02, 'Unique hosts per scan over time',
            transform=self.host_tracking_ax2.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')
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
        self.host_tracking_ax3.text(0.5, 1.02, 'Hosts with intermittent scan coverage',
            transform=self.host_tracking_ax3.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')
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
        """Update advanced metrics visualizations with industry KPIs."""
        if not HAS_MATPLOTLIB or not hasattr(self, 'metrics_ax1'):
            return

        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df
        hist_df = self.historical_df

        for ax in [self.metrics_ax1, self.metrics_ax2, self.metrics_ax3, self.metrics_ax4]:
            ax.clear()
            ax.set_facecolor(GUI_DARK_THEME['entry_bg'])

        if df.empty:
            # Reset KPI labels
            for key in self.kpi_labels:
                self.kpi_labels[key].config(text="--")
            self.metrics_canvas.draw()
            return

        # Get SLA targets from settings
        sla_targets = self.settings_manager.settings.get_sla_targets()
        sla_targets = {k: v for k, v in sla_targets.items() if v is not None}

        # Calculate metrics
        reopen_metrics = calculate_reopen_rate(df)
        remediation_metrics = calculate_remediation_rate(df, hist_df)
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
        self.metrics_ax1.text(0.5, 1.02, 'Remediated vs active findings per severity',
            transform=self.metrics_ax1.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')
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
        self.metrics_ax2.text(0.5, 1.02, 'Organization-wide risk trend over time',
            transform=self.metrics_ax2.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')
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
        self.metrics_ax3.text(0.5, 1.02, 'SLA compliance breakdown per severity',
            transform=self.metrics_ax3.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')
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
        self.metrics_ax4.text(0.5, 1.02, 'Average vulnerabilities per host over time',
            transform=self.metrics_ax4.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')
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

        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df
        hist_df = self.historical_df
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
        ax.text(0.5, 1.02, 'Vulnerability density: darker = more findings',
            transform=ax.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')

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
        ax.text(0.5, 1.02, 'Bubble size = hosts affected; Color = severity',
            transform=ax.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')

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
        ax.text(0.5, 1.02, 'Lifecycle status flow from discovery to resolution',
            transform=ax.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')
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
        ax.text(0.5, 1.02, 'Vulnerability distribution by plugin category',
            transform=ax.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')

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
        ax.text(0.5, 1.02, 'Earlier vs Recent period metrics comparison',
            transform=ax.transAxes, ha='center', va='bottom', fontsize=7, color='#888888')
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
        """Add message to status log."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.status_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.status_text.see(tk.END)
        self.window.update()

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
