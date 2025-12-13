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
from ..analysis.advanced_metrics import (
    get_all_advanced_metrics, calculate_reopen_rate, calculate_coverage_metrics,
    calculate_remediation_rate, calculate_sla_breach_tracking, calculate_normalized_metrics,
    calculate_risk_reduction_trend
)
from ..filters.filter_engine import FilterEngine, apply_filters
from ..filters.hostname_parser import parse_hostname, HostType
from ..filters.custom_lists import FilterListManager, FilterList
from ..export.sqlite_export import export_to_sqlite
from ..export.excel_export import export_to_excel
from ..export.json_export import export_to_json
from ..settings import SettingsManager, UserSettings
from .chart_utils import (
    add_data_labels, add_horizontal_data_labels, add_line_data_labels,
    ChartPopoutModal
)


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

        # Filtered data for display
        self.filtered_lifecycle_df = pd.DataFrame()
        self.filtered_host_df = pd.DataFrame()

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

        # Advanced host filtering
        self.filter_host_list: List[str] = []  # Specific hostnames selected
        self.filter_list_manager = FilterListManager()  # Saved filter lists

        # Lifecycle navigation state
        self.lifecycle_page_size = tk.IntVar(value=100)
        self.lifecycle_current_start = 0  # Starting index for pagination
        self.lifecycle_jump_to = tk.StringVar()

        # Chart pop-out redraw functions (populated after UI build)
        self.chart_redraw_funcs: Dict[str, Any] = {}

        # Settings manager
        self.settings_manager = SettingsManager()
        self._apply_settings_to_ui()

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

        # Row 8: Apply and Reset buttons
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

        # Left side: count label
        self.lifecycle_count_label = ttk.Label(nav_frame, text="Showing 0 findings")
        self.lifecycle_count_label.pack(side=tk.LEFT)

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

        # Info label
        info_frame = ttk.Frame(host_frame)
        info_frame.pack(fill=tk.X, padx=5, pady=5)
        self.host_count_label = ttk.Label(info_frame, text="Showing 0 hosts")
        self.host_count_label.pack(side=tk.LEFT)

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
        else:
            ttk.Label(host_tracking_frame, text="Install matplotlib for visualizations").pack(pady=50)

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
            if not self.historical_df.empty and 'scan_date' in self.historical_df.columns:
                # Ensure scan_date is datetime for min/max operations
                scan_dates = pd.to_datetime(self.historical_df['scan_date'])
                start_date = scan_dates.min().strftime('%Y-%m-%d')
                end_date = scan_dates.max().strftime('%Y-%m-%d')
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

        # Initialize filtered data and update displays
        self.filtered_lifecycle_df = self.lifecycle_df.copy()
        self.filtered_host_df = self.host_presence_df.copy()
        self._update_dashboard()
        self._update_lifecycle_tree()
        self._update_host_tree()
        self._update_all_visualizations()

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

        # Reset host list filter
        self.filter_host_list = []
        self._update_host_count_label()

        # Reset date filters to data range if available
        if not self.historical_df.empty and 'scan_date' in self.historical_df.columns:
            scan_dates = pd.to_datetime(self.historical_df['scan_date'])
            self.filter_start_date.set(scan_dates.min().strftime('%Y-%m-%d'))
            self.filter_end_date.set(scan_dates.max().strftime('%Y-%m-%d'))
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
            avg_days = df['days_open'].mean()
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

    def _update_lifecycle_tree(self):
        """Update lifecycle treeview with filtered data and pagination."""
        # Clear existing items
        for item in self.lifecycle_tree.get_children():
            self.lifecycle_tree.delete(item)

        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df

        if df.empty:
            self.lifecycle_count_label.config(text="Showing 0 findings")
            return

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
                str(plugin_name)[:50] if plugin_name else '',  # Truncate long names
                row.get('severity_text', row.get('severity', '')),
                row.get('status', ''),
                str(row.get('first_seen', ''))[:10],
                str(row.get('last_seen', ''))[:10],
                row.get('days_open', '')
            )
            self.lifecycle_tree.insert('', tk.END, values=values)

        # Update count label with range info
        if page_size == 0:
            label_text = f"Showing all {total} findings"
        else:
            label_text = f"Showing {start + 1}-{end} of {total} findings"
        self.lifecycle_count_label.config(text=label_text)

    def _update_host_tree(self):
        """Update host treeview with filtered data."""
        # Clear existing items
        for item in self.host_tree.get_children():
            self.host_tree.delete(item)

        df = self.filtered_host_df if not self.filtered_host_df.empty else self.host_presence_df

        if df.empty:
            self.host_count_label.config(text="Showing 0 hosts")
            return

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

            values = (
                hostname,
                row.get('ip_address', ''),
                row.get('status', ''),
                str(row.get('first_seen', ''))[:10],
                str(row.get('last_seen', ''))[:10],
                row.get('scan_count', row.get('scans_present', '')),
                f"{row.get('presence_percentage', 0):.1f}%" if 'presence_percentage' in row else '',
                host_type
            )
            self.host_tree.insert('', tk.END, values=values)

        total = len(df)
        shown = len(display_df)
        label_text = f"Showing {shown} of {total} hosts" if shown < total else f"Showing {total} hosts"
        self.host_count_label.config(text=label_text)

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

        # Use scan_changes_df to show trends over time
        if not self.scan_changes_df.empty and 'scan_date' in self.scan_changes_df.columns:
            df = self.scan_changes_df.copy()
            df['scan_date'] = pd.to_datetime(df['scan_date'])

            # Group by date and count new/resolved
            if 'change_type' in df.columns:
                trends = df.groupby([df['scan_date'].dt.date, 'change_type']).size().unstack(fill_value=0)

                if 'New' in trends.columns:
                    self.trends_ax.plot(trends.index, trends['New'], 'r-', label='New', marker='o', markersize=4)
                if 'Resolved' in trends.columns:
                    self.trends_ax.plot(trends.index, trends['Resolved'], 'g-', label='Resolved', marker='s', markersize=4)

                self.trends_ax.legend(loc='upper right', facecolor=GUI_DARK_THEME['bg'],
                                     labelcolor=GUI_DARK_THEME['fg'])

        # If no scan_changes, try to use historical_df to show cumulative counts
        elif not self.historical_df.empty and 'scan_date' in self.historical_df.columns:
            df = self.historical_df.copy()
            df['scan_date'] = pd.to_datetime(df['scan_date'])

            # Count findings per scan date
            counts = df.groupby(df['scan_date'].dt.date).size()

            self.trends_ax.bar(range(len(counts)), counts.values, color='#007bff', alpha=0.7)
            self.trends_ax.set_xticks(range(len(counts)))
            self.trends_ax.set_xticklabels([str(d) for d in counts.index], rotation=45, ha='right', fontsize=8)

        # Style the chart
        self.trends_ax.set_xlabel('Date', color=GUI_DARK_THEME['fg'])
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

        # Clear all axes
        for ax in [self.timeline_ax1, self.timeline_ax2, self.timeline_ax3, self.timeline_ax4]:
            ax.clear()
            ax.set_facecolor(GUI_DARK_THEME['entry_bg'])

        if hist_df.empty:
            self.timeline_canvas.draw()
            return

        hist_df = hist_df.copy()
        hist_df['scan_date'] = pd.to_datetime(hist_df['scan_date'])

        # Chart 1: Total findings over time
        counts = hist_df.groupby(hist_df['scan_date'].dt.date).size()
        self.timeline_ax1.plot(range(len(counts)), counts.values, 'c-', marker='o', markersize=4)
        self.timeline_ax1.set_title('Total Findings Over Time', color=GUI_DARK_THEME['fg'])
        self.timeline_ax1.set_ylabel('Count', color=GUI_DARK_THEME['fg'])

        # Chart 2: Severity breakdown over time
        if 'severity_text' in hist_df.columns:
            severity_colors = {'Critical': '#dc3545', 'High': '#fd7e14', 'Medium': '#ffc107', 'Low': '#007bff', 'Info': '#6c757d'}
            for sev in ['Critical', 'High', 'Medium', 'Low']:
                sev_df = hist_df[hist_df['severity_text'] == sev]
                if not sev_df.empty:
                    counts = sev_df.groupby(sev_df['scan_date'].dt.date).size()
                    self.timeline_ax2.plot(range(len(counts)), counts.values, color=severity_colors.get(sev, 'gray'),
                                          label=sev, marker='.', markersize=3)
            self.timeline_ax2.legend(fontsize=8, facecolor=GUI_DARK_THEME['bg'], labelcolor=GUI_DARK_THEME['fg'])
        self.timeline_ax2.set_title('Findings by Severity', color=GUI_DARK_THEME['fg'])

        # Chart 3: New vs Resolved
        if not self.scan_changes_df.empty and 'change_type' in self.scan_changes_df.columns:
            changes = self.scan_changes_df.copy()
            changes['scan_date'] = pd.to_datetime(changes['scan_date'])
            new_counts = changes[changes['change_type'] == 'New'].groupby(changes['scan_date'].dt.to_period('M')).size()
            resolved_counts = changes[changes['change_type'] == 'Resolved'].groupby(changes['scan_date'].dt.to_period('M')).size()
            x = range(max(len(new_counts), len(resolved_counts)))
            if len(new_counts) > 0:
                self.timeline_ax3.bar([i - 0.2 for i in range(len(new_counts))], new_counts.values, 0.4, label='New', color='#dc3545')
            if len(resolved_counts) > 0:
                self.timeline_ax3.bar([i + 0.2 for i in range(len(resolved_counts))], resolved_counts.values, 0.4, label='Resolved', color='#28a745')
            self.timeline_ax3.legend(fontsize=8, facecolor=GUI_DARK_THEME['bg'], labelcolor=GUI_DARK_THEME['fg'])
        self.timeline_ax3.set_title('New vs Resolved', color=GUI_DARK_THEME['fg'])

        # Chart 4: Cumulative risk
        if 'severity_value' in hist_df.columns:
            risk = hist_df.groupby(hist_df['scan_date'].dt.date)['severity_value'].sum().cumsum()
            self.timeline_ax4.fill_between(range(len(risk)), risk.values, alpha=0.5, color='#dc3545')
            self.timeline_ax4.plot(range(len(risk)), risk.values, 'r-')
        self.timeline_ax4.set_title('Cumulative Risk Exposure', color=GUI_DARK_THEME['fg'])

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

        # Chart 1: CVSS distribution
        if 'cvss3_base_score' in df.columns:
            cvss_scores = df['cvss3_base_score'].dropna()
            if len(cvss_scores) > 0:
                self.risk_ax1.hist(cvss_scores, bins=20, color='#007bff', edgecolor='white', alpha=0.7)
        self.risk_ax1.set_title('CVSS Score Distribution', color=GUI_DARK_THEME['fg'])
        self.risk_ax1.set_xlabel('CVSS Score', color=GUI_DARK_THEME['fg'])

        # Check if data labels are enabled
        show_labels = self.settings_manager.settings.show_data_labels

        # Chart 2: MTTR by severity
        if 'severity_text' in df.columns and 'days_open' in df.columns:
            resolved = df[df['status'] == 'Resolved']
            if not resolved.empty:
                mttr = resolved.groupby('severity_text')['days_open'].mean()
                colors = ['#dc3545', '#fd7e14', '#ffc107', '#007bff', '#6c757d']
                bars = self.risk_ax2.bar(range(len(mttr)), mttr.values, color=colors[:len(mttr)])
                self.risk_ax2.set_xticks(range(len(mttr)))
                self.risk_ax2.set_xticklabels(mttr.index, fontsize=8)
                if show_labels:
                    add_data_labels(self.risk_ax2, bars, fmt='{:.1f}', fontsize=6)
        self.risk_ax2.set_title('Mean Time to Remediation', color=GUI_DARK_THEME['fg'])
        self.risk_ax2.set_ylabel('Days', color=GUI_DARK_THEME['fg'])

        # Chart 3: Findings by age
        if 'days_open' in df.columns:
            active = df[df['status'] == 'Active']
            buckets = [0, 30, 60, 90, 120, float('inf')]
            labels = ['0-30', '31-60', '61-90', '91-120', '121+']
            age_counts = pd.cut(active['days_open'], bins=buckets, labels=labels).value_counts().sort_index()
            bars = self.risk_ax3.bar(range(len(age_counts)), age_counts.values, color='#fd7e14')
            self.risk_ax3.set_xticks(range(len(age_counts)))
            self.risk_ax3.set_xticklabels(labels, fontsize=8)
            if show_labels:
                add_data_labels(self.risk_ax3, bars, fontsize=6)
        self.risk_ax3.set_title('Findings by Age (Days)', color=GUI_DARK_THEME['fg'])

        # Chart 4: Top risky hosts
        if 'hostname' in df.columns and 'severity_value' in df.columns:
            host_risk = df.groupby('hostname')['severity_value'].sum().nlargest(10)
            if len(host_risk) > 0:
                bars = self.risk_ax4.barh(range(len(host_risk)), host_risk.values, color='#dc3545')
                self.risk_ax4.set_yticks(range(len(host_risk)))
                self.risk_ax4.set_yticklabels([h[:15] for h in host_risk.index], fontsize=7)
                if show_labels:
                    add_horizontal_data_labels(self.risk_ax4, bars, fontsize=6)
        self.risk_ax4.set_title('Top 10 Risky Hosts', color=GUI_DARK_THEME['fg'])

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

    def _update_opdir_charts(self):
        """Update OPDIR compliance visualizations."""
        if not HAS_MATPLOTLIB or not hasattr(self, 'opdir_ax1'):
            return

        df = self.filtered_lifecycle_df if not self.filtered_lifecycle_df.empty else self.lifecycle_df

        for ax in [self.opdir_ax1, self.opdir_ax2, self.opdir_ax3, self.opdir_ax4]:
            ax.clear()
            ax.set_facecolor(GUI_DARK_THEME['entry_bg'])

        if df.empty:
            self.opdir_canvas.draw()
            return

        # Chart 1: OPDIR coverage pie
        if 'opdir_number' in df.columns:
            mapped = df['opdir_number'].notna() & (df['opdir_number'] != '')
            counts = [mapped.sum(), (~mapped).sum()]
            labels = ['Mapped', 'Unmapped']
            colors = ['#28a745', '#6c757d']
            self.opdir_ax1.pie(counts, labels=labels, colors=colors, autopct='%1.1f%%',
                              textprops={'color': GUI_DARK_THEME['fg']})
        self.opdir_ax1.set_title('OPDIR Mapping Coverage', color=GUI_DARK_THEME['fg'])

        # Chart 2: OPDIR status distribution
        if 'opdir_status' in df.columns:
            status_counts = df['opdir_status'].value_counts()
            if len(status_counts) > 0:
                colors = {'Overdue': '#dc3545', 'Due Soon': '#ffc107', 'On Track': '#28a745'}
                bar_colors = [colors.get(s, '#6c757d') for s in status_counts.index]
                self.opdir_ax2.bar(range(len(status_counts)), status_counts.values, color=bar_colors)
                self.opdir_ax2.set_xticks(range(len(status_counts)))
                self.opdir_ax2.set_xticklabels(status_counts.index, fontsize=8)
        self.opdir_ax2.set_title('OPDIR Status Distribution', color=GUI_DARK_THEME['fg'])

        # Chart 3: Days open vs OPDIR (scatter)
        if 'days_open' in df.columns and 'opdir_number' in df.columns:
            mapped_df = df[df['opdir_number'].notna() & (df['opdir_number'] != '')]
            if not mapped_df.empty and len(mapped_df) < 1000:
                self.opdir_ax3.scatter(range(len(mapped_df)), mapped_df['days_open'].values,
                                       alpha=0.5, c='#007bff', s=10)
        self.opdir_ax3.set_title('Finding Age (OPDIR Mapped)', color=GUI_DARK_THEME['fg'])
        self.opdir_ax3.set_ylabel('Days Open', color=GUI_DARK_THEME['fg'])

        # Chart 4: Placeholder for compliance by year
        self.opdir_ax4.text(0.5, 0.5, 'OPDIR Year Analysis\n(requires OPDIR data)',
                           ha='center', va='center', color=GUI_DARK_THEME['fg'], fontsize=10)
        self.opdir_ax4.set_title('Compliance by OPDIR Year', color=GUI_DARK_THEME['fg'])

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

        for ax in [self.efficiency_ax1, self.efficiency_ax2, self.efficiency_ax3, self.efficiency_ax4]:
            ax.clear()
            ax.set_facecolor(GUI_DARK_THEME['entry_bg'])

        if df.empty:
            self.efficiency_canvas.draw()
            return

        # Chart 1: Scan coverage (host presence distribution)
        if not host_df.empty and 'presence_percentage' in host_df.columns:
            self.efficiency_ax1.hist(host_df['presence_percentage'], bins=20, color='#17a2b8', edgecolor='white')
        self.efficiency_ax1.set_title('Scan Coverage Consistency', color=GUI_DARK_THEME['fg'])
        self.efficiency_ax1.set_xlabel('Presence %', color=GUI_DARK_THEME['fg'])

        # Chart 2: Reappearance analysis
        if 'reappearances' in df.columns:
            reapp_counts = df['reappearances'].value_counts().sort_index()
            if len(reapp_counts) > 0:
                self.efficiency_ax2.bar(reapp_counts.index[:10], reapp_counts.values[:10], color='#fd7e14')
        self.efficiency_ax2.set_title('Reappearance Analysis', color=GUI_DARK_THEME['fg'])
        self.efficiency_ax2.set_xlabel('Reappearance Count', color=GUI_DARK_THEME['fg'])

        # Chart 3: Host vulnerability burden
        if 'hostname' in df.columns:
            host_burden = df.groupby('hostname').size()
            self.efficiency_ax3.hist(host_burden, bins=30, color='#6f42c1', edgecolor='white')
        self.efficiency_ax3.set_title('Host Vulnerability Burden', color=GUI_DARK_THEME['fg'])
        self.efficiency_ax3.set_xlabel('Findings per Host', color=GUI_DARK_THEME['fg'])

        # Chart 4: Resolution velocity
        if 'status' in df.columns and 'days_open' in df.columns:
            resolved = df[df['status'] == 'Resolved']
            if not resolved.empty:
                self.efficiency_ax4.hist(resolved['days_open'], bins=30, color='#28a745', edgecolor='white')
        self.efficiency_ax4.set_title('Resolution Velocity', color=GUI_DARK_THEME['fg'])
        self.efficiency_ax4.set_xlabel('Days to Resolve', color=GUI_DARK_THEME['fg'])

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

        for ax in [self.network_ax1, self.network_ax2, self.network_ax3, self.network_ax4]:
            ax.clear()
            ax.set_facecolor(GUI_DARK_THEME['entry_bg'])

        if df.empty or 'ip_address' not in df.columns:
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
        df['subnet'] = df['ip_address'].apply(get_subnet)

        # Chart 1: Top subnets
        subnet_counts = df.groupby('subnet').size().nlargest(10)
        if len(subnet_counts) > 0:
            self.network_ax1.barh(range(len(subnet_counts)), subnet_counts.values, color='#007bff')
            self.network_ax1.set_yticks(range(len(subnet_counts)))
            self.network_ax1.set_yticklabels([s[:18] for s in subnet_counts.index], fontsize=7)
        self.network_ax1.set_title('Top Subnets by Vulnerability', color=GUI_DARK_THEME['fg'])

        # Chart 2: Subnet risk scores
        if 'severity_value' in df.columns:
            subnet_risk = df.groupby('subnet')['severity_value'].sum().nlargest(10)
            if len(subnet_risk) > 0:
                colors = ['#dc3545' if v > subnet_risk.median() else '#ffc107' for v in subnet_risk.values]
                self.network_ax2.barh(range(len(subnet_risk)), subnet_risk.values, color=colors)
                self.network_ax2.set_yticks(range(len(subnet_risk)))
                self.network_ax2.set_yticklabels([s[:18] for s in subnet_risk.index], fontsize=7)
        self.network_ax2.set_title('Subnet Risk Scores', color=GUI_DARK_THEME['fg'])

        # Chart 3: Host criticality distribution
        if 'hostname' in df.columns and 'severity_value' in df.columns:
            host_crit = df.groupby('hostname')['severity_value'].sum()
            self.network_ax3.hist(host_crit, bins=30, color='#17a2b8', edgecolor='white')
        self.network_ax3.set_title('Host Criticality Distribution', color=GUI_DARK_THEME['fg'])
        self.network_ax3.set_xlabel('Risk Score', color=GUI_DARK_THEME['fg'])

        # Chart 4: Network class distribution
        def get_class(ip):
            if pd.isna(ip) or not isinstance(ip, str):
                return 'Unknown'
            parts = ip.split('.')
            if len(parts) >= 1:
                first = int(parts[0]) if parts[0].isdigit() else 0
                if first < 128:
                    return 'Class A'
                elif first < 192:
                    return 'Class B'
                elif first < 224:
                    return 'Class C'
            return 'Other'

        class_counts = df['ip_address'].apply(get_class).value_counts()
        if len(class_counts) > 0:
            self.network_ax4.pie(class_counts.values, labels=class_counts.index,
                                autopct='%1.1f%%', textprops={'color': GUI_DARK_THEME['fg']})
        self.network_ax4.set_title('Network Segment Analysis', color=GUI_DARK_THEME['fg'])

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

        for ax in [self.plugin_ax1, self.plugin_ax2, self.plugin_ax3, self.plugin_ax4]:
            ax.clear()
            ax.set_facecolor(GUI_DARK_THEME['entry_bg'])

        if df.empty:
            self.plugin_canvas.draw()
            return

        # Chart 1: Top 15 most common plugins
        if 'plugin_id' in df.columns:
            plugin_counts = df.groupby('plugin_id').size().nlargest(15)
            if len(plugin_counts) > 0:
                # Get plugin names if available
                if 'plugin_name' in df.columns:
                    names = df.groupby('plugin_id')['plugin_name'].first()
                    labels = [str(names.get(pid, pid))[:25] for pid in plugin_counts.index]
                else:
                    labels = [str(pid) for pid in plugin_counts.index]
                self.plugin_ax1.barh(range(len(plugin_counts)), plugin_counts.values, color='#007bff')
                self.plugin_ax1.set_yticks(range(len(plugin_counts)))
                self.plugin_ax1.set_yticklabels(labels, fontsize=6)
        self.plugin_ax1.set_title('Top 15 Most Common Plugins', color=GUI_DARK_THEME['fg'])

        # Chart 2: Plugin severity distribution
        if 'plugin_id' in df.columns and 'severity_text' in df.columns:
            plugin_severity = df.groupby(['plugin_id', 'severity_text']).size().unstack(fill_value=0)
            severity_totals = {}
            for sev in ['Critical', 'High', 'Medium', 'Low', 'Info']:
                if sev in plugin_severity.columns:
                    severity_totals[sev] = plugin_severity[sev].sum()
            if severity_totals:
                colors = {'Critical': '#dc3545', 'High': '#fd7e14', 'Medium': '#ffc107', 'Low': '#007bff', 'Info': '#6c757d'}
                bar_colors = [colors.get(s, 'gray') for s in severity_totals.keys()]
                self.plugin_ax2.bar(range(len(severity_totals)), list(severity_totals.values()), color=bar_colors)
                self.plugin_ax2.set_xticks(range(len(severity_totals)))
                self.plugin_ax2.set_xticklabels(list(severity_totals.keys()), fontsize=8)
        self.plugin_ax2.set_title('Plugin Severity Distribution', color=GUI_DARK_THEME['fg'])

        # Chart 3: Plugins affecting most hosts
        if 'plugin_id' in df.columns and 'hostname' in df.columns:
            plugin_hosts = df.groupby('plugin_id')['hostname'].nunique().nlargest(10)
            if len(plugin_hosts) > 0:
                if 'plugin_name' in df.columns:
                    names = df.groupby('plugin_id')['plugin_name'].first()
                    labels = [str(names.get(pid, pid))[:20] for pid in plugin_hosts.index]
                else:
                    labels = [str(pid) for pid in plugin_hosts.index]
                self.plugin_ax3.barh(range(len(plugin_hosts)), plugin_hosts.values, color='#17a2b8')
                self.plugin_ax3.set_yticks(range(len(plugin_hosts)))
                self.plugin_ax3.set_yticklabels(labels, fontsize=7)
        self.plugin_ax3.set_title('Plugins Affecting Most Hosts', color=GUI_DARK_THEME['fg'])
        self.plugin_ax3.set_xlabel('Host Count', color=GUI_DARK_THEME['fg'])

        # Chart 4: Plugin average age
        if 'plugin_id' in df.columns and 'days_open' in df.columns:
            plugin_age = df.groupby('plugin_id')['days_open'].mean().nlargest(10)
            if len(plugin_age) > 0:
                if 'plugin_name' in df.columns:
                    names = df.groupby('plugin_id')['plugin_name'].first()
                    labels = [str(names.get(pid, pid))[:20] for pid in plugin_age.index]
                else:
                    labels = [str(pid) for pid in plugin_age.index]
                self.plugin_ax4.barh(range(len(plugin_age)), plugin_age.values, color='#fd7e14')
                self.plugin_ax4.set_yticks(range(len(plugin_age)))
                self.plugin_ax4.set_yticklabels(labels, fontsize=7)
        self.plugin_ax4.set_title('Plugin Avg Age (Days Open)', color=GUI_DARK_THEME['fg'])
        self.plugin_ax4.set_xlabel('Days', color=GUI_DARK_THEME['fg'])

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

        for ax in [self.priority_ax1, self.priority_ax2, self.priority_ax3, self.priority_ax4]:
            ax.clear()
            ax.set_facecolor(GUI_DARK_THEME['entry_bg'])

        if df.empty:
            self.priority_canvas.draw()
            return

        # Only look at active findings for priority
        active_df = df[df['status'] == 'Active'].copy() if 'status' in df.columns else df.copy()

        # Calculate priority score (CVSS * days_open normalized)
        if 'cvss3_base_score' in active_df.columns and 'days_open' in active_df.columns:
            active_df['cvss'] = pd.to_numeric(active_df['cvss3_base_score'], errors='coerce').fillna(5.0)
            active_df['priority_score'] = active_df['cvss'] * (1 + active_df['days_open'] / 30)
        elif 'severity_value' in active_df.columns and 'days_open' in active_df.columns:
            active_df['cvss'] = active_df['severity_value'] * 2.5  # Approximate CVSS from severity
            active_df['priority_score'] = active_df['cvss'] * (1 + active_df['days_open'] / 30)
        else:
            active_df['cvss'] = 5.0
            active_df['priority_score'] = 5.0

        # Chart 1: CVSS vs Days Open scatter (Priority Matrix)
        if 'days_open' in active_df.columns and len(active_df) > 0:
            sample_df = active_df.head(500)  # Limit for performance
            colors = sample_df['priority_score'].values if 'priority_score' in sample_df.columns else 'red'
            scatter = self.priority_ax1.scatter(
                sample_df['days_open'], sample_df['cvss'],
                c=colors, cmap='RdYlGn_r', alpha=0.6, s=20
            )
            # Draw quadrant lines
            self.priority_ax1.axhline(y=7.0, color='gray', linestyle='--', alpha=0.5)
            self.priority_ax1.axvline(x=30, color='gray', linestyle='--', alpha=0.5)
            # Label quadrants
            self.priority_ax1.text(5, 8.5, 'Critical\nPriority', fontsize=8, color='#dc3545')
            self.priority_ax1.text(60, 8.5, 'Urgent\n(Old+High)', fontsize=8, color='#fd7e14')
            self.priority_ax1.text(5, 3, 'Monitor', fontsize=8, color='#28a745')
            self.priority_ax1.text(60, 3, 'Schedule', fontsize=8, color='#ffc107')
        self.priority_ax1.set_title('Remediation Priority Matrix', color=GUI_DARK_THEME['fg'])
        self.priority_ax1.set_xlabel('Days Open', color=GUI_DARK_THEME['fg'])
        self.priority_ax1.set_ylabel('CVSS Score', color=GUI_DARK_THEME['fg'])

        # Chart 2: Priority distribution pie
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
            colors = {'Critical': '#dc3545', 'High': '#fd7e14', 'Medium': '#ffc107', 'Low': '#28a745'}
            pie_colors = [colors.get(c, 'gray') for c in priority_cats.index]
            self.priority_ax2.pie(priority_cats.values, labels=priority_cats.index, colors=pie_colors,
                                 autopct='%1.1f%%', textprops={'color': GUI_DARK_THEME['fg']})
        self.priority_ax2.set_title('Priority Distribution', color=GUI_DARK_THEME['fg'])

        # Chart 3: Top 10 priority findings
        if 'priority_score' in active_df.columns and len(active_df) > 0:
            top_priority = active_df.nlargest(10, 'priority_score')
            if 'hostname' in top_priority.columns and 'plugin_id' in top_priority.columns:
                labels = [f"{row['hostname'][:10]}-{row['plugin_id']}" for _, row in top_priority.iterrows()]
            else:
                labels = [str(i) for i in range(len(top_priority))]
            self.priority_ax3.barh(range(len(top_priority)), top_priority['priority_score'].values, color='#dc3545')
            self.priority_ax3.set_yticks(range(len(top_priority)))
            self.priority_ax3.set_yticklabels(labels, fontsize=7)
        self.priority_ax3.set_title('Top 10 Priority Findings', color=GUI_DARK_THEME['fg'])
        self.priority_ax3.set_xlabel('Priority Score', color=GUI_DARK_THEME['fg'])

        # Chart 4: Priority by severity
        if 'priority_score' in active_df.columns and 'severity_text' in active_df.columns:
            sev_priority = active_df.groupby('severity_text')['priority_score'].mean()
            sev_order = ['Critical', 'High', 'Medium', 'Low', 'Info']
            sev_priority = sev_priority.reindex([s for s in sev_order if s in sev_priority.index])
            if len(sev_priority) > 0:
                colors = {'Critical': '#dc3545', 'High': '#fd7e14', 'Medium': '#ffc107', 'Low': '#007bff', 'Info': '#6c757d'}
                bar_colors = [colors.get(s, 'gray') for s in sev_priority.index]
                self.priority_ax4.bar(range(len(sev_priority)), sev_priority.values, color=bar_colors)
                self.priority_ax4.set_xticks(range(len(sev_priority)))
                self.priority_ax4.set_xticklabels(sev_priority.index, fontsize=8)
        self.priority_ax4.set_title('Avg Priority Score by Severity', color=GUI_DARK_THEME['fg'])
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

        # Calculate SLA status for each finding
        sla_data = active_df.apply(lambda row: self._calculate_sla_status(row), axis=1)
        active_df['sla_status'] = [x[0] for x in sla_data]
        active_df['days_remaining'] = [x[1] for x in sla_data]
        active_df['sla_target'] = [x[2] for x in sla_data]

        # Chart 1: SLA Status overview (pie)
        status_counts = active_df['sla_status'].value_counts()
        if len(status_counts) > 0:
            colors = [SLA_STATUS_COLORS.get(s, '#6c757d') for s in status_counts.index]
            self.sla_ax1.pie(status_counts.values, labels=status_counts.index, colors=colors,
                           autopct='%1.1f%%', textprops={'color': GUI_DARK_THEME['fg']})
        self.sla_ax1.set_title('SLA Compliance Status', color=GUI_DARK_THEME['fg'])

        # Chart 2: Overdue by severity
        overdue = active_df[active_df['sla_status'] == SLA_STATUS_OVERDUE]
        if not overdue.empty and 'severity_text' in overdue.columns:
            overdue_by_sev = overdue['severity_text'].value_counts()
            sev_order = ['Critical', 'High', 'Medium', 'Low']
            overdue_by_sev = overdue_by_sev.reindex([s for s in sev_order if s in overdue_by_sev.index])
            if len(overdue_by_sev) > 0:
                colors = {'Critical': '#dc3545', 'High': '#fd7e14', 'Medium': '#ffc107', 'Low': '#007bff'}
                bar_colors = [colors.get(s, 'gray') for s in overdue_by_sev.index]
                self.sla_ax2.bar(range(len(overdue_by_sev)), overdue_by_sev.values, color=bar_colors)
                self.sla_ax2.set_xticks(range(len(overdue_by_sev)))
                self.sla_ax2.set_xticklabels(overdue_by_sev.index, fontsize=9)
        self.sla_ax2.set_title(f'Overdue Findings ({len(overdue)} total)', color=GUI_DARK_THEME['fg'])
        self.sla_ax2.set_ylabel('Count', color=GUI_DARK_THEME['fg'])

        # Chart 3: Approaching deadline - show findings closest to SLA breach
        approaching = active_df[active_df['sla_status'] == SLA_STATUS_APPROACHING].copy()
        if not approaching.empty:
            approaching = approaching.nsmallest(15, 'days_remaining')
            if 'hostname' in approaching.columns and 'severity_text' in approaching.columns:
                labels = [f"{row['hostname'][:12]} ({row['severity_text'][:1]})" for _, row in approaching.iterrows()]
            else:
                labels = [str(i) for i in range(len(approaching))]
            colors = ['#ffc107' if d > 0 else '#dc3545' for d in approaching['days_remaining']]
            self.sla_ax3.barh(range(len(approaching)), approaching['days_remaining'].values, color=colors)
            self.sla_ax3.set_yticks(range(len(approaching)))
            self.sla_ax3.set_yticklabels(labels, fontsize=7)
            self.sla_ax3.axvline(x=0, color='#dc3545', linestyle='-', linewidth=2)
        self.sla_ax3.set_title(f'Approaching Deadline ({len(approaching)} findings)', color=GUI_DARK_THEME['fg'])
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
        self.sla_ax4.set_title('Days Until/Past SLA Distribution', color=GUI_DARK_THEME['fg'])
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
                    self.host_tracking_ax1.barh(range(len(missing)), days_missing.values, color='#dc3545')
                    self.host_tracking_ax1.set_yticks(range(len(missing)))
                    self.host_tracking_ax1.set_yticklabels(labels, fontsize=7)
        self.host_tracking_ax1.set_title('Hosts Missing from Recent Scans', color=GUI_DARK_THEME['fg'])
        self.host_tracking_ax1.set_xlabel('Days Since Last Seen', color=GUI_DARK_THEME['fg'])

        # Chart 2: Host presence over time
        if not hist_df.empty and 'scan_date' in hist_df.columns and 'hostname' in hist_df.columns:
            hist_copy = hist_df.copy()
            hist_copy['scan_date'] = pd.to_datetime(hist_copy['scan_date'])
            hosts_per_scan = hist_copy.groupby(hist_copy['scan_date'].dt.date)['hostname'].nunique()
            if len(hosts_per_scan) > 0:
                self.host_tracking_ax2.plot(range(len(hosts_per_scan)), hosts_per_scan.values, 'c-', marker='o', markersize=4)
                self.host_tracking_ax2.fill_between(range(len(hosts_per_scan)), hosts_per_scan.values, alpha=0.3, color='cyan')
        self.host_tracking_ax2.set_title('Host Presence Over Time', color=GUI_DARK_THEME['fg'])
        self.host_tracking_ax2.set_ylabel('Unique Hosts', color=GUI_DARK_THEME['fg'])

        # Chart 3: Hosts with declining presence (low presence %)
        if 'presence_percentage' in host_df.columns:
            low_presence = host_df[host_df['presence_percentage'] < 50].nsmallest(15, 'presence_percentage')
            if not low_presence.empty and 'hostname' in low_presence.columns:
                labels = [str(h)[:15] for h in low_presence['hostname']]
                self.host_tracking_ax3.barh(range(len(low_presence)), low_presence['presence_percentage'].values, color='#ffc107')
                self.host_tracking_ax3.set_yticks(range(len(low_presence)))
                self.host_tracking_ax3.set_yticklabels(labels, fontsize=7)
                self.host_tracking_ax3.axvline(x=50, color='#dc3545', linestyle='--', alpha=0.7)
        self.host_tracking_ax3.set_title('Hosts with Low Presence (<50%)', color=GUI_DARK_THEME['fg'])
        self.host_tracking_ax3.set_xlabel('Presence %', color=GUI_DARK_THEME['fg'])

        # Chart 4: Host status distribution
        if 'status' in host_df.columns:
            status_counts = host_df['status'].value_counts()
            if len(status_counts) > 0:
                colors = {'Active': '#28a745', 'Inactive': '#dc3545', 'Intermittent': '#ffc107'}
                pie_colors = [colors.get(s, '#6c757d') for s in status_counts.index]
                self.host_tracking_ax4.pie(status_counts.values, labels=status_counts.index, colors=pie_colors,
                                          autopct='%1.1f%%', textprops={'color': GUI_DARK_THEME['fg']})
        self.host_tracking_ax4.set_title('Host Status Distribution', color=GUI_DARK_THEME['fg'])

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

        self.metrics_ax1.set_title('Remediation Status by Severity', color=GUI_DARK_THEME['fg'])
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
        self.metrics_ax2.set_title('Risk Score Trend', color=GUI_DARK_THEME['fg'])
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
        self.metrics_ax3.set_title('SLA Status by Severity', color=GUI_DARK_THEME['fg'])
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
        self.metrics_ax4.set_title('Vulnerabilities per Host Trend', color=GUI_DARK_THEME['fg'])
        self.metrics_ax4.set_ylabel('Vulns/Host', color=GUI_DARK_THEME['fg'])

        for ax in [self.metrics_ax1, self.metrics_ax2, self.metrics_ax3, self.metrics_ax4]:
            ax.tick_params(colors=GUI_DARK_THEME['fg'])
            for spine in ax.spines.values():
                spine.set_color(GUI_DARK_THEME['fg'])

        self.metrics_fig.tight_layout()
        self.metrics_canvas.draw()

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
        if settings.recent_opdir_file and os.path.exists(settings.recent_opdir_file):
            self.opdir_file_path = settings.recent_opdir_file
        if settings.recent_sqlite_db and os.path.exists(settings.recent_sqlite_db):
            self.existing_db_path = settings.recent_sqlite_db

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

    def run(self):
        """Run the application."""
        self._log("Nessus History Tracker v2.0 started")
        self._log("Select archives or load existing database to begin")
        self.window.mainloop()
