"""
Menu Bar Module
Creates the application menu bar with File, Analysis, AI Predictions, and Help menus.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import TYPE_CHECKING, Optional, Callable, Dict, Any

if TYPE_CHECKING:
    from .app import NessusHistoryTrackerApp


class MenuBar:
    """Application menu bar with File, Analysis, AI, and Help menus."""

    def __init__(self, app: 'NessusHistoryTrackerApp'):
        """
        Initialize menu bar.

        Args:
            app: Main application instance
        """
        self.app = app
        self.window = app.window

        # Create menu bar
        self.menubar = tk.Menu(self.window)
        self.window.config(menu=self.menubar)

        # Build menus
        self._build_file_menu()
        self._build_analysis_menu()
        self._build_ai_menu()
        self._build_help_menu()

    def _build_file_menu(self):
        """Build File menu."""
        file_menu = tk.Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label="File", menu=file_menu)

        file_menu.add_command(
            label="Load Nessus Archives...",
            accelerator="Ctrl+O",
            command=self.app._select_archives
        )
        file_menu.add_command(
            label="Load Plugins Database...",
            command=self.app._select_plugins_db
        )
        file_menu.add_command(
            label="Load OPDIR File...",
            command=self.app._select_opdir_file
        )
        file_menu.add_command(
            label="Load Existing Database...",
            command=self.app._select_existing_db
        )
        file_menu.add_command(
            label="Load Info Findings (Yearly)...",
            command=self.app._show_load_info_dialog
        )

        file_menu.add_separator()

        file_menu.add_command(
            label="Export to Excel...",
            accelerator="Ctrl+E",
            command=self.app._export_excel
        )
        file_menu.add_command(
            label="Export to SQLite...",
            command=self.app._export_sqlite
        )
        file_menu.add_command(
            label="Export to JSON...",
            command=self.app._export_json
        )

        file_menu.add_separator()

        # Recent files submenu
        self.recent_menu = tk.Menu(file_menu, tearoff=0)
        file_menu.add_cascade(label="Recent Files", menu=self.recent_menu)
        self._update_recent_files()

        file_menu.add_separator()

        file_menu.add_command(
            label="Exit",
            accelerator="Ctrl+Q",
            command=self.window.quit
        )

        # Keyboard shortcuts
        self.window.bind('<Control-o>', lambda e: self.app._select_archives())
        self.window.bind('<Control-e>', lambda e: self.app._export_excel())
        self.window.bind('<Control-q>', lambda e: self.window.quit())

    def _update_recent_files(self):
        """Update recent files submenu."""
        self.recent_menu.delete(0, tk.END)

        settings = self.app.settings_manager.settings

        if settings.recent_plugins_db:
            self.recent_menu.add_command(
                label=f"Plugins: {settings.recent_plugins_db[-50:]}",
                command=lambda: self._load_recent('plugins_db', settings.recent_plugins_db)
            )

        if settings.recent_opdir_file:
            self.recent_menu.add_command(
                label=f"OPDIR: {settings.recent_opdir_file[-50:]}",
                command=lambda: self._load_recent('opdir', settings.recent_opdir_file)
            )

        if settings.recent_sqlite_db:
            self.recent_menu.add_command(
                label=f"SQLite: {settings.recent_sqlite_db[-50:]}",
                command=lambda: self._load_recent('sqlite', settings.recent_sqlite_db)
            )

        if not any([settings.recent_plugins_db, settings.recent_opdir_file, settings.recent_sqlite_db]):
            self.recent_menu.add_command(label="(No recent files)", state=tk.DISABLED)

    def _load_recent(self, file_type: str, path: str):
        """Load a recent file."""
        import os
        if not os.path.exists(path):
            messagebox.showwarning("Not Found", f"File not found: {path}")
            return

        if file_type == 'plugins_db':
            self.app.plugins_db_path = path
            self.app._log(f"Loaded plugins database: {path}")
        elif file_type == 'opdir':
            self.app.opdir_file_path = path
            self.app._log(f"Loaded OPDIR file: {path}")
        elif file_type == 'sqlite':
            self.app.existing_db_path = path
            self.app._load_existing_database(path)

    def _build_analysis_menu(self):
        """Build Analysis menu."""
        analysis_menu = tk.Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label="Analysis", menu=analysis_menu)

        analysis_menu.add_command(
            label="Process Data",
            accelerator="F5",
            command=self.app._process_archives
        )
        analysis_menu.add_command(
            label="Refresh Analysis",
            accelerator="F6",
            command=self.app._refresh_analysis
        )

        analysis_menu.add_separator()

        analysis_menu.add_command(
            label="Apply Filters",
            command=self.app._apply_filters
        )
        analysis_menu.add_command(
            label="Reset Filters",
            command=self.app._reset_filters
        )

        analysis_menu.add_separator()

        analysis_menu.add_command(
            label="Settings...",
            command=self.app._show_settings_dialog
        )

        # Keyboard shortcuts
        self.window.bind('<F5>', lambda e: self.app._process_archives())
        self.window.bind('<F6>', lambda e: self.app._refresh_analysis())

    def _build_ai_menu(self):
        """Build AI Predictions menu."""
        self.ai_menu = tk.Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label="AI Predictions", menu=self.ai_menu)

        self.ai_menu.add_command(
            label="Analyze Current Data...",
            accelerator="Ctrl+Shift+A",
            command=self._run_ai_analysis
        )

        # Analysis type submenu
        analysis_type_menu = tk.Menu(self.ai_menu, tearoff=0)
        self.ai_menu.add_cascade(label="Analysis Type", menu=analysis_type_menu)

        analysis_type_menu.add_command(
            label="Full Analysis",
            command=lambda: self._run_ai_analysis('full_analysis')
        )
        analysis_type_menu.add_command(
            label="Time to Remediate",
            command=lambda: self._run_ai_analysis('time_to_remediate')
        )
        analysis_type_menu.add_command(
            label="SLA Breach Forecast",
            command=lambda: self._run_ai_analysis('sla_breach_forecast')
        )
        analysis_type_menu.add_command(
            label="Prioritization",
            command=lambda: self._run_ai_analysis('prioritization')
        )
        analysis_type_menu.add_command(
            label="Trend Analysis",
            command=lambda: self._run_ai_analysis('trend_analysis')
        )

        self.ai_menu.add_separator()

        self.ai_menu.add_command(
            label="Configure AI Settings...",
            command=self._show_ai_settings
        )
        self.ai_menu.add_command(
            label="Configure Threat Feeds...",
            command=self._show_threat_intel_settings
        )
        self.ai_menu.add_command(
            label="Sync Threat Intelligence",
            command=self._sync_threat_intel
        )

        # Keyboard shortcut
        self.window.bind('<Control-Shift-A>', lambda e: self._run_ai_analysis())

    def _build_help_menu(self):
        """Build Help menu."""
        help_menu = tk.Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label="Help", menu=help_menu)

        help_menu.add_command(
            label="User Guide",
            command=self._show_user_guide
        )
        help_menu.add_command(
            label="Keyboard Shortcuts",
            command=self._show_shortcuts
        )

        help_menu.add_separator()

        help_menu.add_command(
            label="About",
            command=self._show_about
        )

    def _run_ai_analysis(self, analysis_type: str = 'full_analysis'):
        """Run AI analysis on current data."""
        # Check if AI is configured
        if not self.app.settings_manager.is_ai_configured():
            response = messagebox.askyesno(
                "AI Not Configured",
                "AI predictions are not configured. Would you like to configure them now?"
            )
            if response:
                self._show_ai_settings()
            return

        # Check if we have data
        if self.app.lifecycle_df.empty:
            messagebox.showwarning(
                "No Data",
                "Please load and process vulnerability data first."
            )
            return

        # Import AI modules
        try:
            from .analysis_modal import AnalysisLauncher
            from ..ai.openwebui_client import OpenWebUIClient, OpenWebUIConfig
            from ..ai.predictions import PredictionType, AnalysisMode
        except ImportError:
            from refactored_app.gui.analysis_modal import AnalysisLauncher
            from refactored_app.ai.openwebui_client import OpenWebUIClient, OpenWebUIConfig
            from refactored_app.ai.predictions import PredictionType, AnalysisMode

        # Map string to enum
        prediction_types = {
            'full_analysis': PredictionType.FULL_ANALYSIS,
            'time_to_remediate': PredictionType.TIME_TO_REMEDIATE,
            'sla_breach_forecast': PredictionType.SLA_BREACH_FORECAST,
            'prioritization': PredictionType.PRIORITIZATION,
            'trend_analysis': PredictionType.TREND_ANALYSIS
        }

        prediction_type = prediction_types.get(analysis_type, PredictionType.FULL_ANALYSIS)

        # Determine mode from settings
        mode_str = self.app.settings_manager.ai_settings.analysis_mode
        mode = AnalysisMode.COMPREHENSIVE if mode_str == 'comprehensive' else AnalysisMode.QUICK

        # Create client
        ai_settings = self.app.settings_manager.ai_settings
        config = OpenWebUIConfig(
            base_url=ai_settings.base_url,
            api_key=ai_settings.api_key,
            model=ai_settings.model,
            temperature=ai_settings.get_temperature(),
            max_tokens=ai_settings.max_tokens,
            timeout=ai_settings.timeout
        )
        client = OpenWebUIClient(config)

        # Get RAG collection ID if enabled
        collection_ids = None
        if ai_settings.use_threat_intel_rag and ai_settings.rag_collection_name:
            client.refresh_collections()
            collection = client.get_collection_by_name(ai_settings.rag_collection_name)
            if collection:
                collection_ids = [collection['id']]

        # Launch analysis
        launcher = AnalysisLauncher(
            parent=self.window,
            client=client,
            collection_ids=collection_ids
        )

        # Use filtered data if available, otherwise full data
        findings_df = self.app.filtered_lifecycle_df if not self.app.filtered_lifecycle_df.empty else self.app.historical_df
        lifecycle_df = self.app.filtered_lifecycle_df if not self.app.filtered_lifecycle_df.empty else self.app.lifecycle_df

        launcher.launch_analysis(
            findings_df=findings_df,
            lifecycle_df=lifecycle_df,
            prediction_type=prediction_type,
            mode=mode
        )

    def _show_ai_settings(self):
        """Show AI settings dialog."""
        try:
            from .ai_settings_dialog import show_ai_settings_dialog
        except ImportError:
            from refactored_app.gui.ai_settings_dialog import show_ai_settings_dialog

        show_ai_settings_dialog(
            parent=self.window,
            settings_manager=self.app.settings_manager,
            on_save=lambda: self.app._log("AI settings saved")
        )

    def _show_threat_intel_settings(self):
        """Show threat intel settings dialog."""
        try:
            from .threat_intel_dialog import show_threat_intel_dialog
        except ImportError:
            from refactored_app.gui.threat_intel_dialog import show_threat_intel_dialog

        show_threat_intel_dialog(
            parent=self.window,
            settings_manager=self.app.settings_manager,
            on_sync_complete=lambda stats: self.app._log(
                f"Threat intel sync complete: {stats.get('total_records', 0)} records"
            )
        )

    def _sync_threat_intel(self):
        """Quick sync threat intelligence."""
        if not self.app.settings_manager.is_ai_configured():
            messagebox.showwarning(
                "Not Configured",
                "Please configure AI settings first."
            )
            return

        # Open threat intel dialog in sync mode
        self._show_threat_intel_settings()

    def _show_user_guide(self):
        """Show user guide."""
        guide_text = """
NESSUS HISTORY TRACKER v2.0 - USER GUIDE

GETTING STARTED:
1. Load Nessus scan archives (.zip containing .nessus files)
2. Optionally load a plugins database for enhanced info
3. Optionally load an OPDIR file for compliance tracking
4. Click 'Process' to analyze the data

FEATURES:
- Track vulnerability lifecycle across multiple scans
- Identify reappearing vulnerabilities
- Calculate Mean Time to Remediation (MTTR)
- SLA compliance tracking
- Host presence analysis
- Advanced filtering and search

AI PREDICTIONS (NEW):
- Configure OpenWebUI in AI Predictions > Configure AI Settings
- Run analysis on your data for:
  * Remediation time predictions
  * SLA breach forecasts
  * Prioritization recommendations
  * Trend analysis
- Sync threat intelligence (CISA KEV, EPSS, NVD) for enriched analysis

KEYBOARD SHORTCUTS:
- Ctrl+O: Load archives
- Ctrl+E: Export to Excel
- Ctrl+Shift+A: Run AI analysis
- F5: Process data
- F6: Refresh analysis
- Ctrl+Q: Exit
        """

        dialog = tk.Toplevel(self.window)
        dialog.title("User Guide")
        dialog.geometry("600x500")
        dialog.transient(self.window)

        text = tk.Text(dialog, wrap=tk.WORD, padx=20, pady=20)
        text.pack(fill=tk.BOTH, expand=True)
        text.insert(tk.END, guide_text)
        text.config(state=tk.DISABLED)

        ttk.Button(dialog, text="Close", command=dialog.destroy).pack(pady=10)

    def _show_shortcuts(self):
        """Show keyboard shortcuts."""
        shortcuts = """
KEYBOARD SHORTCUTS

File Operations:
  Ctrl+O          Load Nessus archives
  Ctrl+E          Export to Excel
  Ctrl+Q          Exit application

Analysis:
  F5              Process data
  F6              Refresh analysis
  Ctrl+Shift+A    Run AI analysis

Navigation:
  Tab             Switch between tabs
  Ctrl+Tab        Next tab
  Ctrl+Shift+Tab  Previous tab
        """

        messagebox.showinfo("Keyboard Shortcuts", shortcuts)

    def _show_about(self):
        """Show about dialog."""
        about_text = """
Nessus History Tracker v2.0

A comprehensive vulnerability tracking and analysis tool.

Features:
- Multi-scan vulnerability lifecycle tracking
- SLA compliance monitoring
- AI-powered predictions and insights
- Threat intelligence integration

Built with Python and Tkinter.
        """

        messagebox.showinfo("About", about_text)


def create_menu_bar(app: 'NessusHistoryTrackerApp') -> MenuBar:
    """
    Create and attach menu bar to application.

    Args:
        app: Main application instance

    Returns:
        MenuBar instance
    """
    return MenuBar(app)
