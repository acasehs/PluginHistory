"""
Threat Intelligence Configuration Dialog
Configuration and sync dialog for threat intel feeds.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import json
from datetime import datetime
from typing import Optional, Callable, Dict, Any

try:
    from ..settings import SettingsManager, ThreatIntelSettings
    from ..ai.threat_intel import ThreatIntelManager, ThreatFeedSource, SyncProgress, SyncResult
    from ..ai.rag_sync import RAGSyncManager, RAGSyncProgress
except ImportError:
    from refactored_app.settings import SettingsManager, ThreatIntelSettings
    from refactored_app.ai.threat_intel import ThreatIntelManager, ThreatFeedSource, SyncProgress, SyncResult
    from refactored_app.ai.rag_sync import RAGSyncManager, RAGSyncProgress


class ThreatIntelDialog:
    """Dialog for configuring and syncing threat intelligence feeds."""

    def __init__(
        self,
        parent: tk.Tk,
        settings_manager: SettingsManager,
        on_sync_complete: Optional[Callable[[Dict[str, Any]], None]] = None
    ):
        """
        Initialize threat intel dialog.

        Args:
            parent: Parent window
            settings_manager: Settings manager instance
            on_sync_complete: Optional callback when sync completes
        """
        self.parent = parent
        self.settings_manager = settings_manager
        self.on_sync_complete = on_sync_complete

        self.threat_intel_manager: Optional[ThreatIntelManager] = None
        self.rag_sync_manager: Optional[RAGSyncManager] = None
        self.sync_in_progress = False

        # Create dialog window
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Threat Intelligence Configuration")
        self.dialog.geometry("650x750")
        self.dialog.transient(parent)
        self.dialog.grab_set()

        # Center on parent
        self.dialog.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() - 650) // 2
        y = parent.winfo_y() + (parent.winfo_height() - 750) // 2
        self.dialog.geometry(f"+{x}+{y}")

        # Variables
        ti = settings_manager.threat_intel_settings
        self.rag_collection_var = tk.StringVar(value=settings_manager.ai_settings.rag_collection_name)

        self.kev_enabled_var = tk.BooleanVar(value=ti.cisa_kev_enabled)
        self.epss_enabled_var = tk.BooleanVar(value=ti.epss_enabled)
        self.nvd_enabled_var = tk.BooleanVar(value=ti.nvd_enabled)
        self.nvd_key_var = tk.StringVar(value=ti.nvd_api_key)

        self.iavm_enabled_var = tk.BooleanVar(value=ti.iavm_enabled)
        self.iavm_url_var = tk.StringVar(value=ti.iavm_feed_url)
        self.iavm_key_var = tk.StringVar(value=ti.iavm_api_key)

        self.plugins_enabled_var = tk.BooleanVar(value=ti.include_plugins_db)
        self.plugins_path_var = tk.StringVar(value=ti.plugins_db_path)

        self.auto_sync_var = tk.BooleanVar(value=ti.auto_sync_on_launch)
        self.sync_mode_var = tk.StringVar(value=ti.sync_mode)

        self._build_ui()

    def _build_ui(self):
        """Build the dialog UI."""
        main_frame = ttk.Frame(self.dialog, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # RAG Collection Name
        rag_frame = ttk.LabelFrame(main_frame, text="RAG Collection", padding="8")
        rag_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(rag_frame, text="Collection Name:").pack(side=tk.LEFT)
        ttk.Entry(rag_frame, textvariable=self.rag_collection_var, width=30).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            rag_frame,
            text="Test RAG",
            command=self._test_rag_connection
        ).pack(side=tk.RIGHT)

        # Free Feeds Section
        free_frame = ttk.LabelFrame(main_frame, text="Free Feeds", padding="8")
        free_frame.pack(fill=tk.X, pady=(0, 10))

        # CISA KEV
        kev_row = ttk.Frame(free_frame)
        kev_row.pack(fill=tk.X, pady=2)
        ttk.Checkbutton(kev_row, text="CISA KEV", variable=self.kev_enabled_var).pack(side=tk.LEFT)
        ttk.Label(kev_row, text="(No API key required)", foreground="gray").pack(side=tk.LEFT, padx=10)
        self.kev_status = ttk.Label(kev_row, text="")
        self.kev_status.pack(side=tk.RIGHT)

        # EPSS
        epss_row = ttk.Frame(free_frame)
        epss_row.pack(fill=tk.X, pady=2)
        ttk.Checkbutton(epss_row, text="EPSS", variable=self.epss_enabled_var).pack(side=tk.LEFT)
        ttk.Label(epss_row, text="(No API key required)", foreground="gray").pack(side=tk.LEFT, padx=10)
        self.epss_status = ttk.Label(epss_row, text="")
        self.epss_status.pack(side=tk.RIGHT)

        # NVD
        nvd_row = ttk.Frame(free_frame)
        nvd_row.pack(fill=tk.X, pady=2)
        ttk.Checkbutton(nvd_row, text="NVD", variable=self.nvd_enabled_var).pack(side=tk.LEFT)
        self.nvd_status = ttk.Label(nvd_row, text="")
        self.nvd_status.pack(side=tk.RIGHT)

        nvd_key_row = ttk.Frame(free_frame)
        nvd_key_row.pack(fill=tk.X, pady=2, padx=20)
        ttk.Label(nvd_key_row, text="API Key (optional):").pack(side=tk.LEFT)
        ttk.Entry(nvd_key_row, textvariable=self.nvd_key_var, width=40, show="*").pack(side=tk.LEFT, padx=5)

        ttk.Label(
            free_frame,
            text="Note: Without NVD key, rate limited to 5 requests/30 seconds",
            font=('TkDefaultFont', 8),
            foreground="gray"
        ).pack(anchor=tk.W, padx=20)

        # DoD/Gov Feeds Section
        dod_frame = ttk.LabelFrame(main_frame, text="DoD/Gov Feeds", padding="8")
        dod_frame.pack(fill=tk.X, pady=(0, 10))

        # DISA IAVM
        iavm_check = ttk.Frame(dod_frame)
        iavm_check.pack(fill=tk.X, pady=2)
        ttk.Checkbutton(iavm_check, text="DISA IAVM", variable=self.iavm_enabled_var).pack(side=tk.LEFT)
        self.iavm_status = ttk.Label(iavm_check, text="")
        self.iavm_status.pack(side=tk.RIGHT)

        iavm_url_row = ttk.Frame(dod_frame)
        iavm_url_row.pack(fill=tk.X, pady=2, padx=20)
        ttk.Label(iavm_url_row, text="Feed URL:").pack(side=tk.LEFT)
        ttk.Entry(iavm_url_row, textvariable=self.iavm_url_var, width=45).pack(side=tk.LEFT, padx=5)

        iavm_key_row = ttk.Frame(dod_frame)
        iavm_key_row.pack(fill=tk.X, pady=2, padx=20)
        ttk.Label(iavm_key_row, text="API Key:").pack(side=tk.LEFT)
        ttk.Entry(iavm_key_row, textvariable=self.iavm_key_var, width=45, show="*").pack(side=tk.LEFT, padx=5)

        # Local Sources Section
        local_frame = ttk.LabelFrame(main_frame, text="Local Sources", padding="8")
        local_frame.pack(fill=tk.X, pady=(0, 10))

        plugins_row = ttk.Frame(local_frame)
        plugins_row.pack(fill=tk.X, pady=2)
        ttk.Checkbutton(
            plugins_row,
            text="Include Plugins Database in RAG",
            variable=self.plugins_enabled_var
        ).pack(side=tk.LEFT)

        plugins_path_row = ttk.Frame(local_frame)
        plugins_path_row.pack(fill=tk.X, pady=2, padx=20)
        ttk.Label(plugins_path_row, text="Path:").pack(side=tk.LEFT)
        ttk.Entry(plugins_path_row, textvariable=self.plugins_path_var, width=40).pack(side=tk.LEFT, padx=5)
        ttk.Button(
            plugins_path_row,
            text="Browse",
            command=self._browse_plugins_db
        ).pack(side=tk.LEFT)

        # Sync Settings Section
        sync_frame = ttk.LabelFrame(main_frame, text="Sync Settings", padding="8")
        sync_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Checkbutton(
            sync_frame,
            text="Auto-sync on application launch",
            variable=self.auto_sync_var
        ).pack(anchor=tk.W)

        mode_row = ttk.Frame(sync_frame)
        mode_row.pack(fill=tk.X, pady=(5, 0))
        ttk.Label(mode_row, text="Sync Mode:").pack(side=tk.LEFT)
        ttk.Radiobutton(
            mode_row,
            text="Incremental (last 30 days)",
            variable=self.sync_mode_var,
            value="incremental"
        ).pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(
            mode_row,
            text="Full",
            variable=self.sync_mode_var,
            value="full"
        ).pack(side=tk.LEFT)

        # Last sync info
        ti = self.settings_manager.threat_intel_settings
        last_sync = ti.last_sync_timestamp or "Never"
        if ti.last_sync_stats:
            try:
                stats = json.loads(ti.last_sync_stats)
                stats_text = f" ({stats.get('total_records', 0)} records)"
            except:
                stats_text = ""
        else:
            stats_text = ""

        self.last_sync_label = ttk.Label(
            sync_frame,
            text=f"Last sync: {last_sync}{stats_text}"
        )
        self.last_sync_label.pack(anchor=tk.W, pady=(5, 0))

        # Progress Section
        progress_frame = ttk.LabelFrame(main_frame, text="Sync Progress", padding="8")
        progress_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        self.progress_bar = ttk.Progressbar(progress_frame, mode='determinate')
        self.progress_bar.pack(fill=tk.X, pady=(0, 5))

        self.progress_text = tk.Text(progress_frame, height=8, state=tk.DISABLED)
        self.progress_text.pack(fill=tk.BOTH, expand=True)

        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)

        self.sync_button = ttk.Button(
            button_frame,
            text="Sync Now",
            command=self._start_sync
        )
        self.sync_button.pack(side=tk.RIGHT, padx=5)

        ttk.Button(
            button_frame,
            text="Save",
            command=self._save_settings
        ).pack(side=tk.RIGHT, padx=5)

        ttk.Button(
            button_frame,
            text="Cancel",
            command=self.dialog.destroy
        ).pack(side=tk.RIGHT)

    def _browse_plugins_db(self):
        """Browse for plugins database file."""
        filename = filedialog.askopenfilename(
            title="Select Plugins Database",
            filetypes=[("SQLite Database", "*.db"), ("All Files", "*.*")]
        )
        if filename:
            self.plugins_path_var.set(filename)

    def _test_rag_connection(self):
        """Test connection to RAG collection."""
        ai_settings = self.settings_manager.ai_settings
        if not ai_settings.base_url or not ai_settings.api_key:
            messagebox.showwarning(
                "Not Configured",
                "Please configure OpenWebUI connection in AI Settings first."
            )
            return

        self._log_progress("Testing RAG connection...")

        def _test():
            manager = RAGSyncManager(
                base_url=ai_settings.base_url,
                api_key=ai_settings.api_key,
                collection_name=self.rag_collection_var.get()
            )
            success, message = manager.test_connection()
            self.dialog.after(0, lambda: self._log_progress(
                f"RAG Test: {'Success' if success else 'Failed'} - {message}"
            ))

        threading.Thread(target=_test, daemon=True).start()

    def _log_progress(self, message: str):
        """Log a message to the progress text widget."""
        self.progress_text.config(state=tk.NORMAL)
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.progress_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.progress_text.see(tk.END)
        self.progress_text.config(state=tk.DISABLED)

    def _on_feed_progress(self, progress: SyncProgress):
        """Handle progress updates from threat intel fetch."""
        self.dialog.after(0, lambda: self._update_feed_progress(progress))

    def _update_feed_progress(self, progress: SyncProgress):
        """Update UI with feed progress."""
        source = progress.source.value
        status = progress.status
        message = progress.message

        # Update progress bar
        if progress.progress_pct > 0:
            self.progress_bar['value'] = progress.progress_pct

        # Update status labels
        status_labels = {
            'cisa_kev': self.kev_status,
            'epss': self.epss_status,
            'nvd': self.nvd_status,
            'disa_iavm': self.iavm_status
        }

        label = status_labels.get(source)
        if label:
            if status == 'complete':
                label.config(text="Done", foreground="green")
            elif status == 'error':
                label.config(text="Error", foreground="red")
            elif status == 'fetching':
                label.config(text="Fetching...", foreground="blue")
            elif status == 'processing':
                label.config(text="Processing...", foreground="blue")

        self._log_progress(f"[{source}] {message}")

    def _on_rag_progress(self, progress: RAGSyncProgress):
        """Handle progress updates from RAG sync."""
        self.dialog.after(0, lambda: self._update_rag_progress(progress))

    def _update_rag_progress(self, progress: RAGSyncProgress):
        """Update UI with RAG sync progress."""
        self.progress_bar['value'] = progress.progress_pct
        self._log_progress(f"[RAG] {progress.message}")

    def _start_sync(self):
        """Start threat intel sync."""
        if self.sync_in_progress:
            return

        # Validate settings
        ai_settings = self.settings_manager.ai_settings
        if not ai_settings.base_url or not ai_settings.api_key:
            messagebox.showwarning(
                "Not Configured",
                "Please configure OpenWebUI connection in AI Settings first."
            )
            return

        # Save current settings first
        self._save_settings(close=False)

        self.sync_in_progress = True
        self.sync_button.config(state=tk.DISABLED)
        self.progress_bar['value'] = 0

        # Clear status labels
        for label in [self.kev_status, self.epss_status, self.nvd_status, self.iavm_status]:
            label.config(text="", foreground="black")

        self._log_progress("Starting threat intelligence sync...")

        def _do_sync():
            try:
                # Create threat intel manager
                ti = self.settings_manager.threat_intel_settings
                self.threat_intel_manager = ThreatIntelManager(
                    nvd_api_key=ti.nvd_api_key,
                    iavm_url=ti.iavm_feed_url,
                    iavm_api_key=ti.iavm_api_key
                )
                self.threat_intel_manager.add_progress_callback(self._on_feed_progress)

                # Determine NVD days based on sync mode
                nvd_days = 30 if ti.sync_mode == "incremental" else 365

                # Fetch all enabled feeds
                results = self.threat_intel_manager.fetch_all(
                    include_kev=ti.cisa_kev_enabled,
                    include_epss=ti.epss_enabled,
                    include_nvd=ti.nvd_enabled,
                    include_iavm=ti.iavm_enabled and bool(ti.iavm_feed_url),
                    nvd_days_back=nvd_days
                )

                # Get merged data
                all_data = self.threat_intel_manager.get_all_cached_data()

                self.dialog.after(0, lambda: self._log_progress(
                    f"Fetched {len(all_data)} total records"
                ))

                # Sync to RAG if we have data
                if all_data:
                    self.dialog.after(0, lambda: self._log_progress("Syncing to RAG collection..."))

                    self.rag_sync_manager = RAGSyncManager(
                        base_url=ai_settings.base_url,
                        api_key=ai_settings.api_key,
                        collection_name=self.rag_collection_var.get()
                    )
                    self.rag_sync_manager.add_progress_callback(self._on_rag_progress)

                    rag_result = self.rag_sync_manager.sync(all_data, clear_existing=False)

                    self.dialog.after(0, lambda: self._log_progress(
                        f"RAG sync: {rag_result.documents_uploaded} uploaded, "
                        f"{rag_result.documents_failed} failed"
                    ))

                # Calculate stats
                total_records = sum(r.records_fetched for r in results.values())
                stats = {
                    'total_records': total_records,
                    'sources': {k: {'count': v.records_fetched, 'success': v.success}
                               for k, v in results.items()}
                }

                # Update settings with sync info
                self.dialog.after(0, lambda: self._sync_complete(stats))

            except Exception as e:
                self.dialog.after(0, lambda: self._log_progress(f"Sync error: {str(e)}"))
                self.dialog.after(0, self._sync_finished)

        threading.Thread(target=_do_sync, daemon=True).start()

    def _sync_complete(self, stats: Dict[str, Any]):
        """Handle sync completion."""
        self.settings_manager.update_threat_intel_sync(stats)

        self._log_progress("Sync complete!")
        self.last_sync_label.config(
            text=f"Last sync: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} "
                 f"({stats.get('total_records', 0)} records)"
        )

        if self.on_sync_complete:
            self.on_sync_complete(stats)

        self._sync_finished()

    def _sync_finished(self):
        """Reset UI after sync."""
        self.sync_in_progress = False
        self.sync_button.config(state=tk.NORMAL)
        self.progress_bar['value'] = 100

    def _save_settings(self, close: bool = True):
        """Save settings."""
        ti = self.settings_manager.threat_intel_settings

        ti.cisa_kev_enabled = self.kev_enabled_var.get()
        ti.epss_enabled = self.epss_enabled_var.get()
        ti.nvd_enabled = self.nvd_enabled_var.get()
        ti.nvd_api_key = self.nvd_key_var.get().strip()

        ti.iavm_enabled = self.iavm_enabled_var.get()
        ti.iavm_feed_url = self.iavm_url_var.get().strip()
        ti.iavm_api_key = self.iavm_key_var.get().strip()

        ti.include_plugins_db = self.plugins_enabled_var.get()
        ti.plugins_db_path = self.plugins_path_var.get().strip()

        ti.auto_sync_on_launch = self.auto_sync_var.get()
        ti.sync_mode = self.sync_mode_var.get()

        # Also update RAG collection name in AI settings
        self.settings_manager.ai_settings.rag_collection_name = self.rag_collection_var.get().strip()

        self.settings_manager.save_threat_intel_settings()
        self.settings_manager.save_ai_settings()

        if close:
            self.dialog.destroy()


def show_threat_intel_dialog(
    parent: tk.Tk,
    settings_manager: SettingsManager,
    on_sync_complete: Optional[Callable[[Dict[str, Any]], None]] = None
) -> ThreatIntelDialog:
    """
    Show the threat intel configuration dialog.

    Args:
        parent: Parent window
        settings_manager: Settings manager instance
        on_sync_complete: Optional callback when sync completes

    Returns:
        Dialog instance
    """
    return ThreatIntelDialog(parent, settings_manager, on_sync_complete)
