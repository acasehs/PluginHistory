"""
AI Settings Dialog
Configuration dialog for OpenWebUI AI predictions.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
from typing import Optional, Callable, List

try:
    from ..settings import SettingsManager, AISettings
    from ..ai.openwebui_client import OpenWebUIClient, OpenWebUIConfig, ConnectionStatus
except ImportError:
    from refactored_app.settings import SettingsManager, AISettings
    from refactored_app.ai.openwebui_client import OpenWebUIClient, OpenWebUIConfig, ConnectionStatus


class AISettingsDialog:
    """Dialog for configuring OpenWebUI AI predictions."""

    def __init__(
        self,
        parent: tk.Tk,
        settings_manager: SettingsManager,
        on_save: Optional[Callable[[], None]] = None
    ):
        """
        Initialize AI settings dialog.

        Args:
            parent: Parent window
            settings_manager: Settings manager instance
            on_save: Optional callback when settings are saved
        """
        self.parent = parent
        self.settings_manager = settings_manager
        self.on_save = on_save

        # Create client for testing
        self.client: Optional[OpenWebUIClient] = None
        self.available_models: List[str] = []
        self.available_collections: List[dict] = []

        # Create dialog window
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("AI Predictions Configuration")
        self.dialog.geometry("600x700")
        self.dialog.transient(parent)
        self.dialog.grab_set()

        # Center on parent
        self.dialog.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() - 600) // 2
        y = parent.winfo_y() + (parent.winfo_height() - 700) // 2
        self.dialog.geometry(f"+{x}+{y}")

        # Variables
        self.enabled_var = tk.BooleanVar(value=settings_manager.ai_settings.enabled)
        self.url_var = tk.StringVar(value=settings_manager.ai_settings.base_url)
        self.api_key_var = tk.StringVar(value=settings_manager.ai_settings.api_key)
        self.model_var = tk.StringVar(value=settings_manager.ai_settings.model)
        self.temperature_var = tk.DoubleVar(value=settings_manager.ai_settings.temperature)
        self.max_tokens_var = tk.IntVar(value=settings_manager.ai_settings.max_tokens)
        self.mode_var = tk.StringVar(value=settings_manager.ai_settings.analysis_mode)
        self.use_rag_var = tk.BooleanVar(value=settings_manager.ai_settings.use_threat_intel_rag)
        self.rag_collection_var = tk.StringVar(value=settings_manager.ai_settings.rag_collection_name)

        self._build_ui()

        # Auto-refresh models if configured
        if self.url_var.get() and self.api_key_var.get():
            self.dialog.after(500, self._refresh_resources_async)

    def _build_ui(self):
        """Build the dialog UI."""
        main_frame = ttk.Frame(self.dialog, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Enable checkbox
        enable_frame = ttk.Frame(main_frame)
        enable_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Checkbutton(
            enable_frame,
            text="Enable AI Predictions",
            variable=self.enabled_var
        ).pack(side=tk.LEFT)

        # Connection section
        conn_frame = ttk.LabelFrame(main_frame, text="Connection", padding="8")
        conn_frame.pack(fill=tk.X, pady=(0, 10))

        # URL
        ttk.Label(conn_frame, text="OpenWebUI URL:").grid(row=0, column=0, sticky=tk.W, pady=2)
        url_entry = ttk.Entry(conn_frame, textvariable=self.url_var, width=50)
        url_entry.grid(row=0, column=1, columnspan=2, sticky=tk.EW, pady=2, padx=(5, 0))

        # API Key
        ttk.Label(conn_frame, text="API Key:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.api_key_entry = ttk.Entry(conn_frame, textvariable=self.api_key_var, width=50, show="*")
        self.api_key_entry.grid(row=1, column=1, sticky=tk.EW, pady=2, padx=(5, 0))

        self.show_key_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            conn_frame,
            text="Show",
            variable=self.show_key_var,
            command=self._toggle_key_visibility
        ).grid(row=1, column=2, padx=5)

        # Connection status and test button
        status_frame = ttk.Frame(conn_frame)
        status_frame.grid(row=2, column=0, columnspan=3, sticky=tk.EW, pady=(5, 0))

        self.status_label = ttk.Label(status_frame, text="Status: Not tested")
        self.status_label.pack(side=tk.LEFT)

        ttk.Button(
            status_frame,
            text="Test Connection",
            command=self._test_connection
        ).pack(side=tk.RIGHT)

        conn_frame.columnconfigure(1, weight=1)

        # Model section
        model_frame = ttk.LabelFrame(main_frame, text="Model Selection", padding="8")
        model_frame.pack(fill=tk.X, pady=(0, 10))

        model_top = ttk.Frame(model_frame)
        model_top.pack(fill=tk.X)

        ttk.Button(
            model_top,
            text="Refresh Models",
            command=self._refresh_resources_async
        ).pack(side=tk.LEFT)

        self.model_status = ttk.Label(model_top, text="")
        self.model_status.pack(side=tk.LEFT, padx=10)

        # Model listbox
        model_list_frame = ttk.Frame(model_frame)
        model_list_frame.pack(fill=tk.BOTH, expand=True, pady=(5, 0))

        self.model_listbox = tk.Listbox(
            model_list_frame,
            height=6,
            selectmode=tk.SINGLE,
            exportselection=False
        )
        self.model_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(model_list_frame, orient=tk.VERTICAL, command=self.model_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.model_listbox.config(yscrollcommand=scrollbar.set)

        self.model_listbox.bind('<<ListboxSelect>>', self._on_model_select)

        # Currently selected model label
        self.selected_model_label = ttk.Label(model_frame, text=f"Selected: {self.model_var.get() or 'None'}")
        self.selected_model_label.pack(anchor=tk.W, pady=(5, 0))

        # Generation settings
        gen_frame = ttk.LabelFrame(main_frame, text="Generation Settings", padding="8")
        gen_frame.pack(fill=tk.X, pady=(0, 10))

        # Temperature
        temp_frame = ttk.Frame(gen_frame)
        temp_frame.pack(fill=tk.X, pady=2)

        self.temp_label = ttk.Label(temp_frame, text=f"Temperature: {self.temperature_var.get():.2f}")
        self.temp_label.pack(anchor=tk.W)

        temp_scale = ttk.Scale(
            temp_frame,
            from_=0.0,
            to=1.0,
            variable=self.temperature_var,
            orient=tk.HORIZONTAL,
            command=self._update_temp_label
        )
        temp_scale.pack(fill=tk.X)

        temp_hint = ttk.Label(
            temp_frame,
            text="Lower = more deterministic (0.10-0.20 recommended for predictions)",
            font=('TkDefaultFont', 8)
        )
        temp_hint.pack(anchor=tk.W)

        # Max tokens
        tokens_frame = ttk.Frame(gen_frame)
        tokens_frame.pack(fill=tk.X, pady=(10, 2))

        ttk.Label(tokens_frame, text="Max Tokens:").pack(side=tk.LEFT)
        ttk.Entry(tokens_frame, textvariable=self.max_tokens_var, width=10).pack(side=tk.LEFT, padx=5)

        # Analysis mode
        mode_frame = ttk.Frame(gen_frame)
        mode_frame.pack(fill=tk.X, pady=(10, 2))

        ttk.Label(mode_frame, text="Default Analysis Mode:").pack(anchor=tk.W)

        ttk.Radiobutton(
            mode_frame,
            text="Quick (faster, top findings only)",
            variable=self.mode_var,
            value="quick"
        ).pack(anchor=tk.W, padx=20)

        ttk.Radiobutton(
            mode_frame,
            text="Comprehensive (all data, slower)",
            variable=self.mode_var,
            value="comprehensive"
        ).pack(anchor=tk.W, padx=20)

        # RAG settings
        rag_frame = ttk.LabelFrame(main_frame, text="RAG Integration", padding="8")
        rag_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Checkbutton(
            rag_frame,
            text="Use Threat Intelligence RAG",
            variable=self.use_rag_var
        ).pack(anchor=tk.W)

        rag_name_frame = ttk.Frame(rag_frame)
        rag_name_frame.pack(fill=tk.X, pady=(5, 0))

        ttk.Label(rag_name_frame, text="Collection Name:").pack(side=tk.LEFT)
        ttk.Entry(rag_name_frame, textvariable=self.rag_collection_var, width=30).pack(side=tk.LEFT, padx=5)

        # Available collections
        self.collections_label = ttk.Label(rag_frame, text="Available collections: Loading...")
        self.collections_label.pack(anchor=tk.W, pady=(5, 0))

        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))

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

        ttk.Button(
            button_frame,
            text="Reset to Defaults",
            command=self._reset_defaults
        ).pack(side=tk.LEFT)

    def _toggle_key_visibility(self):
        """Toggle API key visibility."""
        if self.show_key_var.get():
            self.api_key_entry.config(show="")
        else:
            self.api_key_entry.config(show="*")

    def _update_temp_label(self, value):
        """Update temperature label with rounded value."""
        rounded = round(float(value), 2)
        self.temp_label.config(text=f"Temperature: {rounded:.2f}")

    def _test_connection(self):
        """Test connection to OpenWebUI."""
        url = self.url_var.get().strip()
        key = self.api_key_var.get().strip()

        if not url or not key:
            messagebox.showwarning("Missing Info", "Please enter URL and API key")
            return

        self.status_label.config(text="Status: Testing...")
        self.dialog.update()

        def _test():
            config = OpenWebUIConfig(base_url=url, api_key=key)
            client = OpenWebUIClient(config)
            success = client.test_connection()

            self.dialog.after(0, lambda: self._update_connection_status(
                success, client.status_message
            ))

        threading.Thread(target=_test, daemon=True).start()

    def _update_connection_status(self, success: bool, message: str):
        """Update connection status in UI."""
        if success:
            self.status_label.config(text=f"Status: Connected", foreground="green")
        else:
            self.status_label.config(text=f"Status: {message}", foreground="red")

    def _refresh_resources_async(self):
        """Refresh models and collections asynchronously."""
        url = self.url_var.get().strip()
        key = self.api_key_var.get().strip()

        if not url or not key:
            return

        self.model_status.config(text="Loading models...")

        def _fetch():
            config = OpenWebUIConfig(base_url=url, api_key=key)
            self.client = OpenWebUIClient(config)

            models = self.client.refresh_models()
            collections = self.client.refresh_collections()

            self.dialog.after(0, lambda: self._update_resources(models, collections))

        threading.Thread(target=_fetch, daemon=True).start()

    def _update_resources(self, models: List[str], collections: List[dict]):
        """Update models and collections in UI."""
        self.available_models = models
        self.available_collections = collections

        # Update model listbox
        self.model_listbox.delete(0, tk.END)
        for model in models:
            self.model_listbox.insert(tk.END, model)

        # Select current model if in list
        current_model = self.model_var.get()
        if current_model in models:
            idx = models.index(current_model)
            self.model_listbox.selection_set(idx)
            self.model_listbox.see(idx)

        self.model_status.config(text=f"{len(models)} models available")

        # Update collections label
        if collections:
            names = [c.get('name', 'Unknown') for c in collections]
            self.collections_label.config(text=f"Available collections: {', '.join(names[:5])}")
        else:
            self.collections_label.config(text="Available collections: None found")

    def _on_model_select(self, event):
        """Handle model selection."""
        selection = self.model_listbox.curselection()
        if selection:
            model = self.model_listbox.get(selection[0])
            self.model_var.set(model)
            self.selected_model_label.config(text=f"Selected: {model}")

    def _save_settings(self):
        """Save settings and close dialog."""
        # Validate
        if self.enabled_var.get():
            if not self.url_var.get().strip():
                messagebox.showwarning("Validation", "OpenWebUI URL is required")
                return
            if not self.api_key_var.get().strip():
                messagebox.showwarning("Validation", "API Key is required")
                return

        # Update settings
        ai = self.settings_manager.ai_settings
        ai.enabled = self.enabled_var.get()
        ai.base_url = self.url_var.get().strip()
        ai.api_key = self.api_key_var.get().strip()
        ai.model = self.model_var.get()
        ai.temperature = round(self.temperature_var.get(), 2)
        ai.max_tokens = self.max_tokens_var.get()
        ai.analysis_mode = self.mode_var.get()
        ai.use_threat_intel_rag = self.use_rag_var.get()
        ai.rag_collection_name = self.rag_collection_var.get().strip()

        # Save
        self.settings_manager.save_ai_settings()

        # Callback
        if self.on_save:
            self.on_save()

        self.dialog.destroy()

    def _reset_defaults(self):
        """Reset to default settings."""
        if messagebox.askyesno("Reset", "Reset AI settings to defaults?"):
            defaults = AISettings()
            self.enabled_var.set(defaults.enabled)
            self.url_var.set(defaults.base_url)
            self.api_key_var.set(defaults.api_key)
            self.model_var.set(defaults.model)
            self.temperature_var.set(defaults.temperature)
            self.max_tokens_var.set(defaults.max_tokens)
            self.mode_var.set(defaults.analysis_mode)
            self.use_rag_var.set(defaults.use_threat_intel_rag)
            self.rag_collection_var.set(defaults.rag_collection_name)

            self._update_temp_label(defaults.temperature)
            self.selected_model_label.config(text="Selected: None")


def show_ai_settings_dialog(
    parent: tk.Tk,
    settings_manager: SettingsManager,
    on_save: Optional[Callable[[], None]] = None
) -> AISettingsDialog:
    """
    Show the AI settings dialog.

    Args:
        parent: Parent window
        settings_manager: Settings manager instance
        on_save: Optional callback when settings are saved

    Returns:
        Dialog instance
    """
    return AISettingsDialog(parent, settings_manager, on_save)
