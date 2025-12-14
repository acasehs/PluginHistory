"""
Shared Assets Configuration Dialog
Allows users to define hostnames that should be classified as shared resources.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
import os
from typing import Optional, Callable, List, Dict

try:
    from ..config import (
        EXPLICIT_ENV_MAPPINGS, SHARED_RESOURCE_PATTERNS,
        GUI_DARK_THEME
    )
except ImportError:
    from refactored_app.config import (
        EXPLICIT_ENV_MAPPINGS, SHARED_RESOURCE_PATTERNS,
        GUI_DARK_THEME
    )


class SharedAssetsDialog:
    """Dialog for managing shared asset definitions."""

    def __init__(
        self,
        parent: tk.Tk,
        settings_manager,
        on_save: Optional[Callable[[Dict], None]] = None
    ):
        """
        Initialize shared assets dialog.

        Args:
            parent: Parent window
            settings_manager: Settings manager instance
            on_save: Optional callback when settings are saved
        """
        self.parent = parent
        self.settings_manager = settings_manager
        self.on_save = on_save

        # Load current settings
        self.explicit_mappings: Dict[str, str] = dict(
            getattr(settings_manager.settings, 'shared_asset_mappings', {}) or
            EXPLICIT_ENV_MAPPINGS
        )
        self.shared_patterns: List[str] = list(
            getattr(settings_manager.settings, 'shared_asset_patterns', []) or
            SHARED_RESOURCE_PATTERNS
        )

        # Create dialog window
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Shared Assets Configuration")
        self.dialog.geometry("700x600")
        self.dialog.transient(parent)
        self.dialog.grab_set()

        # Center on parent
        self.dialog.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() - 700) // 2
        y = parent.winfo_y() + (parent.winfo_height() - 600) // 2
        self.dialog.geometry(f"+{x}+{y}")

        self._build_ui()

    def _build_ui(self):
        """Build the dialog UI."""
        main_frame = ttk.Frame(self.dialog, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Info label
        info_text = (
            "Define hostnames and patterns for shared infrastructure that serves both "
            "Production and PSS environments.\n\n"
            "Detection Priority:\n"
            "1. Explicit hostname mappings (exact match)\n"
            "2. Regex patterns (for naming conventions)\n"
            "3. Auto-detection (9-char format: letter=Prod, number=PSS)"
        )
        info_label = ttk.Label(main_frame, text=info_text, wraplength=650, justify=tk.LEFT)
        info_label.pack(fill=tk.X, pady=(0, 10))

        # Notebook for two sections
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Tab 1: Explicit Mappings
        mapping_frame = ttk.Frame(notebook, padding="10")
        notebook.add(mapping_frame, text="Explicit Mappings")
        self._build_mappings_tab(mapping_frame)

        # Tab 2: Regex Patterns
        pattern_frame = ttk.Frame(notebook, padding="10")
        notebook.add(pattern_frame, text="Regex Patterns")
        self._build_patterns_tab(pattern_frame)

        # Buttons at bottom
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))

        ttk.Button(button_frame, text="Import from JSON...", command=self._import_json).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Export to JSON...", command=self._export_json).pack(side=tk.LEFT)

        ttk.Button(button_frame, text="Cancel", command=self.dialog.destroy).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Save", command=self._save).pack(side=tk.RIGHT)

    def _build_mappings_tab(self, parent):
        """Build explicit mappings tab."""
        ttk.Label(
            parent,
            text="Add exact hostname-to-environment mappings. These take priority over patterns.",
            wraplength=550
        ).pack(anchor=tk.W, pady=(0, 5))

        # Treeview for mappings
        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        columns = ('hostname', 'environment')
        self.mapping_tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=12)
        self.mapping_tree.heading('hostname', text='Hostname')
        self.mapping_tree.heading('environment', text='Environment')
        self.mapping_tree.column('hostname', width=350)
        self.mapping_tree.column('environment', width=150)

        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.mapping_tree.yview)
        self.mapping_tree.configure(yscrollcommand=scrollbar.set)

        self.mapping_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Load existing mappings
        self._refresh_mappings_tree()

        # Add/Edit/Remove buttons
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X)

        # Entry for new mapping
        entry_frame = ttk.Frame(btn_frame)
        entry_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)

        ttk.Label(entry_frame, text="Hostname:").pack(side=tk.LEFT)
        self.new_hostname_var = tk.StringVar()
        ttk.Entry(entry_frame, textvariable=self.new_hostname_var, width=25).pack(side=tk.LEFT, padx=(2, 10))

        ttk.Label(entry_frame, text="Env:").pack(side=tk.LEFT)
        self.new_env_var = tk.StringVar(value="shared")
        env_combo = ttk.Combobox(
            entry_frame,
            textvariable=self.new_env_var,
            values=["shared", "production", "pre_production"],
            state="readonly",
            width=12
        )
        env_combo.pack(side=tk.LEFT, padx=(2, 10))

        ttk.Button(entry_frame, text="Add", command=self._add_mapping).pack(side=tk.LEFT, padx=2)
        ttk.Button(entry_frame, text="Remove Selected", command=self._remove_mapping).pack(side=tk.LEFT, padx=2)

    def _build_patterns_tab(self, parent):
        """Build regex patterns tab."""
        ttk.Label(
            parent,
            text="Add regex patterns to match hostnames. Patterns are case-insensitive.\n"
                 "Example: ^fw- matches hostnames starting with 'fw-'",
            wraplength=550
        ).pack(anchor=tk.W, pady=(0, 5))

        # Listbox for patterns
        list_frame = ttk.Frame(parent)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        self.pattern_listbox = tk.Listbox(list_frame, height=12, selectmode=tk.SINGLE)
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.pattern_listbox.yview)
        self.pattern_listbox.configure(yscrollcommand=scrollbar.set)

        self.pattern_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Load existing patterns
        self._refresh_patterns_list()

        # Add/Remove buttons
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X)

        ttk.Label(btn_frame, text="Pattern:").pack(side=tk.LEFT)
        self.new_pattern_var = tk.StringVar()
        ttk.Entry(btn_frame, textvariable=self.new_pattern_var, width=30).pack(side=tk.LEFT, padx=(2, 10))

        ttk.Button(btn_frame, text="Add", command=self._add_pattern).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Remove Selected", command=self._remove_pattern).pack(side=tk.LEFT, padx=2)

        # Common patterns help
        help_frame = ttk.LabelFrame(parent, text="Common Patterns", padding="5")
        help_frame.pack(fill=tk.X, pady=(10, 0))

        common_patterns = [
            ("^fw-", "Firewalls"),
            ("^lb-", "Load Balancers"),
            ("^switch-", "Switches"),
            ("^san-", "Storage"),
            ("^mgmt-", "Management"),
            ("-shared-", "Contains 'shared'"),
        ]

        for i, (pattern, desc) in enumerate(common_patterns):
            row = i // 3
            col = i % 3
            btn = ttk.Button(
                help_frame,
                text=f"{desc} ({pattern})",
                command=lambda p=pattern: self._quick_add_pattern(p),
                width=20
            )
            btn.grid(row=row, column=col, padx=2, pady=2)

    def _refresh_mappings_tree(self):
        """Refresh the mappings treeview."""
        for item in self.mapping_tree.get_children():
            self.mapping_tree.delete(item)

        for hostname, env in sorted(self.explicit_mappings.items()):
            self.mapping_tree.insert('', tk.END, values=(hostname, env))

    def _refresh_patterns_list(self):
        """Refresh the patterns listbox."""
        self.pattern_listbox.delete(0, tk.END)
        for pattern in sorted(self.shared_patterns):
            self.pattern_listbox.insert(tk.END, pattern)

    def _add_mapping(self):
        """Add a new hostname mapping."""
        hostname = self.new_hostname_var.get().strip().lower()
        env = self.new_env_var.get()

        if not hostname:
            messagebox.showwarning("Input Required", "Please enter a hostname.")
            return

        self.explicit_mappings[hostname] = env
        self._refresh_mappings_tree()
        self.new_hostname_var.set("")

    def _remove_mapping(self):
        """Remove selected mapping."""
        selection = self.mapping_tree.selection()
        if not selection:
            return

        for item in selection:
            values = self.mapping_tree.item(item, 'values')
            hostname = values[0]
            if hostname in self.explicit_mappings:
                del self.explicit_mappings[hostname]

        self._refresh_mappings_tree()

    def _add_pattern(self):
        """Add a new regex pattern."""
        pattern = self.new_pattern_var.get().strip()

        if not pattern:
            messagebox.showwarning("Input Required", "Please enter a pattern.")
            return

        # Validate regex
        import re
        try:
            re.compile(pattern)
        except re.error as e:
            messagebox.showerror("Invalid Pattern", f"Invalid regex pattern: {e}")
            return

        if pattern not in self.shared_patterns:
            self.shared_patterns.append(pattern)
            self._refresh_patterns_list()

        self.new_pattern_var.set("")

    def _quick_add_pattern(self, pattern: str):
        """Quick add a common pattern."""
        if pattern not in self.shared_patterns:
            self.shared_patterns.append(pattern)
            self._refresh_patterns_list()

    def _remove_pattern(self):
        """Remove selected pattern."""
        selection = self.pattern_listbox.curselection()
        if not selection:
            return

        pattern = self.pattern_listbox.get(selection[0])
        if pattern in self.shared_patterns:
            self.shared_patterns.remove(pattern)
            self._refresh_patterns_list()

    def _import_json(self):
        """Import configuration from JSON file."""
        filepath = filedialog.askopenfilename(
            parent=self.dialog,
            title="Import Shared Assets Configuration",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )

        if not filepath:
            return

        try:
            with open(filepath, 'r') as f:
                data = json.load(f)

            if 'explicit_mappings' in data:
                self.explicit_mappings.update(data['explicit_mappings'])
            if 'shared_patterns' in data:
                for pattern in data['shared_patterns']:
                    if pattern not in self.shared_patterns:
                        self.shared_patterns.append(pattern)

            self._refresh_mappings_tree()
            self._refresh_patterns_list()

            messagebox.showinfo("Import Complete", f"Imported configuration from {os.path.basename(filepath)}")

        except Exception as e:
            messagebox.showerror("Import Error", f"Failed to import: {e}")

    def _export_json(self):
        """Export configuration to JSON file."""
        filepath = filedialog.asksaveasfilename(
            parent=self.dialog,
            title="Export Shared Assets Configuration",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )

        if not filepath:
            return

        try:
            data = {
                'explicit_mappings': self.explicit_mappings,
                'shared_patterns': self.shared_patterns
            }

            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)

            messagebox.showinfo("Export Complete", f"Exported configuration to {os.path.basename(filepath)}")

        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export: {e}")

    def _save(self):
        """Save configuration to settings."""
        # Update settings
        self.settings_manager.settings.shared_asset_mappings = self.explicit_mappings
        self.settings_manager.settings.shared_asset_patterns = self.shared_patterns
        self.settings_manager.save()

        # Update the runtime config module
        try:
            import refactored_app.config as config_module
            config_module.EXPLICIT_ENV_MAPPINGS.clear()
            config_module.EXPLICIT_ENV_MAPPINGS.update(self.explicit_mappings)
            config_module.SHARED_RESOURCE_PATTERNS.clear()
            config_module.SHARED_RESOURCE_PATTERNS.extend(self.shared_patterns)
        except:
            pass

        if self.on_save:
            self.on_save({
                'explicit_mappings': self.explicit_mappings,
                'shared_patterns': self.shared_patterns
            })

        messagebox.showinfo("Saved", "Shared assets configuration saved successfully.")
        self.dialog.destroy()


def show_shared_assets_dialog(
    parent: tk.Tk,
    settings_manager,
    on_save: Optional[Callable[[Dict], None]] = None
) -> SharedAssetsDialog:
    """
    Show the shared assets configuration dialog.

    Args:
        parent: Parent window
        settings_manager: Settings manager instance
        on_save: Optional callback when settings are saved

    Returns:
        SharedAssetsDialog instance
    """
    return SharedAssetsDialog(parent, settings_manager, on_save)
