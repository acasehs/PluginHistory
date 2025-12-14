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
        on_save: Optional[Callable[[Dict], None]] = None,
        hostnames: Optional[List[str]] = None
    ):
        """
        Initialize shared assets dialog.

        Args:
            parent: Parent window
            settings_manager: Settings manager instance
            on_save: Optional callback when settings are saved
            hostnames: Optional list of hostnames from loaded data
        """
        self.parent = parent
        self.settings_manager = settings_manager
        self.on_save = on_save
        self.all_hostnames = hostnames or []

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

        # Notebook for sections
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Tab 1: Host Assignment (from loaded data)
        hosts_frame = ttk.Frame(notebook, padding="10")
        notebook.add(hosts_frame, text="Assign Hosts")
        self._build_hosts_tab(hosts_frame)

        # Tab 2: Explicit Mappings (manual entry)
        mapping_frame = ttk.Frame(notebook, padding="10")
        notebook.add(mapping_frame, text="Manual Entry")
        self._build_mappings_tab(mapping_frame)

        # Tab 3: Regex Patterns
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

    def _classify_hostname(self, hostname: str) -> str:
        """Classify a hostname using current settings."""
        import re
        hostname_lower = hostname.lower().strip()

        # Check explicit mappings first
        if hostname_lower in self.explicit_mappings:
            env = self.explicit_mappings[hostname_lower]
            if env == 'production':
                return 'Production'
            elif env == 'pre_production':
                return 'PSS'
            elif env == 'shared':
                return 'Shared'

        # Check shared patterns
        for pattern in self.shared_patterns:
            try:
                if re.match(pattern, hostname_lower, re.IGNORECASE):
                    return 'Shared'
            except:
                pass

        # Auto-detect from 9-char format
        base = hostname_lower.replace('-ilom', '').replace('ilom', '')
        if len(base) == 9:
            env_char = base[7:8]
            if env_char.isalpha():
                return 'Production'
            elif env_char.isdigit():
                return 'PSS'

        return 'Unknown'

    def _build_hosts_tab(self, parent):
        """Build host assignment tab with list of hosts from data."""
        # Filter controls
        filter_frame = ttk.Frame(parent)
        filter_frame.pack(fill=tk.X, pady=(0, 5))

        ttk.Label(filter_frame, text="Show:").pack(side=tk.LEFT)
        self.host_filter_var = tk.StringVar(value="Unknown")
        filter_combo = ttk.Combobox(
            filter_frame,
            textvariable=self.host_filter_var,
            values=["All", "Unknown", "Production", "PSS", "Shared"],
            state="readonly",
            width=12
        )
        filter_combo.pack(side=tk.LEFT, padx=(5, 15))
        filter_combo.bind('<<ComboboxSelected>>', lambda e: self._refresh_hosts_list())

        ttk.Label(filter_frame, text="Search:").pack(side=tk.LEFT)
        self.host_search_var = tk.StringVar()
        search_entry = ttk.Entry(filter_frame, textvariable=self.host_search_var, width=20)
        search_entry.pack(side=tk.LEFT, padx=(5, 5))
        search_entry.bind('<KeyRelease>', lambda e: self._refresh_hosts_list())

        # Host list with checkboxes (using Treeview)
        list_frame = ttk.Frame(parent)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        columns = ('hostname', 'current_env')
        self.hosts_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=10, selectmode='extended')
        self.hosts_tree.heading('hostname', text='Hostname')
        self.hosts_tree.heading('current_env', text='Current Classification')
        self.hosts_tree.column('hostname', width=350)
        self.hosts_tree.column('current_env', width=150)

        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.hosts_tree.yview)
        self.hosts_tree.configure(yscrollcommand=scrollbar.set)

        self.hosts_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Load hosts
        self._refresh_hosts_list()

        # Assignment controls
        assign_frame = ttk.Frame(parent)
        assign_frame.pack(fill=tk.X)

        ttk.Label(assign_frame, text="Assign selected to:").pack(side=tk.LEFT)
        self.assign_env_var = tk.StringVar(value="shared")
        assign_combo = ttk.Combobox(
            assign_frame,
            textvariable=self.assign_env_var,
            values=["shared", "production", "pre_production"],
            state="readonly",
            width=12
        )
        assign_combo.pack(side=tk.LEFT, padx=(5, 10))

        ttk.Button(assign_frame, text="Assign Selected", command=self._assign_selected_hosts).pack(side=tk.LEFT, padx=2)
        ttk.Button(assign_frame, text="Select All Visible", command=self._select_all_hosts).pack(side=tk.LEFT, padx=2)
        ttk.Button(assign_frame, text="Clear Selection", command=self._clear_host_selection).pack(side=tk.LEFT, padx=2)

        # Status label
        self.hosts_status_label = ttk.Label(parent, text="", foreground="gray")
        self.hosts_status_label.pack(anchor=tk.W, pady=(5, 0))

        if not self.all_hostnames:
            self.hosts_status_label.config(text="No host data loaded. Load Nessus archives first.")

    def _refresh_hosts_list(self):
        """Refresh the hosts list based on filter."""
        for item in self.hosts_tree.get_children():
            self.hosts_tree.delete(item)

        if not self.all_hostnames:
            return

        filter_type = self.host_filter_var.get()
        search_term = self.host_search_var.get().lower().strip()

        count = 0
        for hostname in sorted(set(self.all_hostnames)):
            if not isinstance(hostname, str):
                continue

            # Apply search filter
            if search_term and search_term not in hostname.lower():
                continue

            # Classify and filter
            current_env = self._classify_hostname(hostname)

            if filter_type != "All" and current_env != filter_type:
                continue

            self.hosts_tree.insert('', tk.END, values=(hostname, current_env))
            count += 1

        self.hosts_status_label.config(text=f"Showing {count} hosts")

    def _assign_selected_hosts(self):
        """Assign selected hosts to chosen environment."""
        selection = self.hosts_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select hosts to assign.")
            return

        env = self.assign_env_var.get()
        count = 0

        for item in selection:
            values = self.hosts_tree.item(item, 'values')
            hostname = values[0].lower()
            self.explicit_mappings[hostname] = env
            count += 1

        self._refresh_hosts_list()
        self._refresh_mappings_tree()
        messagebox.showinfo("Assigned", f"Assigned {count} hosts to '{env}'")

    def _select_all_hosts(self):
        """Select all visible hosts in the list."""
        for item in self.hosts_tree.get_children():
            self.hosts_tree.selection_add(item)

    def _clear_host_selection(self):
        """Clear host selection."""
        self.hosts_tree.selection_remove(self.hosts_tree.selection())

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
    on_save: Optional[Callable[[Dict], None]] = None,
    hostnames: Optional[List[str]] = None
) -> SharedAssetsDialog:
    """
    Show the shared assets configuration dialog.

    Args:
        parent: Parent window
        settings_manager: Settings manager instance
        on_save: Optional callback when settings are saved
        hostnames: Optional list of hostnames from loaded data

    Returns:
        SharedAssetsDialog instance
    """
    return SharedAssetsDialog(parent, settings_manager, on_save, hostnames)
