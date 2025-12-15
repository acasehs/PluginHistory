"""
Package Version Impact Analysis Dialog

GUI dialog for loading, analyzing, and visualizing package version impact
for remediation prioritization.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import pandas as pd
import threading
from typing import Optional, List, Dict, Any, Callable
from datetime import datetime
import os

from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
from matplotlib.figure import Figure

try:
    from ..analysis.package_version_impact import (
        analyze_package_version_impact,
        create_remediation_summary_df,
        calculate_cumulative_impact,
        estimate_remediation_effort,
        export_remediation_plan,
        RemediationPlan,
        PackageVersionInfo
    )
    from ..analysis.cve_validation import (
        CVEValidator,
        ValidationResult,
        create_cve_validation_report
    )
    from ..visualization.package_impact_charts import (
        create_package_impact_bar_chart,
        create_cumulative_impact_chart,
        create_severity_breakdown_chart,
        create_quick_wins_chart
    )
    from ..visualization.remediation_dashboard import (
        create_remediation_impact_dashboard,
        create_executive_remediation_summary
    )
except ImportError:
    from refactored_app.analysis.package_version_impact import (
        analyze_package_version_impact,
        create_remediation_summary_df,
        calculate_cumulative_impact,
        estimate_remediation_effort,
        export_remediation_plan,
        RemediationPlan,
        PackageVersionInfo
    )
    from refactored_app.analysis.cve_validation import (
        CVEValidator,
        ValidationResult,
        create_cve_validation_report
    )
    from refactored_app.visualization.package_impact_charts import (
        create_package_impact_bar_chart,
        create_cumulative_impact_chart,
        create_severity_breakdown_chart,
        create_quick_wins_chart
    )
    from refactored_app.visualization.remediation_dashboard import (
        create_remediation_impact_dashboard,
        create_executive_remediation_summary
    )


class PackageImpactDialog:
    """
    Dialog for analyzing and visualizing package version remediation impact.

    Provides:
    - Loading version extraction data (from Tenable Version Extractor)
    - Impact analysis and prioritization
    - Interactive visualizations
    - CVE validation against NVD
    - Export capabilities
    """

    def __init__(
        self,
        parent: tk.Tk,
        findings_df: Optional[pd.DataFrame] = None,
        on_close: Optional[Callable] = None
    ):
        """
        Initialize the package impact dialog.

        Args:
            parent: Parent window
            findings_df: Optional findings DataFrame for severity enrichment
            on_close: Optional callback when dialog closes
        """
        self.parent = parent
        self.findings_df = findings_df
        self.on_close = on_close
        self.plan: Optional[RemediationPlan] = None
        self.version_df: Optional[pd.DataFrame] = None
        self.current_chart: Optional[Figure] = None
        self.processing = False

        # Create dialog
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Package Version Impact Analysis")
        self.dialog.geometry("1400x1170")  # 30% taller to fit all content
        self.dialog.transient(parent)

        # Dark theme colors
        self.bg_color = '#2b2b2b'
        self.fg_color = 'white'
        self.entry_bg = '#404040'

        # Apply dark theme
        self.dialog.configure(bg=self.bg_color)

        # Center on parent
        self.dialog.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() - 1400) // 2
        y = parent.winfo_y() + (parent.winfo_height() - 900) // 2
        self.dialog.geometry(f"+{x}+{y}")

        self._build_ui()

        # Handle close
        self.dialog.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self):
        """Build the dialog UI."""
        # Main container
        main_frame = ttk.Frame(self.dialog, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Tab 1: Data & Analysis
        self._build_data_tab()

        # Tab 2: Visualizations
        self._build_viz_tab()

        # Tab 3: Prioritized List
        self._build_list_tab()

        # Tab 4: CVE Validation
        self._build_cve_tab()

        # Tab 5: Export
        self._build_export_tab()

    def _build_data_tab(self):
        """Build the data loading and analysis tab."""
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="Data & Analysis")

        # Option 1: Extract from Lifecycle Data (Primary option)
        extract_frame = ttk.LabelFrame(tab, text="Extract from Active Findings", padding="10")
        extract_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(
            extract_frame,
            text="Extract package/version information directly from plugin output in loaded findings:",
            wraplength=800
        ).pack(anchor=tk.W)

        extract_btn_frame = ttk.Frame(extract_frame)
        extract_btn_frame.pack(fill=tk.X, pady=(10, 0))

        ttk.Button(
            extract_btn_frame,
            text="Extract & Analyze from Lifecycle Data",
            command=self._extract_from_lifecycle
        ).pack(side=tk.LEFT)

        self.extract_status_label = ttk.Label(extract_btn_frame, text="")
        self.extract_status_label.pack(side=tk.LEFT, padx=10)

        # Show finding count if available
        if self.findings_df is not None and not self.findings_df.empty:
            count = len(self.findings_df)
            has_output = 'plugin_output' in self.findings_df.columns
            # Count active findings
            active_count = count
            if 'status' in self.findings_df.columns:
                active_count = len(self.findings_df[self.findings_df['status'] == 'Active'])
            status = f"✓ {active_count:,} active findings" + (" with plugin_output" if has_output else " (no plugin_output column)")
            self.extract_status_label.config(text=status, foreground='#66ff66' if has_output else '#ffaa00')
        else:
            self.extract_status_label.config(text="⚠ No findings loaded - load data first", foreground='#ff6666')

        # Option 2: Load from file (Alternative)
        load_frame = ttk.LabelFrame(tab, text="Or Load from External File", padding="10")
        load_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(
            load_frame,
            text="Load extracted version data from Tenable Version Extractor or similar tool:"
        ).pack(anchor=tk.W)

        file_frame = ttk.Frame(load_frame)
        file_frame.pack(fill=tk.X, pady=(5, 0))

        self.file_path_var = tk.StringVar()
        self.file_entry = ttk.Entry(file_frame, textvariable=self.file_path_var, width=80)
        self.file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        ttk.Button(
            file_frame,
            text="Browse...",
            command=self._browse_file
        ).pack(side=tk.LEFT, padx=(0, 5))

        ttk.Button(
            file_frame,
            text="Load & Analyze",
            command=self._load_and_analyze
        ).pack(side=tk.LEFT)

        # Progress
        self.progress_frame = ttk.Frame(tab)
        self.progress_frame.pack(fill=tk.X, pady=(5, 0))
        self.progress_label = ttk.Label(self.progress_frame, text="")
        self.progress_label.pack(side=tk.LEFT)
        self.progress_bar = ttk.Progressbar(self.progress_frame, mode='indeterminate', length=200)

        # Summary section
        summary_frame = ttk.LabelFrame(tab, text="Analysis Summary", padding="10")
        summary_frame.pack(fill=tk.BOTH, expand=True)

        # Summary text
        self.summary_text = tk.Text(
            summary_frame,
            wrap=tk.WORD,
            font=('Consolas', 10),
            bg=self.entry_bg,
            fg=self.fg_color,
            height=20
        )
        self.summary_text.pack(fill=tk.BOTH, expand=True)

        # Configure tags
        self.summary_text.tag_configure('header', font=('Consolas', 12, 'bold'), foreground='#00aaff')
        self.summary_text.tag_configure('subheader', font=('Consolas', 11, 'bold'), foreground='#aaffaa')
        self.summary_text.tag_configure('metric', foreground='#ffaa00')
        self.summary_text.tag_configure('warning', foreground='#ff6666')
        self.summary_text.tag_configure('success', foreground='#66ff66')

    def _extract_from_lifecycle(self):
        """Extract package/version data from lifecycle findings plugin_output."""
        if self.findings_df is None or self.findings_df.empty:
            messagebox.showwarning("No Data", "No findings data loaded. Please load findings first.")
            return

        if 'plugin_output' not in self.findings_df.columns:
            messagebox.showwarning(
                "Missing Data",
                "The loaded findings don't have a 'plugin_output' column.\n\n"
                "Package version extraction requires the plugin_output field."
            )
            return

        self.processing = True
        self.progress_label.config(text="Extracting package versions from plugin output...")
        self.progress_bar.pack(side=tk.LEFT, padx=5)
        self.progress_bar.start(10)

        def _process():
            try:
                # Filter to only active findings
                df_to_process = self.findings_df.copy()
                if 'status' in df_to_process.columns:
                    df_to_process = df_to_process[df_to_process['status'] == 'Active']

                if df_to_process.empty:
                    self.dialog.after(0, lambda: self._extraction_warning(
                        "No active findings found.\n\n"
                        "The analysis only includes active findings (not fixed/closed)."
                    ))
                    return

                # Extract package/version info from plugin_output
                version_data = self._parse_plugin_outputs(df_to_process)

                if version_data.empty:
                    self.dialog.after(0, lambda: self._extraction_warning(
                        "No package version information found in plugin outputs.\n\n"
                        "This typically happens when:\n"
                        "• Findings are not patch-related vulnerabilities\n"
                        "• Plugin output doesn't contain version information\n"
                        "• The plugin output format is not recognized"
                    ))
                    return

                self.version_df = version_data

                # Run analysis
                self.plan = analyze_package_version_impact(
                    self.version_df,
                    self.findings_df
                )

                self.dialog.after(0, self._analysis_complete)

            except Exception as e:
                import traceback
                traceback.print_exc()
                self.dialog.after(0, lambda: self._analysis_error(str(e)))

        threading.Thread(target=_process, daemon=True).start()

    def _parse_plugin_outputs(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Parse plugin_output field to extract package/version information.

        Args:
            df: DataFrame with plugin_output column

        Returns:
            DataFrame with extracted version data
        """
        import re

        records = []

        for _, row in df.iterrows():
            output = str(row.get('plugin_output', ''))
            if not output or output == 'nan':
                continue

            hostname = row.get('hostname', 'Unknown')
            plugin_id = str(row.get('plugin_id', ''))
            severity = row.get('severity_text', row.get('severity', 'Unknown'))

            # Extract CVEs from the output or from cves column
            cves_col = row.get('cves', row.get('CVEs', ''))
            cves = []
            if cves_col and str(cves_col) != 'nan':
                cves = re.findall(r'CVE-\d{4}-\d+', str(cves_col))
            cves.extend(re.findall(r'CVE-\d{4}-\d+', output))
            cves = list(set(cves))

            # Try multiple patterns to extract package/version info

            # Pattern 1: "Package: xxx / Installed version: xxx / Fixed version: xxx"
            pkg_match = re.search(r'[Pp]ackage\s*[:=]\s*([^\n\r]+)', output)
            installed_match = re.search(r'[Ii]nstalled\s+[Vv]ersion\s*[:=]\s*([^\n\r]+)', output)
            fixed_match = re.search(r'[Ff]ixed\s+[Vv]ersion\s*[:=]\s*([^\n\r]+)', output)

            if pkg_match and (installed_match or fixed_match):
                records.append({
                    'package_name': pkg_match.group(1).strip(),
                    'installed_version': installed_match.group(1).strip() if installed_match else '',
                    'target_version': fixed_match.group(1).strip() if fixed_match else '',
                    'hostname': hostname,
                    'plugin_id': plugin_id,
                    'severity': severity,
                    'cves': ','.join(cves)
                })
                continue

            # Pattern 2: "Remote package installed : xxx-version" (common Nessus format)
            remote_pkg = re.findall(r'[Rr]emote\s+package\s+installed\s*:\s*([^\n\r]+)', output)
            should_be = re.findall(r'[Ss]hould\s+be\s*:\s*([^\n\r]+)', output)

            if remote_pkg:
                for i, pkg_str in enumerate(remote_pkg):
                    pkg_str = pkg_str.strip()
                    # Try to split package-version
                    # Pattern: name-version or name version
                    match = re.match(r'^([a-zA-Z][a-zA-Z0-9._+-]*?)[-_](\d[^\s]*)$', pkg_str)
                    if match:
                        pkg_name = match.group(1)
                        installed_ver = match.group(2)
                    else:
                        pkg_name = pkg_str
                        installed_ver = ''

                    target_ver = should_be[i].strip() if i < len(should_be) else ''

                    records.append({
                        'package_name': pkg_name,
                        'installed_version': installed_ver,
                        'target_version': target_ver,
                        'hostname': hostname,
                        'plugin_id': plugin_id,
                        'severity': severity,
                        'cves': ','.join(cves)
                    })
                continue

            # Pattern 3: Path-based versions (e.g., "Path: /opt/java\nVersion: 1.8.0")
            path_match = re.search(r'[Pp]ath\s*[:=]\s*([^\n\r]+)', output)
            version_match = re.search(r'\b[Vv]ersion\s*[:=]\s*([0-9][^\n\r]*)', output)
            fixed_ver_match = re.search(r'[Ff]ix(?:ed)?\s*[:=]\s*([0-9][^\n\r]*)', output)

            if path_match and version_match:
                path = path_match.group(1).strip()
                # Extract app name from path
                app_name = path.split('/')[-1] or path.split('\\')[-1] or 'Unknown'
                records.append({
                    'package_name': app_name,
                    'installed_version': version_match.group(1).strip(),
                    'target_version': fixed_ver_match.group(1).strip() if fixed_ver_match else '',
                    'hostname': hostname,
                    'plugin_id': plugin_id,
                    'severity': severity,
                    'cves': ','.join(cves)
                })
                continue

            # Pattern 4: Simple version pattern "xxx is installed" / "version xxx"
            simple_ver = re.search(r'[Vv]ersion\s+([0-9][0-9.]*[^\s]*)\s+(?:is\s+)?installed', output)
            if simple_ver:
                # Try to get product name from plugin_name if available
                plugin_name = row.get('plugin_name', '')
                # Extract likely package name from plugin name
                pkg_from_name = re.sub(r'\s*[Vv]ulnerability.*|\s*[Dd]etection.*|\s*<\s*[\d.]+.*', '', str(plugin_name)).strip()

                records.append({
                    'package_name': pkg_from_name or 'Unknown',
                    'installed_version': simple_ver.group(1).strip(),
                    'target_version': '',
                    'hostname': hostname,
                    'plugin_id': plugin_id,
                    'severity': severity,
                    'cves': ','.join(cves)
                })
                continue

            # Pattern 5: For patch-related plugins, try to extract from structured output
            # "Installed package : kernel-3.10.0-1160.el7\n  Fixed package : kernel-3.10.0-1160.88.1.el7"
            installed_pkg = re.search(r'[Ii]nstalled\s+package\s*:\s*([^\n\r]+)', output)
            fixed_pkg = re.search(r'[Ff]ixed\s+package\s*:\s*([^\n\r]+)', output)

            if installed_pkg:
                pkg_str = installed_pkg.group(1).strip()
                # Extract name and version
                match = re.match(r'^([a-zA-Z][a-zA-Z0-9._+-]*?)[-_](\d[^\s]*)$', pkg_str)
                if match:
                    records.append({
                        'package_name': match.group(1),
                        'installed_version': match.group(2),
                        'target_version': fixed_pkg.group(1).strip() if fixed_pkg else '',
                        'hostname': hostname,
                        'plugin_id': plugin_id,
                        'severity': severity,
                        'cves': ','.join(cves)
                    })

        result_df = pd.DataFrame(records)

        # Remove duplicates based on package_name, hostname, and plugin_id
        if not result_df.empty:
            result_df = result_df.drop_duplicates(
                subset=['package_name', 'hostname', 'plugin_id'],
                keep='first'
            )

        return result_df

    def _extraction_warning(self, message: str):
        """Handle extraction warning."""
        self.processing = False
        self.progress_bar.stop()
        self.progress_bar.pack_forget()
        self.progress_label.config(text="")
        messagebox.showwarning("Extraction Warning", message)

    def _build_viz_tab(self):
        """Build the visualizations tab."""
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="Visualizations")

        # Chart selection
        control_frame = ttk.Frame(tab)
        control_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(control_frame, text="Chart Type:").pack(side=tk.LEFT)

        self.chart_var = tk.StringVar(value="dashboard")
        charts = [
            ("Full Dashboard", "dashboard"),
            ("Executive Summary", "executive"),
            ("Impact Ranking", "impact"),
            ("Cumulative Impact", "cumulative"),
            ("Severity Breakdown", "severity"),
            ("Quick Wins", "quickwins")
        ]

        for text, value in charts:
            ttk.Radiobutton(
                control_frame,
                text=text,
                value=value,
                variable=self.chart_var,
                command=self._update_chart
            ).pack(side=tk.LEFT, padx=5)

        # Chart display area
        self.chart_frame = ttk.Frame(tab)
        self.chart_frame.pack(fill=tk.BOTH, expand=True)

        # Placeholder
        self.chart_placeholder = ttk.Label(
            self.chart_frame,
            text="Load version data to view charts",
            font=('TkDefaultFont', 14)
        )
        self.chart_placeholder.pack(expand=True)

    def _build_list_tab(self):
        """Build the prioritized list tab."""
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="Prioritized List")

        # Search/filter frame
        filter_frame = ttk.Frame(tab)
        filter_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(filter_frame, text="Search:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        self.search_var.trace('w', lambda *args: self._filter_list())
        ttk.Entry(filter_frame, textvariable=self.search_var, width=30).pack(side=tk.LEFT, padx=5)

        ttk.Label(filter_frame, text="Min Impact:").pack(side=tk.LEFT, padx=(20, 5))
        self.min_impact_var = tk.StringVar(value="0")
        ttk.Entry(filter_frame, textvariable=self.min_impact_var, width=10).pack(side=tk.LEFT)

        ttk.Button(filter_frame, text="Apply", command=self._filter_list).pack(side=tk.LEFT, padx=5)

        # Treeview for package list
        tree_frame = ttk.Frame(tab)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        columns = (
            'priority', 'package', 'target_version', 'hosts', 'findings',
            'impact_score', 'critical', 'high', 'cves'
        )

        self.package_tree = ttk.Treeview(tree_frame, columns=columns, show='headings')

        # Define headings
        self.package_tree.heading('priority', text='#')
        self.package_tree.heading('package', text='Package')
        self.package_tree.heading('target_version', text='Target Version')
        self.package_tree.heading('hosts', text='Hosts')
        self.package_tree.heading('findings', text='Findings')
        self.package_tree.heading('impact_score', text='Impact')
        self.package_tree.heading('critical', text='Critical')
        self.package_tree.heading('high', text='High')
        self.package_tree.heading('cves', text='CVEs')

        # Define column widths
        self.package_tree.column('priority', width=40, anchor=tk.CENTER)
        self.package_tree.column('package', width=200)
        self.package_tree.column('target_version', width=120)
        self.package_tree.column('hosts', width=60, anchor=tk.CENTER)
        self.package_tree.column('findings', width=70, anchor=tk.CENTER)
        self.package_tree.column('impact_score', width=80, anchor=tk.CENTER)
        self.package_tree.column('critical', width=60, anchor=tk.CENTER)
        self.package_tree.column('high', width=60, anchor=tk.CENTER)
        self.package_tree.column('cves', width=60, anchor=tk.CENTER)

        # Scrollbars
        y_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.package_tree.yview)
        x_scroll = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.package_tree.xview)
        self.package_tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)

        self.package_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        y_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Double-click to show details
        self.package_tree.bind('<Double-1>', self._show_package_details)

        # Status bar
        self.list_status = ttk.Label(tab, text="")
        self.list_status.pack(anchor=tk.W, pady=(5, 0))

    def _build_cve_tab(self):
        """Build the CVE validation tab."""
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="CVE Validation")

        # Info section
        info_frame = ttk.LabelFrame(tab, text="CVE Database Validation", padding="10")
        info_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(
            info_frame,
            text="Validate that target versions actually resolve associated CVEs using NVD database.\n"
                 "Note: This requires internet access and may take time due to API rate limits.",
            wraplength=800
        ).pack(anchor=tk.W)

        # Options
        options_frame = ttk.Frame(info_frame)
        options_frame.pack(fill=tk.X, pady=(10, 0))

        self.validate_critical_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            options_frame,
            text="Critical severity only",
            variable=self.validate_critical_var
        ).pack(side=tk.LEFT)

        self.validate_top_n_var = tk.StringVar(value="10")
        ttk.Label(options_frame, text="Top N packages:").pack(side=tk.LEFT, padx=(20, 5))
        ttk.Entry(options_frame, textvariable=self.validate_top_n_var, width=5).pack(side=tk.LEFT)

        ttk.Button(
            options_frame,
            text="Validate Top N",
            command=self._validate_cves
        ).pack(side=tk.LEFT, padx=(20, 0))

        ttk.Button(
            options_frame,
            text="Validate All",
            command=self._validate_all_cves
        ).pack(side=tk.LEFT, padx=(5, 0))

        # Results
        results_frame = ttk.LabelFrame(tab, text="Validation Results", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True)

        self.cve_results_text = tk.Text(
            results_frame,
            wrap=tk.WORD,
            font=('Consolas', 10),
            bg=self.entry_bg,
            fg=self.fg_color
        )
        self.cve_results_text.pack(fill=tk.BOTH, expand=True)

        self.cve_results_text.tag_configure('header', font=('Consolas', 12, 'bold'), foreground='#00aaff')
        self.cve_results_text.tag_configure('success', foreground='#66ff66')
        self.cve_results_text.tag_configure('warning', foreground='#ffaa00')
        self.cve_results_text.tag_configure('error', foreground='#ff6666')

    def _build_export_tab(self):
        """Build the export tab."""
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="Export")

        # Export options
        options_frame = ttk.LabelFrame(tab, text="Export Options", padding="10")
        options_frame.pack(fill=tk.X, pady=(0, 10))

        # Format selection
        format_frame = ttk.Frame(options_frame)
        format_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(format_frame, text="Export Format:").pack(side=tk.LEFT)

        self.export_format_var = tk.StringVar(value="xlsx")
        formats = [("Excel (.xlsx)", "xlsx"), ("CSV (.csv)", "csv"), ("JSON (.json)", "json")]

        for text, value in formats:
            ttk.Radiobutton(
                format_frame,
                text=text,
                value=value,
                variable=self.export_format_var
            ).pack(side=tk.LEFT, padx=10)

        # Content options
        content_frame = ttk.Frame(options_frame)
        content_frame.pack(fill=tk.X)

        self.export_summary_var = tk.BooleanVar(value=True)
        self.export_hosts_var = tk.BooleanVar(value=True)
        self.export_cumulative_var = tk.BooleanVar(value=True)

        ttk.Checkbutton(content_frame, text="Include Summary", variable=self.export_summary_var).pack(side=tk.LEFT)
        ttk.Checkbutton(content_frame, text="Include Host Details", variable=self.export_hosts_var).pack(side=tk.LEFT, padx=20)
        ttk.Checkbutton(content_frame, text="Include Cumulative Impact", variable=self.export_cumulative_var).pack(side=tk.LEFT)

        # Export buttons
        button_frame = ttk.Frame(tab)
        button_frame.pack(fill=tk.X, pady=20)

        ttk.Button(
            button_frame,
            text="Export Remediation Plan",
            command=self._export_plan
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            button_frame,
            text="Export Charts (PDF)",
            command=self._export_charts_pdf
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            button_frame,
            text="Export Charts (PNG)",
            command=self._export_charts_png
        ).pack(side=tk.LEFT, padx=5)

        # Preview
        preview_frame = ttk.LabelFrame(tab, text="Export Preview", padding="10")
        preview_frame.pack(fill=tk.BOTH, expand=True)

        self.export_preview_text = tk.Text(
            preview_frame,
            wrap=tk.WORD,
            font=('Consolas', 9),
            bg=self.entry_bg,
            fg=self.fg_color,
            height=15
        )
        self.export_preview_text.pack(fill=tk.BOTH, expand=True)

    def _browse_file(self):
        """Browse for version data file."""
        file_path = filedialog.askopenfilename(
            title="Select Version Extraction Data",
            filetypes=[
                ("Excel files", "*.xlsx"),
                ("CSV files", "*.csv"),
                ("All files", "*.*")
            ]
        )
        if file_path:
            self.file_path_var.set(file_path)

    def _load_and_analyze(self):
        """Load version data and run analysis."""
        file_path = self.file_path_var.get().strip()
        if not file_path:
            messagebox.showwarning("No File", "Please select a version data file first.")
            return

        if not os.path.exists(file_path):
            messagebox.showerror("File Not Found", f"File not found: {file_path}")
            return

        self.processing = True
        self.progress_label.config(text="Loading and analyzing...")
        self.progress_bar.pack(side=tk.LEFT, padx=5)
        self.progress_bar.start(10)

        def _process():
            try:
                # Load data
                if file_path.endswith('.xlsx'):
                    self.version_df = pd.read_excel(file_path)
                else:
                    self.version_df = pd.read_csv(file_path)

                # Run analysis
                self.plan = analyze_package_version_impact(
                    self.version_df,
                    self.findings_df
                )

                self.dialog.after(0, self._analysis_complete)

            except Exception as e:
                self.dialog.after(0, lambda: self._analysis_error(str(e)))

        threading.Thread(target=_process, daemon=True).start()

    def _analysis_complete(self):
        """Handle analysis completion."""
        self.processing = False
        self.progress_bar.stop()
        self.progress_bar.pack_forget()
        self.progress_label.config(text="Analysis complete!")

        # Update all tabs
        self._update_summary()
        self._update_chart()
        self._populate_list()
        self._update_export_preview()

        messagebox.showinfo(
            "Analysis Complete",
            f"Analyzed {len(self.plan.packages)} packages affecting "
            f"{self.plan.total_hosts_affected} hosts with "
            f"{self.plan.total_findings_resolved} findings."
        )

    def _analysis_error(self, error: str):
        """Handle analysis error."""
        self.processing = False
        self.progress_bar.stop()
        self.progress_bar.pack_forget()
        self.progress_label.config(text="")

        messagebox.showerror("Analysis Error", f"Failed to analyze data:\n{error}")

    def _update_summary(self):
        """Update the summary text."""
        if not self.plan:
            return

        self.summary_text.config(state=tk.NORMAL)
        self.summary_text.delete(1.0, tk.END)

        # Title
        self.summary_text.insert(tk.END, "PACKAGE VERSION REMEDIATION ANALYSIS\n", 'header')
        self.summary_text.insert(tk.END, "=" * 50 + "\n\n")

        # Key metrics
        self.summary_text.insert(tk.END, "KEY METRICS\n", 'subheader')
        self.summary_text.insert(tk.END, f"Total Packages to Remediate: ", 'metric')
        self.summary_text.insert(tk.END, f"{len(self.plan.packages):,}\n")
        self.summary_text.insert(tk.END, f"Total Findings Resolved: ", 'metric')
        self.summary_text.insert(tk.END, f"{self.plan.total_findings_resolved:,}\n")
        self.summary_text.insert(tk.END, f"Total Hosts Affected: ", 'metric')
        self.summary_text.insert(tk.END, f"{self.plan.total_hosts_affected:,}\n")
        self.summary_text.insert(tk.END, f"Total Unique CVEs: ", 'metric')
        self.summary_text.insert(tk.END, f"{self.plan.total_unique_cves:,}\n\n")

        # Calculate 80% coverage
        cumulative = 0
        packages_for_80 = len(self.plan.packages)
        for i, pkg in enumerate(self.plan.packages):
            cumulative += pkg.total_impact
            if cumulative >= self.plan.total_findings_resolved * 0.8:
                packages_for_80 = i + 1
                break

        self.summary_text.insert(tk.END, "EFFICIENCY\n", 'subheader')
        self.summary_text.insert(tk.END, f"80% Coverage with Top: ", 'metric')
        self.summary_text.insert(tk.END, f"{packages_for_80} packages\n\n")

        # Severity breakdown
        self.summary_text.insert(tk.END, "SEVERITY BREAKDOWN\n", 'subheader')
        severity_totals = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        for pkg in self.plan.packages:
            for sev, count in pkg.severity_breakdown.items():
                if sev in severity_totals:
                    severity_totals[sev] += count

        for sev in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            count = severity_totals[sev]
            tag = 'warning' if sev in ['Critical', 'High'] else None
            self.summary_text.insert(tk.END, f"  {sev}:\n", tag)
            self.summary_text.insert(tk.END, f"    {count:,}\n", tag)

        self.summary_text.insert(tk.END, "\n")

        # Top packages
        self.summary_text.insert(tk.END, "TOP 20 PRIORITY PACKAGES\n", 'subheader')
        for i, pkg in enumerate(self.plan.packages[:20]):
            self.summary_text.insert(tk.END, f"  {i+1}. {pkg.package_name}\n")
            self.summary_text.insert(tk.END, f"     Target: {pkg.target_version}\n")
            self.summary_text.insert(tk.END, f"     Impact: {pkg.total_impact} findings on {pkg.affected_hosts} hosts\n")

        self.summary_text.insert(tk.END, "\n")

        # Effort estimate
        effort = estimate_remediation_effort(self.plan)
        self.summary_text.insert(tk.END, "EFFORT ESTIMATE\n", 'subheader')
        self.summary_text.insert(tk.END, f"  Effort Level: {effort['effort_level']}\n")
        self.summary_text.insert(tk.END, f"  Critical Packages: {effort['critical_packages']}\n", 'warning')
        self.summary_text.insert(tk.END, f"  High Packages: {effort['high_packages']}\n")

        self.summary_text.insert(tk.END, "\n")

        # Recommendations (general)
        self.summary_text.insert(tk.END, "RECOMMENDATIONS\n", 'subheader')
        for rec in effort.get('recommendations', []):
            self.summary_text.insert(tk.END, f"  {rec}\n\n")

        # Consolidation Recommendations (separate section)
        self.summary_text.insert(tk.END, "CONSOLIDATION RECOMMENDATIONS\n", 'subheader')
        self._add_consolidation_recommendations()
        self.summary_text.insert(tk.END, "\n")

        # OPDIR Remediation Status
        self._add_opdir_summary()

        # Detailed Package List (all packages)
        self.summary_text.insert(tk.END, "=" * 50 + "\n")
        self.summary_text.insert(tk.END, "DETAILED PACKAGE LIST\n", 'header')
        self.summary_text.insert(tk.END, "=" * 50 + "\n\n")
        self.summary_text.insert(tk.END, f"{'#':<4} {'Package':<35} {'Target Ver':<15} {'Hosts':<7} {'Finds':<7} {'Crit':<6} {'High':<6} {'Med':<6} {'Low':<6}\n")
        self.summary_text.insert(tk.END, "-" * 98 + "\n")

        for i, pkg in enumerate(self.plan.packages):
            crit_count = pkg.severity_breakdown.get('Critical', 0)
            high_count = pkg.severity_breakdown.get('High', 0)
            med_count = pkg.severity_breakdown.get('Medium', 0)
            low_count = pkg.severity_breakdown.get('Low', 0)
            line = f"{i+1:<4} {pkg.package_name[:33]:<35} {str(pkg.target_version)[:13]:<15} {pkg.affected_hosts:<7} {pkg.total_impact:<7} {crit_count:<6} {high_count:<6} {med_count:<6} {low_count:<6}\n"
            # Highlight rows with critical findings
            if crit_count > 0:
                self.summary_text.insert(tk.END, line, 'warning')
            else:
                self.summary_text.insert(tk.END, line)

        self.summary_text.insert(tk.END, "\n")
        self.summary_text.insert(tk.END, f"Total: {len(self.plan.packages)} packages\n", 'metric')

        self.summary_text.config(state=tk.DISABLED)

    def _add_consolidation_recommendations(self):
        """Add consolidation-specific recommendations to the summary."""
        if not self.plan or not self.plan.packages:
            self.summary_text.insert(tk.END, "  No packages analyzed yet.\n")
            return

        # Find packages with multiple current versions (consolidation opportunities)
        multi_version_packages = [
            pkg for pkg in self.plan.packages
            if len(pkg.current_versions) > 1
        ]

        if multi_version_packages:
            self.summary_text.insert(tk.END,
                f"  • {len(multi_version_packages)} packages have multiple versions deployed\n")

            # Show top consolidation opportunities
            sorted_by_versions = sorted(multi_version_packages,
                                        key=lambda p: len(p.current_versions), reverse=True)

            self.summary_text.insert(tk.END, "  • Top consolidation opportunities:\n")
            for pkg in sorted_by_versions[:5]:
                versions_count = len(pkg.current_versions)
                self.summary_text.insert(tk.END,
                    f"    - {pkg.package_name}: {versions_count} versions → consolidate to {pkg.target_version}\n")
        else:
            self.summary_text.insert(tk.END, "  • No multi-version packages found for consolidation\n")

        # Calculate efficiency gains
        total_packages = len(self.plan.packages)
        if total_packages > 0:
            # Find packages that resolve multiple CVEs
            high_impact_pkgs = [p for p in self.plan.packages if len(p.cves) >= 3]
            if high_impact_pkgs:
                self.summary_text.insert(tk.END,
                    f"  • {len(high_impact_pkgs)} packages resolve 3+ CVEs each - prioritize these for efficiency\n")

            # Find packages affecting many hosts
            wide_impact_pkgs = [p for p in self.plan.packages if p.affected_hosts >= 5]
            if wide_impact_pkgs:
                self.summary_text.insert(tk.END,
                    f"  • {len(wide_impact_pkgs)} packages affect 5+ hosts - consider batch deployment\n")

    def _add_opdir_summary(self):
        """Add OPDIR remediation status to the summary."""
        if self.findings_df is None or self.findings_df.empty:
            return

        # Check if OPDIR columns exist
        if 'opdir_status' not in self.findings_df.columns:
            return

        self.summary_text.insert(tk.END, "OPDIR REMEDIATION STATUS\n", 'subheader')

        # Filter to active findings only
        df = self.findings_df.copy()
        if 'status' in df.columns:
            df = df[df['status'] == 'Active']

        # Get OPDIR status breakdown
        opdir_counts = df['opdir_status'].value_counts()

        if opdir_counts.empty or (len(opdir_counts) == 1 and opdir_counts.index[0] in ['', 'nan', None]):
            self.summary_text.insert(tk.END, "  No OPDIR data available for active findings.\n\n")
            return

        # Display OPDIR breakdown
        has_opdir = False
        for status, count in opdir_counts.items():
            if status and str(status) != 'nan' and str(status).strip():
                has_opdir = True
                tag = 'warning' if status in ['Overdue', 'Open'] else None
                self.summary_text.insert(tk.END, f"  {status}: {count:,} findings\n", tag)

        if not has_opdir:
            self.summary_text.insert(tk.END, "  No OPDIR data available for active findings.\n")
            return

        # Show overdue/open OPDIRs that need attention
        urgent_statuses = ['Overdue', 'Open']
        urgent_findings = df[df['opdir_status'].isin(urgent_statuses)]

        if not urgent_findings.empty:
            self.summary_text.insert(tk.END, "\n  Findings Requiring OPDIR Action:\n", 'warning')

            # Group by OPDIR number if available
            if 'opdir_number' in urgent_findings.columns:
                opdir_groups = urgent_findings.groupby('opdir_number').agg({
                    'plugin_id': 'count',
                    'opdir_status': 'first'
                }).reset_index()
                opdir_groups.columns = ['opdir_number', 'finding_count', 'status']

                # Show up to 10 OPDIRs needing attention
                for _, row in opdir_groups.head(10).iterrows():
                    opdir_num = row['opdir_number']
                    if opdir_num and str(opdir_num) != 'nan':
                        self.summary_text.insert(tk.END,
                            f"    - {opdir_num} ({row['status']}): {row['finding_count']} findings\n", 'warning')

                if len(opdir_groups) > 10:
                    self.summary_text.insert(tk.END,
                        f"    ... and {len(opdir_groups) - 10} more OPDIRs\n")
            else:
                # Just show count by status
                for status in urgent_statuses:
                    status_count = len(urgent_findings[urgent_findings['opdir_status'] == status])
                    if status_count > 0:
                        self.summary_text.insert(tk.END,
                            f"    - {status}: {status_count:,} findings\n", 'warning')

        self.summary_text.insert(tk.END, "\n")

    def _update_chart(self):
        """Update the chart display."""
        if not self.plan:
            return

        # Clear existing chart
        for widget in self.chart_frame.winfo_children():
            widget.destroy()

        # Get selected chart type
        chart_type = self.chart_var.get()

        try:
            if chart_type == "dashboard":
                fig = create_remediation_impact_dashboard(self.plan)
            elif chart_type == "executive":
                fig = create_executive_remediation_summary(self.plan)
            elif chart_type == "impact":
                fig = create_package_impact_bar_chart(self.plan)
            elif chart_type == "cumulative":
                fig = create_cumulative_impact_chart(self.plan)
            elif chart_type == "severity":
                fig = create_severity_breakdown_chart(self.plan)
            elif chart_type == "quickwins":
                fig = create_quick_wins_chart(self.plan)
            else:
                fig = create_package_impact_bar_chart(self.plan)

            self.current_chart = fig

            # Embed in tkinter
            canvas = FigureCanvasTkAgg(fig, master=self.chart_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

            # Add toolbar
            toolbar = NavigationToolbar2Tk(canvas, self.chart_frame)
            toolbar.update()

        except Exception as e:
            ttk.Label(
                self.chart_frame,
                text=f"Error creating chart: {str(e)}",
                font=('TkDefaultFont', 12)
            ).pack(expand=True)

    def _populate_list(self):
        """Populate the package list."""
        if not self.plan:
            return

        # Clear existing items
        for item in self.package_tree.get_children():
            self.package_tree.delete(item)

        # Add packages
        for i, pkg in enumerate(self.plan.packages):
            values = (
                i + 1,
                pkg.package_name,
                pkg.target_version,
                pkg.affected_hosts,
                pkg.total_impact,
                f"{pkg.impact_score:,.0f}",
                pkg.severity_breakdown.get('Critical', 0),
                pkg.severity_breakdown.get('High', 0),
                len(pkg.cves)
            )
            self.package_tree.insert('', tk.END, values=values)

        self.list_status.config(text=f"Showing {len(self.plan.packages)} packages")

    def _filter_list(self):
        """Filter the package list based on search criteria."""
        if not self.plan:
            return

        search_term = self.search_var.get().lower()
        try:
            min_impact = int(self.min_impact_var.get())
        except ValueError:
            min_impact = 0

        # Clear and repopulate
        for item in self.package_tree.get_children():
            self.package_tree.delete(item)

        count = 0
        for i, pkg in enumerate(self.plan.packages):
            # Apply filters
            if search_term and search_term not in pkg.package_name.lower():
                continue
            if pkg.total_impact < min_impact:
                continue

            count += 1
            values = (
                count,
                pkg.package_name,
                pkg.target_version,
                pkg.affected_hosts,
                pkg.total_impact,
                f"{pkg.impact_score:,.0f}",
                pkg.severity_breakdown.get('Critical', 0),
                pkg.severity_breakdown.get('High', 0),
                len(pkg.cves)
            )
            self.package_tree.insert('', tk.END, values=values)

        self.list_status.config(text=f"Showing {count} of {len(self.plan.packages)} packages")

    def _show_package_details(self, event):
        """Show detailed information for selected package."""
        selection = self.package_tree.selection()
        if not selection:
            return

        item = self.package_tree.item(selection[0])
        package_name = item['values'][1]

        # Find package in plan
        pkg = None
        for p in self.plan.packages:
            if p.package_name == package_name:
                pkg = p
                break

        if not pkg:
            return

        # Create details dialog
        details_dialog = tk.Toplevel(self.dialog)
        details_dialog.title(f"Package Details: {package_name}")
        details_dialog.geometry("700x500")
        details_dialog.transient(self.dialog)

        frame = ttk.Frame(details_dialog, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)

        text = tk.Text(frame, wrap=tk.WORD, font=('Consolas', 10))
        text.pack(fill=tk.BOTH, expand=True)

        # Populate details
        text.insert(tk.END, f"PACKAGE: {pkg.package_name}\n")
        text.insert(tk.END, "=" * 50 + "\n\n")

        text.insert(tk.END, f"Target Version: {pkg.target_version}\n")
        text.insert(tk.END, f"Affected Hosts: {pkg.affected_hosts}\n")
        text.insert(tk.END, f"Findings Resolved: {pkg.total_impact}\n")
        text.insert(tk.END, f"Impact Score: {pkg.impact_score:,.0f}\n\n")

        text.insert(tk.END, "CURRENT VERSIONS:\n")
        for v in pkg.current_versions[:20]:
            text.insert(tk.END, f"  - {v}\n")
        if len(pkg.current_versions) > 20:
            text.insert(tk.END, f"  ... and {len(pkg.current_versions) - 20} more\n")

        text.insert(tk.END, "\nSEVERITY BREAKDOWN:\n")
        for sev, count in pkg.severity_breakdown.items():
            text.insert(tk.END, f"  {sev}: {count}\n")

        text.insert(tk.END, "\nCVEs:\n")
        for cve in pkg.cves[:20]:
            text.insert(tk.END, f"  {cve}\n")
        if len(pkg.cves) > 20:
            text.insert(tk.END, f"  ... and {len(pkg.cves) - 20} more\n")

        text.insert(tk.END, "\nAFFECTED HOSTS:\n")
        for host in pkg.hosts_list[:30]:
            text.insert(tk.END, f"  {host}\n")
        if len(pkg.hosts_list) > 30:
            text.insert(tk.END, f"  ... and {len(pkg.hosts_list) - 30} more\n")

        text.config(state=tk.DISABLED)

        ttk.Button(
            details_dialog,
            text="Close",
            command=details_dialog.destroy
        ).pack(pady=10)

    def _validate_cves(self):
        """Validate CVEs against NVD database."""
        if not self.plan:
            messagebox.showwarning("No Data", "Please load version data first.")
            return

        self.cve_results_text.config(state=tk.NORMAL)
        self.cve_results_text.delete(1.0, tk.END)
        self.cve_results_text.insert(tk.END, "Starting CVE validation...\n\n", 'header')
        self.cve_results_text.config(state=tk.DISABLED)

        try:
            top_n = int(self.validate_top_n_var.get())
        except ValueError:
            top_n = 10

        critical_only = self.validate_critical_var.get()

        def _validate():
            validator = CVEValidator()
            results = []

            packages_to_validate = self.plan.packages[:top_n]
            if critical_only:
                packages_to_validate = [
                    p for p in packages_to_validate
                    if p.severity_breakdown.get('Critical', 0) > 0
                ]

            for i, pkg in enumerate(packages_to_validate):
                if not pkg.cves:
                    continue

                self.dialog.after(0, lambda p=pkg, idx=i: self._update_validation_progress(p.package_name, idx, len(packages_to_validate)))

                result = validator.validate_package_versions(
                    pkg.package_name,
                    pkg.target_version,
                    pkg.cves[:5],  # Limit CVEs per package
                    rate_limit_delay=0.7
                )
                results.append(result)

            report = create_cve_validation_report(results)
            self.dialog.after(0, lambda: self._display_validation_results(report))

        threading.Thread(target=_validate, daemon=True).start()

    def _validate_all_cves(self):
        """Validate ALL packages' CVEs against NVD database."""
        if not self.plan:
            messagebox.showwarning("No Data", "Please load version data first.")
            return

        total_packages = len(self.plan.packages)
        if total_packages > 50:
            if not messagebox.askyesno(
                "Large Validation",
                f"You are about to validate {total_packages} packages.\n"
                "This may take a significant amount of time due to API rate limits.\n\n"
                "Continue?"
            ):
                return

        self.cve_results_text.config(state=tk.NORMAL)
        self.cve_results_text.delete(1.0, tk.END)
        self.cve_results_text.insert(tk.END, f"Starting validation of ALL {total_packages} packages...\n\n", 'header')
        self.cve_results_text.config(state=tk.DISABLED)

        critical_only = self.validate_critical_var.get()

        def _validate():
            validator = CVEValidator()
            results = []

            packages_to_validate = self.plan.packages
            if critical_only:
                packages_to_validate = [
                    p for p in packages_to_validate
                    if p.severity_breakdown.get('Critical', 0) > 0
                ]

            for i, pkg in enumerate(packages_to_validate):
                if not pkg.cves:
                    continue

                self.dialog.after(0, lambda p=pkg, idx=i: self._update_validation_progress(p.package_name, idx, len(packages_to_validate)))

                result = validator.validate_package_versions(
                    pkg.package_name,
                    pkg.target_version,
                    pkg.cves[:5],  # Limit CVEs per package to avoid excessive API calls
                    rate_limit_delay=0.7
                )
                results.append(result)

            report = create_cve_validation_report(results)
            self.dialog.after(0, lambda: self._display_validation_results(report))

        threading.Thread(target=_validate, daemon=True).start()

    def _update_validation_progress(self, package: str, current: int, total: int):
        """Update validation progress."""
        self.cve_results_text.config(state=tk.NORMAL)
        self.cve_results_text.insert(tk.END, f"Validating {current+1}/{total}: {package}...\n")
        self.cve_results_text.see(tk.END)
        self.cve_results_text.config(state=tk.DISABLED)

    def _display_validation_results(self, report: Dict):
        """Display CVE validation results."""
        self.cve_results_text.config(state=tk.NORMAL)
        self.cve_results_text.insert(tk.END, "\n" + "=" * 50 + "\n", 'header')
        self.cve_results_text.insert(tk.END, "VALIDATION RESULTS\n", 'header')
        self.cve_results_text.insert(tk.END, "=" * 50 + "\n\n")

        summary = report['summary']
        self.cve_results_text.insert(tk.END, f"Packages Validated: {summary['total_packages']}\n")
        self.cve_results_text.insert(tk.END, f"Valid: {summary['valid_packages']}\n", 'success')
        self.cve_results_text.insert(tk.END, f"Invalid: {summary['invalid_packages']}\n", 'error' if summary['invalid_packages'] > 0 else None)
        self.cve_results_text.insert(tk.END, f"Validation Rate: {summary['validation_rate']}%\n\n")

        self.cve_results_text.insert(tk.END, f"CVEs Checked: {summary['total_cves_checked']}\n")
        self.cve_results_text.insert(tk.END, f"CVEs Resolved: {summary['cves_resolved']}\n", 'success')
        self.cve_results_text.insert(tk.END, f"CVEs Unresolved: {summary['cves_unresolved']}\n\n", 'warning' if summary['cves_unresolved'] > 0 else None)

        if report['failed_validations']:
            self.cve_results_text.insert(tk.END, "FAILED VALIDATIONS:\n", 'warning')
            for fail in report['failed_validations']:
                self.cve_results_text.insert(tk.END, f"\n  Package: {fail['package']}\n")
                self.cve_results_text.insert(tk.END, f"  Target: {fail['target_version']}\n")
                self.cve_results_text.insert(tk.END, f"  Unresolved CVEs: {', '.join(fail['unresolved_cves'][:5])}\n")

        self.cve_results_text.insert(tk.END, "\nRECOMMENDATIONS:\n", 'header')
        for rec in report.get('recommendations', []):
            self.cve_results_text.insert(tk.END, f"  {rec}\n")

        self.cve_results_text.config(state=tk.DISABLED)

    def _update_export_preview(self):
        """Update the export preview."""
        if not self.plan:
            return

        self.export_preview_text.config(state=tk.NORMAL)
        self.export_preview_text.delete(1.0, tk.END)

        df = create_remediation_summary_df(self.plan)
        if not df.empty:
            preview = df.head(10).to_string()
            self.export_preview_text.insert(tk.END, "Preview of Remediation Plan (first 10 rows):\n\n")
            self.export_preview_text.insert(tk.END, preview)
            self.export_preview_text.insert(tk.END, f"\n\n... and {len(df) - 10} more rows" if len(df) > 10 else "")

        self.export_preview_text.config(state=tk.DISABLED)

    def _export_plan(self):
        """Export the remediation plan."""
        if not self.plan:
            messagebox.showwarning("No Data", "Please load version data first.")
            return

        format_type = self.export_format_var.get()
        ext = f".{format_type}"

        file_path = filedialog.asksaveasfilename(
            title="Export Remediation Plan",
            defaultextension=ext,
            filetypes=[
                ("Excel files", "*.xlsx") if format_type == "xlsx" else
                ("CSV files", "*.csv") if format_type == "csv" else
                ("JSON files", "*.json"),
                ("All files", "*.*")
            ],
            initialfile=f"remediation_plan_{datetime.now().strftime('%Y%m%d')}{ext}"
        )

        if not file_path:
            return

        try:
            success = export_remediation_plan(self.plan, file_path, format_type)
            if success:
                messagebox.showinfo("Export Complete", f"Remediation plan exported to:\n{file_path}")
            else:
                messagebox.showerror("Export Failed", "Failed to export remediation plan.")
        except Exception as e:
            messagebox.showerror("Export Error", f"Error exporting plan:\n{str(e)}")

    def _export_charts_pdf(self):
        """Export charts to PDF."""
        if not self.plan:
            messagebox.showwarning("No Data", "Please load version data first.")
            return

        file_path = filedialog.asksaveasfilename(
            title="Export Charts to PDF",
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf")],
            initialfile=f"remediation_charts_{datetime.now().strftime('%Y%m%d')}.pdf"
        )

        if not file_path:
            return

        try:
            from matplotlib.backends.backend_pdf import PdfPages

            with PdfPages(file_path) as pdf:
                # Add multiple charts
                charts = [
                    ("Dashboard", create_remediation_impact_dashboard(self.plan)),
                    ("Executive Summary", create_executive_remediation_summary(self.plan)),
                    ("Impact Ranking", create_package_impact_bar_chart(self.plan)),
                    ("Cumulative Impact", create_cumulative_impact_chart(self.plan))
                ]

                for name, fig in charts:
                    pdf.savefig(fig, bbox_inches='tight')
                    plt.close(fig)

            messagebox.showinfo("Export Complete", f"Charts exported to:\n{file_path}")

        except Exception as e:
            messagebox.showerror("Export Error", f"Error exporting charts:\n{str(e)}")

    def _export_charts_png(self):
        """Export current chart to PNG."""
        if not self.current_chart:
            messagebox.showwarning("No Chart", "Please select a chart first.")
            return

        file_path = filedialog.asksaveasfilename(
            title="Export Chart to PNG",
            defaultextension=".png",
            filetypes=[("PNG files", "*.png")],
            initialfile=f"remediation_chart_{datetime.now().strftime('%Y%m%d')}.png"
        )

        if not file_path:
            return

        try:
            self.current_chart.savefig(file_path, dpi=150, bbox_inches='tight',
                                       facecolor='#2b2b2b', edgecolor='none')
            messagebox.showinfo("Export Complete", f"Chart exported to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Error exporting chart:\n{str(e)}")

    def _on_close(self):
        """Handle dialog close."""
        if self.on_close:
            self.on_close()
        self.dialog.destroy()


def show_package_impact_dialog(
    parent: tk.Tk,
    findings_df: Optional[pd.DataFrame] = None,
    on_close: Optional[Callable] = None
) -> PackageImpactDialog:
    """
    Show the package impact analysis dialog.

    Args:
        parent: Parent window
        findings_df: Optional findings DataFrame for severity enrichment
        on_close: Optional callback when dialog closes

    Returns:
        PackageImpactDialog instance
    """
    return PackageImpactDialog(parent, findings_df, on_close)


# Import plt at module level for export functions
import matplotlib.pyplot as plt
