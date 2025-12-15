"""
Chart Utilities Module
Helper functions for matplotlib chart formatting and interactivity.
"""

import tkinter as tk
from tkinter import ttk
from typing import Optional, List, Dict, Any, Callable
import matplotlib.pyplot as plt
from matplotlib.figure import Figure
from matplotlib.axes import Axes
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
import numpy as np


def add_data_labels(ax: Axes, bars, fmt: str = '{:.0f}', offset: tuple = (0, 3),
                    fontsize: int = 7, color: str = 'white', rotation: int = 0):
    """
    Add data labels to bar chart bars.

    Args:
        ax: Matplotlib axes
        bars: Bar container from ax.bar()
        fmt: Format string for values
        offset: (x, y) offset in points from bar top
        fontsize: Font size for labels
        color: Label text color
        rotation: Label rotation angle
    """
    for bar in bars:
        height = bar.get_height()
        if height > 0:
            ax.annotate(fmt.format(height),
                       xy=(bar.get_x() + bar.get_width() / 2, height),
                       xytext=offset,
                       textcoords="offset points",
                       ha='center', va='bottom',
                       fontsize=fontsize,
                       color=color,
                       rotation=rotation)


def add_horizontal_data_labels(ax: Axes, bars, fmt: str = '{:.0f}',
                                offset: tuple = (3, 0), fontsize: int = 7,
                                color: str = 'white'):
    """
    Add data labels to horizontal bar chart bars.

    Args:
        ax: Matplotlib axes
        bars: Bar container from ax.barh()
        fmt: Format string for values
        offset: (x, y) offset in points from bar end
        fontsize: Font size for labels
        color: Label text color
    """
    for bar in bars:
        width = bar.get_width()
        if width > 0:
            ax.annotate(fmt.format(width),
                       xy=(width, bar.get_y() + bar.get_height() / 2),
                       xytext=offset,
                       textcoords="offset points",
                       ha='left', va='center',
                       fontsize=fontsize,
                       color=color)


def add_line_data_labels(ax: Axes, x_data, y_data, fmt: str = '{:.1f}',
                          fontsize: int = 7, color: str = 'white',
                          skip_every: int = 1):
    """
    Add data labels to line chart points.

    Args:
        ax: Matplotlib axes
        x_data: X coordinates
        y_data: Y coordinates
        fmt: Format string for values
        fontsize: Font size for labels
        color: Label text color
        skip_every: Show label every N points (1 = all, 2 = every other, etc.)
    """
    for i, (x, y) in enumerate(zip(x_data, y_data)):
        if i % skip_every == 0:
            ax.annotate(fmt.format(y),
                       xy=(x, y),
                       xytext=(0, 5),
                       textcoords="offset points",
                       ha='center', va='bottom',
                       fontsize=fontsize,
                       color=color)


def add_pie_labels(ax: Axes, wedges, labels: List[str], values: List[float],
                   fontsize: int = 8, color: str = 'white'):
    """
    Add custom labels to pie chart.

    Args:
        ax: Matplotlib axes
        wedges: Pie wedges from ax.pie()
        labels: Label strings
        values: Values for percentage calculation
        fontsize: Font size for labels
        color: Label text color
    """
    total = sum(values)
    for wedge, label, value in zip(wedges, labels, values):
        pct = value / total * 100 if total > 0 else 0
        angle = (wedge.theta2 - wedge.theta1) / 2. + wedge.theta1
        x = np.cos(np.deg2rad(angle))
        y = np.sin(np.deg2rad(angle))
        # Place label inside the wedge
        ax.annotate(f'{pct:.1f}%',
                   xy=(x * 0.6, y * 0.6),
                   ha='center', va='center',
                   fontsize=fontsize,
                   color=color)


class HoverTooltip:
    """
    Add hover tooltips to matplotlib charts.

    Usage:
        tooltip = HoverTooltip(ax, data_labels)
        fig.canvas.mpl_connect('motion_notify_event', tooltip.on_hover)
    """

    def __init__(self, ax: Axes, annotations: Dict[Any, str], threshold: float = 5.0):
        """
        Initialize hover tooltip handler.

        Args:
            ax: Matplotlib axes
            annotations: Dict mapping (x, y) tuples to tooltip text
            threshold: Distance threshold for showing tooltip (in data units)
        """
        self.ax = ax
        self.annotations = annotations
        self.threshold = threshold
        self.tooltip = None

    def on_hover(self, event):
        """Handle mouse motion events."""
        if event.inaxes != self.ax:
            self._hide_tooltip()
            return

        # Find nearest point
        min_dist = float('inf')
        nearest_text = None

        for (x, y), text in self.annotations.items():
            dist = np.sqrt((event.xdata - x)**2 + (event.ydata - y)**2)
            if dist < min_dist and dist < self.threshold:
                min_dist = dist
                nearest_text = text

        if nearest_text:
            self._show_tooltip(event.xdata, event.ydata, nearest_text)
        else:
            self._hide_tooltip()

    def _show_tooltip(self, x: float, y: float, text: str):
        """Show tooltip at position."""
        if self.tooltip is None:
            self.tooltip = self.ax.annotate(
                text,
                xy=(x, y),
                xytext=(10, 10),
                textcoords='offset points',
                bbox=dict(boxstyle='round,pad=0.3', fc='yellow', alpha=0.9),
                fontsize=8,
                color='black'
            )
        else:
            self.tooltip.set_text(text)
            self.tooltip.xy = (x, y)
            self.tooltip.set_visible(True)
        self.ax.figure.canvas.draw_idle()

    def _hide_tooltip(self):
        """Hide the tooltip."""
        if self.tooltip is not None:
            self.tooltip.set_visible(False)
            self.ax.figure.canvas.draw_idle()


class ChartInteractiveTooltip:
    """
    Enhanced interactive tooltip system for matplotlib charts.

    Automatically detects chart elements (bars, lines, scatter points) and shows
    tooltips with label + value information on hover.

    Usage:
        tooltip = ChartInteractiveTooltip(fig, ax)
        # The tooltip system automatically connects to the figure canvas
    """

    def __init__(self, fig: Figure, ax: Axes, format_value: Callable = None):
        """
        Initialize interactive tooltip.

        Args:
            fig: Matplotlib figure
            ax: Matplotlib axes
            format_value: Optional function to format values (default: comma-separated)
        """
        self.fig = fig
        self.ax = ax
        self.format_value = format_value or (lambda v: f'{v:,.0f}' if isinstance(v, (int, float)) else str(v))
        self.annotation = None
        self.bar_data = []  # List of (bar, label, value) tuples
        self.line_data = []  # List of (line, labels, values) tuples
        self.scatter_data = []  # List of (collection, labels, values) tuples

        # Extract data from chart elements
        self._extract_chart_data()

        # Connect hover event
        self.cid = fig.canvas.mpl_connect('motion_notify_event', self._on_hover)

    def _extract_chart_data(self):
        """Extract data from chart elements for tooltip display."""
        # Extract bar chart data
        for container in self.ax.containers:
            try:
                for i, bar in enumerate(container):
                    if hasattr(bar, 'get_height') and hasattr(bar, 'get_width'):
                        # Get label from y-axis (horizontal) or x-axis (vertical)
                        height = bar.get_height()
                        width = bar.get_width()
                        x = bar.get_x()
                        y = bar.get_y()

                        # Determine if horizontal or vertical bar
                        if width > height:  # Horizontal bar
                            value = width
                            center_x = x + width / 2
                            center_y = y + height / 2
                            # Try to get label from y-axis
                            yticks = self.ax.get_yticks()
                            ylabels = [t.get_text() for t in self.ax.get_yticklabels()]
                            label = ylabels[i] if i < len(ylabels) else f'Bar {i}'
                        else:  # Vertical bar
                            value = height
                            center_x = x + width / 2
                            center_y = y + height / 2
                            # Try to get label from x-axis
                            xticks = self.ax.get_xticks()
                            xlabels = [t.get_text() for t in self.ax.get_xticklabels()]
                            label = xlabels[i] if i < len(xlabels) else f'Bar {i}'

                        self.bar_data.append({
                            'bar': bar,
                            'label': label,
                            'value': value,
                            'center': (center_x, center_y),
                            'bounds': (x, y, x + width, y + height)
                        })
            except Exception:
                pass

        # Extract line chart data
        for line in self.ax.get_lines():
            try:
                xdata = line.get_xdata()
                ydata = line.get_ydata()
                label = line.get_label()
                if label.startswith('_'):  # Skip internal labels
                    label = 'Series'

                for i, (x, y) in enumerate(zip(xdata, ydata)):
                    self.line_data.append({
                        'x': x,
                        'y': y,
                        'label': label,
                        'index': i
                    })
            except Exception:
                pass

        # Extract scatter plot data
        for collection in self.ax.collections:
            try:
                offsets = collection.get_offsets()
                if len(offsets) > 0:
                    for i, (x, y) in enumerate(offsets):
                        self.scatter_data.append({
                            'x': x,
                            'y': y,
                            'index': i
                        })
            except Exception:
                pass

    def _on_hover(self, event):
        """Handle mouse motion events."""
        if event.inaxes != self.ax:
            self._hide_tooltip()
            return

        # Check bars first (most common)
        for bar_info in self.bar_data:
            bounds = bar_info['bounds']
            if bounds[0] <= event.xdata <= bounds[2] and bounds[1] <= event.ydata <= bounds[3]:
                label = bar_info['label']
                value = self.format_value(bar_info['value'])
                tooltip_text = f"{label}\nValue: {value}"
                self._show_tooltip(event.xdata, event.ydata, tooltip_text)
                return

        # Check line points
        if self.line_data:
            threshold = self._calculate_threshold()
            for point in self.line_data:
                dist = np.sqrt((event.xdata - point['x'])**2 + (event.ydata - point['y'])**2)
                if dist < threshold:
                    value = self.format_value(point['y'])
                    tooltip_text = f"{point['label']}\nValue: {value}"
                    self._show_tooltip(point['x'], point['y'], tooltip_text)
                    return

        # Check scatter points
        if self.scatter_data:
            threshold = self._calculate_threshold()
            for point in self.scatter_data:
                dist = np.sqrt((event.xdata - point['x'])**2 + (event.ydata - point['y'])**2)
                if dist < threshold:
                    tooltip_text = f"Point {point['index']}\nX: {point['x']:.2f}\nY: {point['y']:.2f}"
                    self._show_tooltip(point['x'], point['y'], tooltip_text)
                    return

        self._hide_tooltip()

    def _calculate_threshold(self) -> float:
        """Calculate a reasonable threshold based on axis ranges."""
        xlim = self.ax.get_xlim()
        ylim = self.ax.get_ylim()
        x_range = xlim[1] - xlim[0]
        y_range = ylim[1] - ylim[0]
        return min(x_range, y_range) * 0.03  # 3% of smaller range

    def _show_tooltip(self, x: float, y: float, text: str):
        """Show tooltip at position."""
        if self.annotation is None:
            self.annotation = self.ax.annotate(
                text,
                xy=(x, y),
                xytext=(15, 15),
                textcoords='offset points',
                bbox=dict(boxstyle='round,pad=0.4', fc='#ffffcc', ec='#666666', alpha=0.95),
                fontsize=9,
                color='black',
                zorder=1000
            )
        else:
            self.annotation.set_text(text)
            self.annotation.xy = (x, y)
            self.annotation.set_visible(True)

        try:
            self.fig.canvas.draw_idle()
        except Exception:
            pass

    def _hide_tooltip(self):
        """Hide the tooltip."""
        if self.annotation is not None:
            self.annotation.set_visible(False)
            try:
                self.fig.canvas.draw_idle()
            except Exception:
                pass

    def disconnect(self):
        """Disconnect the hover event handler."""
        if hasattr(self, 'cid') and self.cid:
            try:
                self.fig.canvas.mpl_disconnect(self.cid)
            except Exception:
                pass


def add_interactive_tooltips(fig: Figure, ax: Axes, format_value: Callable = None) -> ChartInteractiveTooltip:
    """
    Add interactive hover tooltips to a chart.

    This is the easiest way to add tooltips to any chart. Call this after
    drawing your chart.

    Args:
        fig: Matplotlib figure
        ax: Matplotlib axes
        format_value: Optional function to format values

    Returns:
        ChartInteractiveTooltip instance (keep reference to prevent garbage collection)

    Usage:
        fig, ax = plt.subplots()
        ax.bar(['A', 'B', 'C'], [10, 20, 30])
        tooltip = add_interactive_tooltips(fig, ax)
    """
    return ChartInteractiveTooltip(fig, ax, format_value)


def format_large_number(value: float) -> str:
    """
    Format large numbers with K/M suffixes.

    Args:
        value: Number to format

    Returns:
        Formatted string (e.g., '1.2K', '3.5M')
    """
    if abs(value) >= 1_000_000:
        return f'{value/1_000_000:.1f}M'
    elif abs(value) >= 1_000:
        return f'{value/1_000:.1f}K'
    else:
        return f'{value:.0f}'


def style_chart_for_dark_theme(ax: Axes, bg_color: str = '#1e1e1e',
                                fg_color: str = '#f0f0f0'):
    """
    Apply dark theme styling to chart axes.

    Args:
        ax: Matplotlib axes
        bg_color: Background color
        fg_color: Foreground color (labels, ticks, spines)
    """
    ax.set_facecolor(bg_color)
    ax.tick_params(colors=fg_color)
    ax.xaxis.label.set_color(fg_color)
    ax.yaxis.label.set_color(fg_color)
    ax.title.set_color(fg_color)
    for spine in ax.spines.values():
        spine.set_color(fg_color)


class ChartPopoutModal:
    """
    Pop-out modal window for enlarged chart viewing with zoom and pan.

    Features:
    - Resizable window
    - Matplotlib navigation toolbar (zoom, pan, home, save)
    - Larger fonts and labels for readability
    - Dark theme matching main app
    - Filter options for Active/Resolved, Unique/Cumulative, and date filtering

    Usage:
        # In your chart update method, store the redraw function:
        self.chart_redraw_funcs['risk'] = lambda fig, ax: self._draw_risk_chart(fig, ax)

        # Bind double-click to canvas:
        canvas.get_tk_widget().bind('<Double-Button-1>',
            lambda e: ChartPopoutModal(self.window, 'Risk Analysis', self.chart_redraw_funcs['risk']))
    """

    # Dark theme colors
    BG_COLOR = '#1e1e1e'
    FG_COLOR = '#f0f0f0'
    ENTRY_BG = '#2d2d2d'

    def __init__(self, parent, title: str, redraw_func: Callable,
                 width: int = 900, height: int = 700,
                 description: str = "", app_ref=None):
        """
        Create a pop-out chart modal.

        Args:
            parent: Parent tkinter window
            title: Window title
            redraw_func: Function that takes (fig, ax) and draws the chart
            width: Initial window width
            height: Initial window height
            description: Chart description (shown in tooltip)
            app_ref: Reference to main app for accessing data
        """
        self.parent = parent
        self.title = title
        self.redraw_func = redraw_func
        self.description = description
        self.app_ref = app_ref
        self.zoom_level = 1.0

        # Create modal window
        self.modal = tk.Toplevel(parent)
        self.modal.title(f"{title} (Pop-out)")
        self.modal.geometry(f"{width}x{height}")
        self.modal.configure(bg=self.BG_COLOR)
        self.modal.transient(parent)

        # Make it resizable
        self.modal.resizable(True, True)
        self.modal.minsize(600, 400)

        self._build_ui()
        self._draw_chart()

        # Bind resize event
        self.modal.bind('<Configure>', self._on_resize)

        # Focus and bring to front
        self.modal.focus_set()
        self.modal.grab_set()

    def _build_ui(self):
        """Build the modal UI."""
        # Control bar at top
        control_frame = ttk.Frame(self.modal)
        control_frame.pack(fill=tk.X, padx=5, pady=5)

        # Title label with tooltip for description
        title_label = ttk.Label(control_frame, text=self.title,
                               font=('Arial', 12, 'bold'))
        title_label.pack(side=tk.LEFT, padx=5)
        if self.description:
            self._create_tooltip(title_label, self.description)

        # Zoom controls
        zoom_frame = ttk.Frame(control_frame)
        zoom_frame.pack(side=tk.RIGHT, padx=5)

        ttk.Label(zoom_frame, text="Zoom:").pack(side=tk.LEFT, padx=2)

        ttk.Button(zoom_frame, text="-", width=2,
                  command=self._zoom_out).pack(side=tk.LEFT, padx=1)

        self.zoom_label = ttk.Label(zoom_frame, text="100%", width=5)
        self.zoom_label.pack(side=tk.LEFT, padx=2)

        ttk.Button(zoom_frame, text="+", width=2,
                  command=self._zoom_in).pack(side=tk.LEFT, padx=1)

        ttk.Button(zoom_frame, text="Reset", width=5,
                  command=self._zoom_reset).pack(side=tk.LEFT, padx=5)

        # Show data labels toggle
        self.show_labels_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(control_frame, text="Labels",
                       variable=self.show_labels_var,
                       command=self._redraw).pack(side=tk.RIGHT, padx=10)

        # Filter options frame
        filter_frame = ttk.Frame(self.modal)
        filter_frame.pack(fill=tk.X, padx=5, pady=2)

        # Status filter (Active/Resolved/All)
        ttk.Label(filter_frame, text="Status:").pack(side=tk.LEFT, padx=2)
        self.status_var = tk.StringVar(value="All")
        status_combo = ttk.Combobox(filter_frame, textvariable=self.status_var,
                                    values=["All", "Active", "Resolved"],
                                    state="readonly", width=10)
        status_combo.pack(side=tk.LEFT, padx=2)

        # Data mode (Unique/Cumulative)
        ttk.Label(filter_frame, text="Mode:").pack(side=tk.LEFT, padx=(10, 2))
        self.mode_var = tk.StringVar(value="Filtered")
        mode_combo = ttk.Combobox(filter_frame, textvariable=self.mode_var,
                                  values=["Filtered", "All Data", "Unique"],
                                  state="readonly", width=10)
        mode_combo.pack(side=tk.LEFT, padx=2)

        # Date range filter
        ttk.Label(filter_frame, text="From:").pack(side=tk.LEFT, padx=(10, 2))
        self.date_from_var = tk.StringVar()
        date_from_entry = ttk.Entry(filter_frame, textvariable=self.date_from_var,
                                    width=12)
        date_from_entry.pack(side=tk.LEFT, padx=2)
        self._create_tooltip(date_from_entry, "Start date (YYYY-MM-DD)")

        ttk.Label(filter_frame, text="To:").pack(side=tk.LEFT, padx=(5, 2))
        self.date_to_var = tk.StringVar()
        date_to_entry = ttk.Entry(filter_frame, textvariable=self.date_to_var,
                                  width=12)
        date_to_entry.pack(side=tk.LEFT, padx=2)
        self._create_tooltip(date_to_entry, "End date (YYYY-MM-DD)")

        # Apply button
        ttk.Button(filter_frame, text="Apply",
                  command=self._apply_filters).pack(side=tk.LEFT, padx=10)

        # Chart frame
        self.chart_frame = ttk.Frame(self.modal)
        self.chart_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Create figure with larger size
        self.fig = Figure(figsize=(10, 8), dpi=100, facecolor=self.BG_COLOR)
        self.ax = self.fig.add_subplot(111)
        self.ax.set_facecolor(self.ENTRY_BG)

        # Create canvas
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.chart_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Add matplotlib navigation toolbar
        toolbar_frame = ttk.Frame(self.modal)
        toolbar_frame.pack(fill=tk.X, padx=5, pady=2)
        self.toolbar = NavigationToolbar2Tk(self.canvas, toolbar_frame)
        self.toolbar.update()

        # Button frame with Copy and Close
        btn_frame = ttk.Frame(self.modal)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)

        # Info button (left side)
        if self.description:
            info_btn = tk.Button(btn_frame, text="ⓘ Info", bg='#1a3a5c', fg='white',
                               command=self._show_chart_info, relief='flat', padx=10)
            info_btn.pack(side=tk.LEFT, padx=5)

        # Copy to clipboard button
        ttk.Button(btn_frame, text="📋 Copy to Clipboard",
                  command=self._copy_to_clipboard).pack(side=tk.LEFT, padx=5)

        # Close button
        ttk.Button(btn_frame, text="Close", command=self.modal.destroy).pack(side=tk.RIGHT)

    def _draw_chart(self):
        """Draw/redraw the chart."""
        # Disconnect any existing tooltip handler
        if hasattr(self, '_tooltip_handler') and self._tooltip_handler:
            self._tooltip_handler.disconnect()
            self._tooltip_handler = None

        self.ax.clear()
        self.ax.set_facecolor(self.ENTRY_BG)

        # Get filter settings
        filter_settings = self.get_filter_settings()

        # Call the redraw function with larger font settings and filters
        try:
            self.redraw_func(self.fig, self.ax, enlarged=True,
                           show_labels=filter_settings['show_labels'],
                           filter_settings=filter_settings)
        except TypeError:
            # Fallback if redraw_func doesn't accept filter_settings
            try:
                self.redraw_func(self.fig, self.ax, enlarged=True,
                               show_labels=filter_settings['show_labels'])
            except TypeError:
                # Fallback if redraw_func doesn't accept extra args
                self.redraw_func(self.fig, self.ax)

        # Apply dark theme styling with larger fonts
        self._style_enlarged_chart()

        # Add interactive tooltips for hover information
        try:
            self._tooltip_handler = ChartInteractiveTooltip(self.fig, self.ax)
        except Exception:
            self._tooltip_handler = None

        self.fig.tight_layout()
        self.canvas.draw()

    def _redraw(self):
        """Redraw chart (called from controls)."""
        self._draw_chart()

    def _style_enlarged_chart(self):
        """Apply enlarged styling for pop-out view."""
        # Larger tick labels
        self.ax.tick_params(axis='both', labelsize=10, colors=self.FG_COLOR)

        # Style spines
        for spine in self.ax.spines.values():
            spine.set_color(self.FG_COLOR)

        # Style title and labels
        title = self.ax.get_title()
        if title:
            self.ax.set_title(title, fontsize=14, color=self.FG_COLOR, fontweight='bold')

        xlabel = self.ax.get_xlabel()
        if xlabel:
            self.ax.set_xlabel(xlabel, fontsize=11, color=self.FG_COLOR)

        ylabel = self.ax.get_ylabel()
        if ylabel:
            self.ax.set_ylabel(ylabel, fontsize=11, color=self.FG_COLOR)

        # Style legend if present
        legend = self.ax.get_legend()
        if legend:
            legend.get_frame().set_facecolor(self.ENTRY_BG)
            legend.get_frame().set_edgecolor(self.FG_COLOR)
            for text in legend.get_texts():
                text.set_color(self.FG_COLOR)

    def _zoom_in(self):
        """Zoom in on the chart."""
        self.zoom_level = min(self.zoom_level * 1.2, 3.0)
        self._apply_zoom()

    def _zoom_out(self):
        """Zoom out on the chart."""
        self.zoom_level = max(self.zoom_level / 1.2, 0.5)
        self._apply_zoom()

    def _zoom_reset(self):
        """Reset zoom to 100%."""
        self.zoom_level = 1.0
        self._apply_zoom()

    def _apply_zoom(self):
        """Apply current zoom level."""
        self.zoom_label.config(text=f"{int(self.zoom_level * 100)}%")

        # Adjust figure DPI for zoom effect
        base_dpi = 100
        self.fig.set_dpi(base_dpi * self.zoom_level)
        self.canvas.draw()

    def _on_resize(self, event):
        """Handle window resize."""
        # Only respond to actual window resizes
        if event.widget == self.modal:
            self.fig.tight_layout()
            self.canvas.draw()

    def _create_tooltip(self, widget, text: str):
        """Create a tooltip that appears on hover."""
        def show_tooltip(event):
            tooltip = tk.Toplevel(widget)
            tooltip.wm_overrideredirect(True)
            tooltip.wm_geometry(f"+{event.x_root + 10}+{event.y_root + 10}")
            tooltip.configure(bg='#ffffe0')
            label = tk.Label(tooltip, text=text, bg='#ffffe0', fg='black',
                           relief='solid', borderwidth=1, padx=5, pady=3,
                           wraplength=300, justify='left')
            label.pack()
            widget._tooltip = tooltip

        def hide_tooltip(event):
            if hasattr(widget, '_tooltip') and widget._tooltip:
                widget._tooltip.destroy()
                widget._tooltip = None

        widget.bind('<Enter>', show_tooltip)
        widget.bind('<Leave>', hide_tooltip)

    def _apply_filters(self):
        """Apply filter settings and redraw chart."""
        self._draw_chart()

    def _copy_to_clipboard(self):
        """Copy chart image to clipboard or save to file."""
        import tempfile
        import os

        try:
            # Save to temp file first
            temp_dir = tempfile.gettempdir()
            temp_path = os.path.join(temp_dir, f'chart_export_{id(self)}.png')
            self.fig.savefig(temp_path, format='png', dpi=150, facecolor=self.BG_COLOR,
                           edgecolor='none', bbox_inches='tight')

            copied = False
            import platform
            system = platform.system()

            # Try platform-specific clipboard copy
            try:
                if system == 'Windows':
                    try:
                        from PIL import Image
                        import win32clipboard
                        from io import BytesIO

                        img = Image.open(temp_path)
                        output = BytesIO()
                        img.convert('RGB').save(output, 'BMP')
                        data = output.getvalue()[14:]  # BMP header offset
                        output.close()

                        win32clipboard.OpenClipboard()
                        win32clipboard.EmptyClipboard()
                        win32clipboard.SetClipboardData(win32clipboard.CF_DIB, data)
                        win32clipboard.CloseClipboard()
                        copied = True
                    except ImportError:
                        pass

                elif system == 'Darwin':
                    import subprocess
                    result = subprocess.run(
                        ['osascript', '-e', f'set the clipboard to (read (POSIX file "{temp_path}") as TIFF picture)'],
                        capture_output=True
                    )
                    copied = (result.returncode == 0)

                else:
                    # Linux - try xclip
                    import subprocess
                    result = subprocess.run(
                        ['xclip', '-selection', 'clipboard', '-t', 'image/png', '-i', temp_path],
                        capture_output=True
                    )
                    copied = (result.returncode == 0)

            except Exception:
                pass

            if copied:
                self._show_copy_success("Chart copied to clipboard!")
            else:
                # Fallback: offer to open or show path
                self._show_copy_dialog(temp_path)

        except Exception as e:
            self._show_copy_success(f"Export failed: {str(e)}")

    def _show_copy_dialog(self, file_path: str):
        """Show dialog with export options when clipboard copy fails."""
        dialog = tk.Toplevel(self.modal)
        dialog.title("Chart Exported")
        dialog.geometry("400x180")
        dialog.configure(bg=self.BG_COLOR)
        dialog.transient(self.modal)

        # Center on modal
        x = self.modal.winfo_x() + (self.modal.winfo_width() // 2) - 200
        y = self.modal.winfo_y() + (self.modal.winfo_height() // 2) - 90
        dialog.geometry(f"+{x}+{y}")

        ttk.Label(dialog, text="Chart saved to temporary file:").pack(pady=(15, 5))

        # File path (truncated if too long)
        path_display = file_path if len(file_path) < 50 else f"...{file_path[-47:]}"
        path_label = ttk.Label(dialog, text=path_display, font=('Consolas', 9))
        path_label.pack(pady=5)

        # Copy path to clipboard button
        def copy_path():
            self.modal.clipboard_clear()
            self.modal.clipboard_append(file_path)
            copy_btn.config(text="✓ Path Copied")

        # Open file button
        def open_file():
            import subprocess
            import platform
            try:
                if platform.system() == 'Windows':
                    os.startfile(file_path)
                elif platform.system() == 'Darwin':
                    subprocess.run(['open', file_path])
                else:
                    subprocess.run(['xdg-open', file_path])
                dialog.destroy()
            except Exception as e:
                ttk.Label(dialog, text=f"Could not open: {e}", foreground='red').pack()

        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(pady=15)

        copy_btn = ttk.Button(btn_frame, text="Copy Path", command=copy_path)
        copy_btn.pack(side=tk.LEFT, padx=10)

        ttk.Button(btn_frame, text="Open Image", command=open_file).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="Close", command=dialog.destroy).pack(side=tk.LEFT, padx=10)

    def _show_copy_success(self, message: str):
        """Show a brief success message."""
        popup = tk.Toplevel(self.modal)
        popup.wm_overrideredirect(True)
        popup.configure(bg='#28a745')

        # Center on modal
        x = self.modal.winfo_x() + self.modal.winfo_width() // 2 - 100
        y = self.modal.winfo_y() + self.modal.winfo_height() // 2 - 25
        popup.geometry(f"+{x}+{y}")

        label = tk.Label(popup, text=message, bg='#28a745', fg='white',
                        padx=20, pady=10, font=('Arial', 10))
        label.pack()

        # Auto-close after 2 seconds
        popup.after(2000, popup.destroy)

    def _show_chart_info(self):
        """Show detailed chart information dialog."""
        info_dialog = tk.Toplevel(self.modal)
        info_dialog.title(f"Chart Info: {self.title}")
        info_dialog.geometry("500x400")
        info_dialog.configure(bg=self.BG_COLOR)
        info_dialog.transient(self.modal)

        # Title
        title_frame = tk.Frame(info_dialog, bg='#1a3a5c')
        title_frame.pack(fill=tk.X, padx=10, pady=10)
        tk.Label(title_frame, text=self.title, font=('Arial', 14, 'bold'),
                bg='#1a3a5c', fg='white').pack(padx=10, pady=5)

        # Scrollable content
        content_frame = ttk.Frame(info_dialog)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        text = tk.Text(content_frame, wrap=tk.WORD, bg=self.ENTRY_BG, fg=self.FG_COLOR,
                      font=('Arial', 10), padx=10, pady=10)
        scrollbar = ttk.Scrollbar(content_frame, command=text.yview)
        text.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        text.pack(fill=tk.BOTH, expand=True)

        # Format description content
        if isinstance(self.description, dict):
            # Structured description from chart_descriptions
            sections = [
                ('Description', self.description.get('description', '')),
                ('Cyber Security Context', self.description.get('cyber_context', '')),
                ('Data Inputs', self.description.get('inputs', '')),
                ('How to Interpret', self.description.get('interpretation', '')),
                ('Available Filters', ', '.join(self.description.get('filters', []))),
            ]
            for title, content in sections:
                if content:
                    text.insert(tk.END, f"{title}\n", 'heading')
                    text.insert(tk.END, f"{content}\n\n")
        else:
            # Plain string description
            text.insert(tk.END, self.description)

        # Add current filter settings
        text.insert(tk.END, "\nCurrent Filters Applied\n", 'heading')
        filters = self.get_filter_settings()
        for key, value in filters.items():
            if value and value != 'All':
                text.insert(tk.END, f"  • {key}: {value}\n")

        # Style headings
        text.tag_configure('heading', font=('Arial', 11, 'bold'), foreground='#17a2b8')
        text.configure(state=tk.DISABLED)

        # Close button
        ttk.Button(info_dialog, text="Close", command=info_dialog.destroy).pack(pady=10)

    def get_filter_settings(self) -> Dict[str, Any]:
        """Get current filter settings for use in redraw function."""
        return {
            'status': self.status_var.get(),
            'mode': self.mode_var.get(),
            'date_from': self.date_from_var.get(),
            'date_to': self.date_to_var.get(),
            'show_labels': self.show_labels_var.get()
        }


def create_popout_redraw_func(original_update_func, ax_index: int = 0):
    """
    Create a redraw function for pop-out from an existing chart update method.

    This wraps an existing multi-axis chart update to work with single-axis pop-out.

    Args:
        original_update_func: The original _update_*_charts method
        ax_index: Which subplot to extract (0-3 for 2x2 grid)

    Returns:
        Function suitable for ChartPopoutModal
    """
    def redraw_func(fig, ax, enlarged=False, show_labels=True):
        # This is a template - actual implementation depends on chart type
        pass
    return redraw_func


def bind_chart_popout(canvas, parent_window, title: str, redraw_func: Callable):
    """
    Bind double-click to pop out a chart.

    Args:
        canvas: FigureCanvasTkAgg canvas
        parent_window: Parent tkinter window
        title: Title for pop-out window
        redraw_func: Function(fig, ax, enlarged=False, show_labels=True) to draw chart
    """
    def on_double_click(event):
        ChartPopoutModal(parent_window, title, redraw_func)

    canvas.get_tk_widget().bind('<Double-Button-1>', on_double_click)
