"""
Chart Utilities Module
Helper functions for matplotlib chart formatting and interactivity.
"""

from typing import Optional, List, Dict, Any, Callable
import matplotlib.pyplot as plt
from matplotlib.figure import Figure
from matplotlib.axes import Axes
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
