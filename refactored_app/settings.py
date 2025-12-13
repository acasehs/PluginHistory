"""
User Settings Management
Handles persistent user preferences and configuration.
"""

import json
import os
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any
from datetime import datetime


@dataclass
class UserSettings:
    """User-configurable settings with defaults."""

    # SLA Targets (days to remediate by severity)
    sla_critical: int = 15
    sla_high: int = 30
    sla_medium: int = 60
    sla_low: int = 90
    sla_info: Optional[int] = None  # None = no SLA

    # SLA Warning threshold (percentage remaining)
    sla_warning_threshold: float = 0.25

    # Severity colors (hex)
    color_critical: str = '#dc3545'
    color_high: str = '#fd7e14'
    color_medium: str = '#ffc107'
    color_low: str = '#28a745'  # Changed to green per user request
    color_info: str = '#17a2b8'  # Changed to blue per user request

    # Default filter settings
    default_include_info: bool = False  # Info hidden by default
    default_severity: str = 'All'
    default_status: str = 'All'

    # Chart settings
    show_data_labels: bool = False
    chart_animation: bool = True

    # Recent files (persisted)
    recent_plugins_db: str = ''
    recent_opdir_file: str = ''
    recent_sqlite_db: str = ''

    # Window settings
    window_width: int = 1400
    window_height: int = 900

    # Lifecycle pagination
    default_page_size: int = 100

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'UserSettings':
        """Create from dictionary."""
        # Filter to only known fields
        known_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in known_fields}
        return cls(**filtered)

    def get_sla_targets(self) -> Dict[str, Optional[int]]:
        """Get SLA targets as dictionary."""
        return {
            'Critical': self.sla_critical,
            'High': self.sla_high,
            'Medium': self.sla_medium,
            'Low': self.sla_low,
            'Info': self.sla_info
        }

    def get_severity_colors(self) -> Dict[str, str]:
        """Get severity colors as dictionary."""
        return {
            'Critical': self.color_critical,
            'High': self.color_high,
            'Medium': self.color_medium,
            'Low': self.color_low,
            'Info': self.color_info
        }


class SettingsManager:
    """Manages user settings persistence."""

    DEFAULT_PATH = os.path.join(os.path.expanduser('~'), '.nessus_tracker', 'settings.json')

    def __init__(self, settings_path: str = None):
        """Initialize settings manager."""
        self.settings_path = settings_path or self.DEFAULT_PATH
        self.settings = UserSettings()

        # Ensure directory exists
        os.makedirs(os.path.dirname(self.settings_path), exist_ok=True)

        # Load existing settings
        self.load()

    def load(self) -> bool:
        """Load settings from file."""
        try:
            if os.path.exists(self.settings_path):
                with open(self.settings_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self.settings = UserSettings.from_dict(data)
                return True
        except Exception as e:
            print(f"Error loading settings: {e}")
        return False

    def save(self) -> bool:
        """Save settings to file."""
        try:
            with open(self.settings_path, 'w', encoding='utf-8') as f:
                json.dump(self.settings.to_dict(), f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving settings: {e}")
            return False

    def reset_to_defaults(self):
        """Reset all settings to defaults."""
        self.settings = UserSettings()
        self.save()

    def update_recent_file(self, file_type: str, path: str):
        """Update a recent file path."""
        if file_type == 'plugins_db':
            self.settings.recent_plugins_db = path
        elif file_type == 'opdir':
            self.settings.recent_opdir_file = path
        elif file_type == 'sqlite':
            self.settings.recent_sqlite_db = path
        self.save()
