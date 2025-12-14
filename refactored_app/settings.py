"""
User Settings Management
Handles persistent user preferences and configuration.
"""

import json
import os
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any
from datetime import datetime
from enum import Enum


class AnalysisMode(Enum):
    """AI analysis mode selection."""
    QUICK = "quick"
    COMPREHENSIVE = "comprehensive"


@dataclass
class AISettings:
    """AI/OpenWebUI configuration settings."""

    # Connection settings
    enabled: bool = False  # Must opt-in
    base_url: str = ""
    api_key: str = ""
    model: str = ""

    # Generation settings
    temperature: float = 0.15  # Deterministic default (0.10-0.20 range)
    max_tokens: int = 8000
    timeout: int = 300  # 5 minutes

    # Analysis settings
    analysis_mode: str = "quick"  # "quick" or "comprehensive"

    # RAG settings
    use_threat_intel_rag: bool = True
    rag_collection_name: str = "vuln_intelligence"

    def get_temperature(self) -> float:
        """Get temperature rounded to nearest 0.01."""
        return round(self.temperature, 2)

    def set_temperature(self, value: float):
        """Set temperature, rounded to nearest 0.01."""
        self.temperature = round(max(0.0, min(1.0, value)), 2)


@dataclass
class ThreatIntelSettings:
    """Threat intelligence feed configuration."""

    # Free feeds (enabled by default)
    cisa_kev_enabled: bool = True
    epss_enabled: bool = True
    nvd_enabled: bool = True

    # NVD API key (optional, but recommended for rate limits)
    nvd_api_key: str = ""

    # DISA IAVM feed (DoD)
    iavm_enabled: bool = False
    iavm_feed_url: str = ""
    iavm_api_key: str = ""

    # Local sources
    include_plugins_db: bool = True
    plugins_db_path: str = ""

    # Sync settings
    auto_sync_on_launch: bool = False
    last_sync_timestamp: str = ""
    last_sync_stats: str = ""  # JSON string of sync stats

    # Incremental vs full sync
    sync_mode: str = "incremental"  # "incremental" (last 30 days) or "full"


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

    # Shared assets configuration
    shared_asset_mappings: Dict[str, str] = field(default_factory=dict)
    shared_asset_patterns: List[str] = field(default_factory=list)

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
    AI_SETTINGS_PATH = os.path.join(os.path.expanduser('~'), '.nessus_tracker', 'ai_settings.json')
    THREAT_INTEL_PATH = os.path.join(os.path.expanduser('~'), '.nessus_tracker', 'threat_intel.json')

    def __init__(self, settings_path: str = None):
        """Initialize settings manager."""
        self.settings_path = settings_path or self.DEFAULT_PATH
        self.settings = UserSettings()
        self.ai_settings = AISettings()
        self.threat_intel_settings = ThreatIntelSettings()

        # Ensure directory exists
        os.makedirs(os.path.dirname(self.settings_path), exist_ok=True)

        # Load existing settings
        self.load()

    def load(self) -> bool:
        """Load all settings from files."""
        success = True

        # Load main settings
        try:
            if os.path.exists(self.settings_path):
                with open(self.settings_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self.settings = UserSettings.from_dict(data)
        except Exception as e:
            print(f"Error loading settings: {e}")
            success = False

        # Load AI settings
        try:
            if os.path.exists(self.AI_SETTINGS_PATH):
                with open(self.AI_SETTINGS_PATH, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self.ai_settings = self._ai_settings_from_dict(data)
        except Exception as e:
            print(f"Error loading AI settings: {e}")
            success = False

        # Load threat intel settings
        try:
            if os.path.exists(self.THREAT_INTEL_PATH):
                with open(self.THREAT_INTEL_PATH, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self.threat_intel_settings = self._threat_intel_from_dict(data)
        except Exception as e:
            print(f"Error loading threat intel settings: {e}")
            success = False

        return success

    def _ai_settings_from_dict(self, data: Dict[str, Any]) -> AISettings:
        """Create AISettings from dictionary."""
        known_fields = {f.name for f in AISettings.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in known_fields}
        return AISettings(**filtered)

    def _threat_intel_from_dict(self, data: Dict[str, Any]) -> ThreatIntelSettings:
        """Create ThreatIntelSettings from dictionary."""
        known_fields = {f.name for f in ThreatIntelSettings.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in known_fields}
        return ThreatIntelSettings(**filtered)

    def save(self) -> bool:
        """Save all settings to files."""
        success = True

        # Save main settings
        try:
            with open(self.settings_path, 'w', encoding='utf-8') as f:
                json.dump(self.settings.to_dict(), f, indent=2)
        except Exception as e:
            print(f"Error saving settings: {e}")
            success = False

        # Save AI settings
        try:
            with open(self.AI_SETTINGS_PATH, 'w', encoding='utf-8') as f:
                json.dump(asdict(self.ai_settings), f, indent=2)
        except Exception as e:
            print(f"Error saving AI settings: {e}")
            success = False

        # Save threat intel settings
        try:
            with open(self.THREAT_INTEL_PATH, 'w', encoding='utf-8') as f:
                json.dump(asdict(self.threat_intel_settings), f, indent=2)
        except Exception as e:
            print(f"Error saving threat intel settings: {e}")
            success = False

        return success

    def save_ai_settings(self) -> bool:
        """Save only AI settings."""
        try:
            with open(self.AI_SETTINGS_PATH, 'w', encoding='utf-8') as f:
                json.dump(asdict(self.ai_settings), f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving AI settings: {e}")
            return False

    def save_threat_intel_settings(self) -> bool:
        """Save only threat intel settings."""
        try:
            with open(self.THREAT_INTEL_PATH, 'w', encoding='utf-8') as f:
                json.dump(asdict(self.threat_intel_settings), f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving threat intel settings: {e}")
            return False

    def reset_to_defaults(self):
        """Reset all settings to defaults."""
        self.settings = UserSettings()
        self.ai_settings = AISettings()
        self.threat_intel_settings = ThreatIntelSettings()
        self.save()

    def reset_ai_settings(self):
        """Reset only AI settings to defaults."""
        self.ai_settings = AISettings()
        self.save_ai_settings()

    def reset_threat_intel_settings(self):
        """Reset only threat intel settings to defaults."""
        self.threat_intel_settings = ThreatIntelSettings()
        self.save_threat_intel_settings()

    def update_recent_file(self, file_type: str, path: str):
        """Update a recent file path."""
        if file_type == 'plugins_db':
            self.settings.recent_plugins_db = path
        elif file_type == 'opdir':
            self.settings.recent_opdir_file = path
        elif file_type == 'sqlite':
            self.settings.recent_sqlite_db = path
        self.save()

    def update_threat_intel_sync(self, stats: Dict[str, Any]):
        """Update threat intel sync timestamp and stats."""
        self.threat_intel_settings.last_sync_timestamp = datetime.now().isoformat()
        self.threat_intel_settings.last_sync_stats = json.dumps(stats)
        self.save_threat_intel_settings()

    def get_openwebui_config(self) -> Dict[str, Any]:
        """Get OpenWebUI configuration as dictionary for client initialization."""
        return {
            'base_url': self.ai_settings.base_url,
            'api_key': self.ai_settings.api_key,
            'model': self.ai_settings.model,
            'temperature': self.ai_settings.get_temperature(),
            'max_tokens': self.ai_settings.max_tokens,
            'timeout': self.ai_settings.timeout
        }

    def is_ai_configured(self) -> bool:
        """Check if AI is properly configured."""
        return bool(
            self.ai_settings.enabled and
            self.ai_settings.base_url and
            self.ai_settings.api_key
        )
