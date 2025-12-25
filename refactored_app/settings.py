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
class ExecutiveRiskSettings:
    """Executive risk quantification settings for C-suite reporting."""

    # === BASIC FINANCIAL PARAMETERS ===
    # These are required for financial impact estimates
    hourly_downtime_cost: float = 10000.0  # Cost per hour of system downtime
    cost_per_record: float = 165.0  # Cost per compromised record (IBM 2024: $165 avg)
    estimated_records_at_risk: int = 10000  # Estimated sensitive records in environment

    # Industry vertical affects breach cost multipliers
    # Options: healthcare, financial, technology, retail, government, manufacturing, other
    industry_vertical: str = "technology"

    # Industry-specific breach cost multipliers (IBM Cost of Data Breach 2024)
    # These are automatically applied based on industry_vertical
    INDUSTRY_MULTIPLIERS: Dict[str, float] = field(default_factory=lambda: {
        'healthcare': 1.95,      # $9.77M avg - highest
        'financial': 1.18,       # $5.90M avg
        'technology': 1.00,      # $5.00M avg (baseline)
        'energy': 0.98,          # $4.90M avg
        'industrial': 0.94,      # $4.70M avg
        'retail': 0.74,          # $3.70M avg
        'government': 0.70,      # $3.50M avg
        'manufacturing': 0.66,   # $3.30M avg
        'other': 0.80            # Conservative default
    })

    # === COMPLIANCE & REGULATORY ===
    # Regulatory frameworks that apply (affects penalty calculations)
    compliance_frameworks: List[str] = field(default_factory=lambda: [])
    # Options: HIPAA, PCI-DSS, SOX, GDPR, CCPA, FedRAMP, FISMA, CMMC

    # Maximum regulatory penalty exposure (organization-specific)
    max_regulatory_penalty: float = 0.0  # 0 = not configured

    # === ASSET CRITICALITY (Optional - enables enhanced risk scoring) ===
    # Map environment types to criticality multipliers
    environment_criticality: Dict[str, float] = field(default_factory=lambda: {
        'Production': 1.0,       # Full weight
        'PSS': 0.5,              # Pre-production - half weight
        'Shared': 0.75,          # Shared infrastructure - 75%
        'Unknown': 0.25          # Unknown environments - minimal weight
    })

    # Asset value tiers (map hostnames/patterns to value tiers)
    # Tier 1 = Critical (databases, auth servers), Tier 2 = Important, Tier 3 = Standard
    asset_tier_values: Dict[str, float] = field(default_factory=lambda: {
        'tier1': 100000.0,  # Critical assets
        'tier2': 25000.0,   # Important assets
        'tier3': 5000.0     # Standard assets
    })

    # Hostname patterns for asset tiers (regex)
    asset_tier_patterns: Dict[str, List[str]] = field(default_factory=lambda: {
        'tier1': [r'.*db.*', r'.*sql.*', r'.*auth.*', r'.*ldap.*', r'.*ad-.*'],
        'tier2': [r'.*app.*', r'.*web.*', r'.*api.*'],
        'tier3': []  # Default tier for unmatched
    })

    # === FAIR MODEL PARAMETERS (Optional - enables full FAIR analysis) ===
    # Loss Event Frequency (LEF) components
    threat_event_frequency: float = 0.0  # Annual threat events (0 = not configured)
    vulnerability_percentage: float = 0.0  # % of threats that succeed (0-100, 0 = not configured)

    # Loss Magnitude (LM) components
    primary_loss_min: float = 0.0  # Minimum direct loss
    primary_loss_max: float = 0.0  # Maximum direct loss
    primary_loss_likely: float = 0.0  # Most likely direct loss

    secondary_loss_min: float = 0.0  # Minimum indirect loss (reputation, legal)
    secondary_loss_max: float = 0.0  # Maximum indirect loss
    secondary_loss_likely: float = 0.0  # Most likely indirect loss

    # Control effectiveness (0-100, higher = more effective)
    control_effectiveness: float = 0.0  # 0 = not configured

    # === DISPLAY PREFERENCES ===
    show_fair_model: bool = True  # Show FAIR analysis when data available
    risk_tolerance_threshold: float = 100000.0  # Highlight risks above this value
    currency_symbol: str = "$"

    def is_fair_configured(self) -> bool:
        """Check if FAIR model has sufficient data for analysis."""
        return (
            self.threat_event_frequency > 0 and
            self.vulnerability_percentage > 0 and
            self.primary_loss_likely > 0
        )

    def is_basic_configured(self) -> bool:
        """Check if basic financial parameters are configured."""
        return self.hourly_downtime_cost > 0 or self.estimated_records_at_risk > 0

    def get_industry_multiplier(self) -> float:
        """Get breach cost multiplier for configured industry."""
        return self.INDUSTRY_MULTIPLIERS.get(self.industry_vertical, 0.80)

    def get_asset_tier(self, hostname: str) -> str:
        """Determine asset tier based on hostname patterns."""
        import re
        hostname_lower = hostname.lower()
        for tier, patterns in self.asset_tier_patterns.items():
            for pattern in patterns:
                if re.search(pattern, hostname_lower):
                    return tier
        return 'tier3'  # Default

    def get_asset_value(self, hostname: str) -> float:
        """Get estimated asset value based on tier."""
        tier = self.get_asset_tier(hostname)
        return self.asset_tier_values.get(tier, self.asset_tier_values['tier3'])


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
    color_medium: str = '#B8860B'  # Dark goldenrod (changed from #ffc107 yellow)
    color_low: str = '#28a745'  # Changed to green per user request
    color_info: str = '#17a2b8'  # Changed to blue per user request

    # Default filter settings
    default_include_info: bool = False  # Info hidden by default
    default_severity: str = 'All'
    default_status: str = 'All'
    default_severity_critical: bool = True
    default_severity_high: bool = True
    default_severity_medium: bool = True
    default_severity_low: bool = True
    default_severity_info: bool = False
    default_cvss_min: float = 0.0
    default_cvss_max: float = 10.0
    default_env_type: str = 'All Combined'
    default_opdir_status: str = 'All'
    auto_apply_filters: bool = True

    # Chart settings
    show_data_labels: bool = False
    chart_animation: bool = True

    # Recent files (persisted)
    recent_plugins_db: str = ''
    recent_opdir_file: str = ''
    recent_iavm_file: str = ''
    recent_sqlite_db: str = ''

    # Window settings
    window_width: int = 1400
    window_height: int = 900

    # Lifecycle pagination
    default_page_size: int = 100

    # Shared assets configuration
    shared_asset_mappings: Dict[str, str] = field(default_factory=dict)
    shared_asset_patterns: List[str] = field(default_factory=list)

    # Environment configuration
    environment_types: List[str] = field(default_factory=lambda: ['Production', 'PSS', 'Shared', 'Unknown'])
    environment_mappings: Dict[str, str] = field(default_factory=dict)  # hostname -> environment
    environment_patterns: Dict[str, str] = field(default_factory=dict)  # regex pattern -> environment
    excluded_environments: List[str] = field(default_factory=list)  # environments to exclude from all calculations

    # Hostname auto-detection settings
    hostname_length: int = 9  # Expected hostname length for auto-detection

    # Default filter date range (days back from today)
    default_date_range_days: int = 180

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

    def is_environment_excluded(self, env_name: str) -> bool:
        """Check if an environment is excluded from calculations."""
        return env_name in self.excluded_environments

    def get_active_environments(self) -> List[str]:
        """Get list of environments that are NOT excluded."""
        return [e for e in self.environment_types if e not in self.excluded_environments]


class SettingsManager:
    """Manages user settings persistence."""

    DEFAULT_PATH = os.path.join(os.path.expanduser('~'), '.nessus_tracker', 'settings.json')
    AI_SETTINGS_PATH = os.path.join(os.path.expanduser('~'), '.nessus_tracker', 'ai_settings.json')
    THREAT_INTEL_PATH = os.path.join(os.path.expanduser('~'), '.nessus_tracker', 'threat_intel.json')
    EXEC_RISK_PATH = os.path.join(os.path.expanduser('~'), '.nessus_tracker', 'executive_risk.json')

    def __init__(self, settings_path: str = None):
        """Initialize settings manager."""
        self.settings_path = settings_path or self.DEFAULT_PATH
        self.settings = UserSettings()
        self.ai_settings = AISettings()
        self.threat_intel_settings = ThreatIntelSettings()
        self.executive_risk_settings = ExecutiveRiskSettings()

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

        # Load executive risk settings
        try:
            if os.path.exists(self.EXEC_RISK_PATH):
                with open(self.EXEC_RISK_PATH, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self.executive_risk_settings = self._exec_risk_from_dict(data)
        except Exception as e:
            print(f"Error loading executive risk settings: {e}")
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

    def _exec_risk_from_dict(self, data: Dict[str, Any]) -> ExecutiveRiskSettings:
        """Create ExecutiveRiskSettings from dictionary."""
        known_fields = {f.name for f in ExecutiveRiskSettings.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in known_fields}
        return ExecutiveRiskSettings(**filtered)

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

        # Save executive risk settings
        try:
            with open(self.EXEC_RISK_PATH, 'w', encoding='utf-8') as f:
                json.dump(asdict(self.executive_risk_settings), f, indent=2)
        except Exception as e:
            print(f"Error saving executive risk settings: {e}")
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

    def save_executive_risk_settings(self) -> bool:
        """Save only executive risk settings."""
        try:
            with open(self.EXEC_RISK_PATH, 'w', encoding='utf-8') as f:
                json.dump(asdict(self.executive_risk_settings), f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving executive risk settings: {e}")
            return False

    def reset_to_defaults(self):
        """Reset all settings to defaults."""
        self.settings = UserSettings()
        self.ai_settings = AISettings()
        self.threat_intel_settings = ThreatIntelSettings()
        self.executive_risk_settings = ExecutiveRiskSettings()
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
        elif file_type == 'iavm':
            self.settings.recent_iavm_file = path
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
