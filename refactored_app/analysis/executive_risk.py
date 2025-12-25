"""
Executive Risk Quantification Engine

Provides financial impact estimates and risk quantification for C-suite reporting.
Implements both basic risk scoring and FAIR (Factor Analysis of Information Risk) model
when sufficient data is available.

Key Metrics:
- Risk Exposure Score (0-100)
- Annualized Loss Expectancy (ALE)
- Financial Impact Estimates
- Remediation ROI Analysis
"""

import math
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
import pandas as pd


@dataclass
class RiskFinding:
    """Represents a finding with risk-relevant attributes."""
    hostname: str
    plugin_id: str
    plugin_name: str
    severity: str
    cvss_score: float = 0.0
    epss_score: float = 0.0
    is_kev: bool = False  # CISA Known Exploited Vulnerability
    exploit_available: bool = False
    days_open: int = 0
    environment: str = "Unknown"
    asset_value: float = 0.0
    sla_status: str = "On Track"


@dataclass
class RiskMetrics:
    """Comprehensive risk metrics for executive reporting."""

    # Overall Risk Posture
    risk_score: float = 0.0  # 0-100 scale
    risk_rating: str = "Unknown"  # Critical/High/Medium/Low
    risk_trend: str = "stable"  # improving/stable/declining
    risk_trend_pct: float = 0.0

    # Financial Impact Estimates
    estimated_breach_cost: float = 0.0
    estimated_downtime_cost: float = 0.0
    total_financial_exposure: float = 0.0
    regulatory_penalty_exposure: float = 0.0

    # FAIR Model Results (when configured)
    fair_available: bool = False
    annualized_loss_expectancy: float = 0.0
    loss_exceedance_curve: Dict[str, float] = field(default_factory=dict)

    # Vulnerability Summary
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    exploitable_findings: int = 0
    kev_findings: int = 0
    sla_breached_findings: int = 0

    # Environment Breakdown
    production_findings: int = 0
    production_risk_score: float = 0.0

    # Remediation Metrics
    mttr_critical: float = 0.0  # Mean Time to Remediate - Critical
    mttr_high: float = 0.0
    remediation_velocity: float = 0.0  # % change in active findings

    # Top Remediation Actions
    top_remediations: List[Dict[str, Any]] = field(default_factory=list)

    # Calculated timestamps
    calculation_date: str = ""
    data_as_of: str = ""


class ExecutiveRiskEngine:
    """
    Calculates executive-level risk metrics and financial impact estimates.

    Supports two modes:
    1. Basic Mode: Uses severity, CVSS, EPSS, and asset criticality for estimates
    2. FAIR Mode: Full probabilistic risk analysis when configured with threat data
    """

    # Severity to base risk score mapping
    SEVERITY_RISK_WEIGHTS = {
        'Critical': 40,
        'High': 25,
        'Medium': 10,
        'Low': 3,
        'Info': 0
    }

    # Risk multipliers for various factors
    KEV_MULTIPLIER = 3.0  # Actively exploited vulns are 3x more risky
    EXPLOIT_AVAILABLE_MULTIPLIER = 2.0
    HIGH_EPSS_MULTIPLIER = 2.5  # EPSS > 0.5
    PRODUCTION_MULTIPLIER = 1.5
    SLA_BREACH_MULTIPLIER = 1.25

    # Age-based risk increase (risk increases with exposure time)
    AGE_RISK_FACTORS = {
        30: 1.0,   # 0-30 days: baseline
        60: 1.2,   # 31-60 days: 20% increase
        90: 1.5,   # 61-90 days: 50% increase
        180: 2.0,  # 91-180 days: 100% increase
        365: 3.0,  # 181-365 days: 200% increase
        float('inf'): 4.0  # 365+ days: 300% increase
    }

    def __init__(self, settings: Any = None):
        """Initialize the risk engine with optional settings."""
        self.settings = settings
        self._cache = {}

    def calculate_risk_metrics(
        self,
        findings_df: pd.DataFrame,
        historical_df: Optional[pd.DataFrame] = None,
        threat_intel_data: Optional[Dict[str, Any]] = None
    ) -> RiskMetrics:
        """
        Calculate comprehensive risk metrics from vulnerability data.

        Args:
            findings_df: DataFrame with current findings (lifecycle data preferred)
            historical_df: Optional historical data for trend analysis
            threat_intel_data: Optional threat intelligence enrichment

        Returns:
            RiskMetrics object with all calculated metrics
        """
        metrics = RiskMetrics()
        metrics.calculation_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        if findings_df.empty:
            return metrics

        # Get latest scan date as "data as of"
        if 'last_seen' in findings_df.columns:
            try:
                metrics.data_as_of = pd.to_datetime(findings_df['last_seen']).max().strftime('%Y-%m-%d')
            except:
                metrics.data_as_of = datetime.now().strftime('%Y-%m-%d')

        # Filter to active findings only
        if 'status' in findings_df.columns:
            active_df = findings_df[findings_df['status'] == 'Active'].copy()
        else:
            active_df = findings_df.copy()

        if active_df.empty:
            metrics.risk_rating = "Low"
            return metrics

        # Basic counts
        metrics.total_findings = len(active_df)

        # Severity counts
        if 'severity_text' in active_df.columns:
            sev_counts = active_df['severity_text'].value_counts()
            metrics.critical_findings = sev_counts.get('Critical', 0)
            metrics.high_findings = sev_counts.get('High', 0)

        # Exploitability counts
        if 'exploit_available' in active_df.columns:
            metrics.exploitable_findings = len(active_df[
                active_df['exploit_available'].str.lower().isin(['yes', 'true', '1'])
            ])

        # KEV counts (from threat intel enrichment)
        if 'is_kev' in active_df.columns:
            metrics.kev_findings = len(active_df[active_df['is_kev'] == True])
        elif threat_intel_data and 'kev_cves' in threat_intel_data:
            kev_set = set(threat_intel_data['kev_cves'])
            if 'cves' in active_df.columns:
                metrics.kev_findings = len(active_df[
                    active_df['cves'].apply(lambda x: bool(set(str(x).split(',')) & kev_set) if pd.notna(x) else False)
                ])

        # SLA breach counts
        if 'sla_status' in active_df.columns:
            metrics.sla_breached_findings = len(active_df[
                active_df['sla_status'] == 'Overdue'
            ])

        # Environment breakdown
        if 'environment_type' in active_df.columns:
            prod_df = active_df[active_df['environment_type'] == 'Production']
            metrics.production_findings = len(prod_df)

        # Calculate risk scores
        risk_scores = self._calculate_finding_risk_scores(active_df, threat_intel_data)

        # Aggregate to overall risk score (0-100)
        if risk_scores:
            total_risk = sum(risk_scores.values())
            # Normalize to 0-100 scale using logarithmic scaling
            # This prevents extreme scores while still differentiating severity
            metrics.risk_score = min(100, self._normalize_risk_score(total_risk, len(active_df)))

        # Risk rating
        metrics.risk_rating = self._get_risk_rating(metrics.risk_score)

        # Calculate financial exposure
        self._calculate_financial_exposure(metrics, active_df, risk_scores)

        # Calculate remediation metrics
        self._calculate_remediation_metrics(metrics, active_df, findings_df)

        # Calculate trend if historical data available
        if historical_df is not None and not historical_df.empty:
            self._calculate_risk_trend(metrics, historical_df)

        # FAIR model calculation if configured
        if self.settings and self.settings.is_fair_configured():
            self._calculate_fair_model(metrics, active_df, risk_scores)

        # Top remediation priorities
        metrics.top_remediations = self._get_top_remediations(active_df, risk_scores)

        return metrics

    def _calculate_finding_risk_scores(
        self,
        df: pd.DataFrame,
        threat_intel_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, float]:
        """Calculate individual risk scores for each finding."""
        risk_scores = {}

        kev_set = set()
        if threat_intel_data and 'kev_cves' in threat_intel_data:
            kev_set = set(threat_intel_data['kev_cves'])

        for idx, row in df.iterrows():
            finding_key = f"{row.get('hostname', '')}|{row.get('plugin_id', '')}"

            # Base risk from severity
            severity = row.get('severity_text', 'Info')
            base_risk = self.SEVERITY_RISK_WEIGHTS.get(severity, 0)

            if base_risk == 0:
                risk_scores[finding_key] = 0
                continue

            # CVSS adjustment (scale 0-10 to multiplier 0.5-1.5)
            cvss = row.get('cvss3_base_score', row.get('cvss_base_score', 0))
            if pd.notna(cvss) and cvss > 0:
                cvss_multiplier = 0.5 + (float(cvss) / 10)
            else:
                cvss_multiplier = 1.0

            risk = base_risk * cvss_multiplier

            # EPSS adjustment (exploit probability)
            epss = row.get('epss_score', 0)
            if pd.notna(epss) and float(epss) > 0.5:
                risk *= self.HIGH_EPSS_MULTIPLIER
            elif pd.notna(epss) and float(epss) > 0.1:
                risk *= 1.5

            # KEV check (actively exploited)
            is_kev = row.get('is_kev', False)
            if not is_kev and kev_set:
                cves = str(row.get('cves', ''))
                if cves and any(cve.strip() in kev_set for cve in cves.split(',')):
                    is_kev = True

            if is_kev:
                risk *= self.KEV_MULTIPLIER

            # Exploit availability
            exploit_avail = str(row.get('exploit_available', '')).lower()
            if exploit_avail in ['yes', 'true', '1'] and not is_kev:
                risk *= self.EXPLOIT_AVAILABLE_MULTIPLIER

            # Production environment
            env = row.get('environment_type', row.get('environment', ''))
            if env == 'Production':
                risk *= self.PRODUCTION_MULTIPLIER

            # Age-based risk increase
            days_open = row.get('days_open', 0)
            if pd.notna(days_open):
                age_factor = 1.0
                for threshold, factor in sorted(self.AGE_RISK_FACTORS.items()):
                    if days_open <= threshold:
                        age_factor = factor
                        break
                risk *= age_factor

            # SLA breach
            sla_status = row.get('sla_status', '')
            if sla_status == 'Overdue':
                risk *= self.SLA_BREACH_MULTIPLIER

            risk_scores[finding_key] = risk

        return risk_scores

    def _normalize_risk_score(self, total_risk: float, finding_count: int) -> float:
        """
        Normalize total risk to 0-100 scale.
        Uses logarithmic scaling to handle wide range of values.
        """
        if total_risk <= 0:
            return 0.0

        # Log scale with adjustments for finding count
        # This ensures:
        # - Single critical finding ~= 30-40 score
        # - Moderate risk environment (50 mixed findings) ~= 50-60
        # - High risk (100+ with criticals) ~= 70-85
        # - Extreme risk (many criticals, KEVs) ~= 85-100

        base_score = math.log10(total_risk + 1) * 20

        # Adjust for finding density
        if finding_count > 0:
            avg_risk = total_risk / finding_count
            density_factor = min(1.5, 1 + (finding_count / 500))
            base_score *= density_factor

        return min(100, max(0, base_score))

    def _get_risk_rating(self, risk_score: float) -> str:
        """Convert numeric risk score to rating."""
        if risk_score >= 80:
            return "Critical"
        elif risk_score >= 60:
            return "High"
        elif risk_score >= 40:
            return "Medium"
        elif risk_score >= 20:
            return "Low"
        else:
            return "Minimal"

    def _calculate_financial_exposure(
        self,
        metrics: RiskMetrics,
        df: pd.DataFrame,
        risk_scores: Dict[str, float]
    ):
        """Calculate financial exposure estimates."""
        if not self.settings:
            return

        settings = self.settings

        # Breach cost estimate using IBM benchmark methodology
        # Base: $165/record, adjusted by industry and severity distribution
        industry_multiplier = settings.get_industry_multiplier()
        records_at_risk = settings.estimated_records_at_risk

        # Risk-weighted breach probability estimate
        # Higher risk score = higher probability of breach
        # Baseline: 5% annual breach probability at score 50
        breach_probability = min(0.5, (metrics.risk_score / 100) * 0.1)

        # KEV findings significantly increase breach probability
        if metrics.kev_findings > 0:
            kev_boost = min(0.3, metrics.kev_findings * 0.05)
            breach_probability = min(0.8, breach_probability + kev_boost)

        # Base breach cost = records * cost per record * industry multiplier
        base_breach_cost = records_at_risk * settings.cost_per_record * industry_multiplier

        # Expected breach cost = probability * potential cost
        metrics.estimated_breach_cost = base_breach_cost * breach_probability

        # Downtime cost estimate
        # Assume critical findings could cause 24-72hr outage, high 8-24hr
        if metrics.critical_findings > 0:
            avg_downtime_hours = 48 + (metrics.critical_findings * 4)  # Base + increment
            avg_downtime_hours = min(168, avg_downtime_hours)  # Cap at 1 week
        elif metrics.high_findings > 0:
            avg_downtime_hours = 16 + (metrics.high_findings * 2)
            avg_downtime_hours = min(72, avg_downtime_hours)
        else:
            avg_downtime_hours = 4

        # Weight by breach probability
        metrics.estimated_downtime_cost = (
            settings.hourly_downtime_cost * avg_downtime_hours * breach_probability
        )

        # Regulatory penalty exposure
        if settings.max_regulatory_penalty > 0:
            # Scale penalty exposure by compliance gap (SLA breaches indicate poor posture)
            compliance_factor = min(1.0, metrics.sla_breached_findings / max(1, metrics.total_findings) * 2)
            metrics.regulatory_penalty_exposure = settings.max_regulatory_penalty * compliance_factor * breach_probability

        # Total financial exposure
        metrics.total_financial_exposure = (
            metrics.estimated_breach_cost +
            metrics.estimated_downtime_cost +
            metrics.regulatory_penalty_exposure
        )

    def _calculate_remediation_metrics(
        self,
        metrics: RiskMetrics,
        active_df: pd.DataFrame,
        full_df: pd.DataFrame
    ):
        """Calculate remediation performance metrics."""
        # MTTR by severity (from resolved findings)
        if 'status' in full_df.columns and 'days_to_remediation' in full_df.columns:
            resolved = full_df[full_df['status'] == 'Resolved']

            if 'severity_text' in resolved.columns and not resolved.empty:
                crit_resolved = resolved[resolved['severity_text'] == 'Critical']
                if not crit_resolved.empty:
                    metrics.mttr_critical = crit_resolved['days_to_remediation'].mean()

                high_resolved = resolved[resolved['severity_text'] == 'High']
                if not high_resolved.empty:
                    metrics.mttr_high = high_resolved['days_to_remediation'].mean()

    def _calculate_risk_trend(self, metrics: RiskMetrics, historical_df: pd.DataFrame):
        """Calculate risk trend from historical data."""
        if 'scan_date' not in historical_df.columns:
            return

        try:
            hist = historical_df.copy()
            hist['scan_date'] = pd.to_datetime(hist['scan_date'])

            # Get data from 30 days ago
            now = hist['scan_date'].max()
            thirty_days_ago = now - timedelta(days=30)

            current_count = len(hist[hist['scan_date'] == now])
            past_count = len(hist[hist['scan_date'] <= thirty_days_ago])

            if past_count > 0:
                change_pct = ((current_count - past_count) / past_count) * 100
                metrics.risk_trend_pct = change_pct

                if change_pct < -10:
                    metrics.risk_trend = "improving"
                elif change_pct > 10:
                    metrics.risk_trend = "declining"
                else:
                    metrics.risk_trend = "stable"
        except Exception:
            pass

    def _calculate_fair_model(
        self,
        metrics: RiskMetrics,
        df: pd.DataFrame,
        risk_scores: Dict[str, float]
    ):
        """
        Calculate FAIR model metrics when configured.

        FAIR = Factor Analysis of Information Risk
        ALE = Annual Loss Expectancy = LEF × LM
        LEF = Loss Event Frequency = TEF × Vulnerability
        LM = Loss Magnitude = Primary Loss + Secondary Loss
        """
        if not self.settings or not self.settings.is_fair_configured():
            return

        metrics.fair_available = True
        settings = self.settings

        # Loss Event Frequency (LEF)
        tef = settings.threat_event_frequency  # Annual threat events
        vuln_pct = settings.vulnerability_percentage / 100  # Convert to decimal

        # Adjust vulnerability percentage based on actual posture
        # Control effectiveness reduces successful attacks
        control_eff = settings.control_effectiveness / 100
        adjusted_vuln = vuln_pct * (1 - control_eff)

        # Boost vulnerability based on KEV/exploitable findings
        if metrics.kev_findings > 0:
            adjusted_vuln = min(1.0, adjusted_vuln * 1.5)

        lef = tef * adjusted_vuln

        # Loss Magnitude using PERT distribution (min, likely, max)
        primary_lm = self._pert_estimate(
            settings.primary_loss_min,
            settings.primary_loss_likely,
            settings.primary_loss_max
        )

        secondary_lm = self._pert_estimate(
            settings.secondary_loss_min,
            settings.secondary_loss_likely,
            settings.secondary_loss_max
        )

        total_lm = primary_lm + secondary_lm

        # Annualized Loss Expectancy
        metrics.annualized_loss_expectancy = lef * total_lm

        # Loss Exceedance Curve (simplified)
        # Shows probability of exceeding various loss amounts
        metrics.loss_exceedance_curve = {
            '10%': total_lm * 0.1 * lef,
            '50%': total_lm * 0.5 * lef,
            '90%': total_lm * 0.9 * lef,
            '95%': total_lm * 0.95 * lef,
            '99%': total_lm * 0.99 * lef
        }

    def _pert_estimate(self, minimum: float, likely: float, maximum: float) -> float:
        """
        Calculate PERT (Program Evaluation Review Technique) estimate.
        Formula: (min + 4*likely + max) / 6
        """
        if likely <= 0:
            return 0
        return (minimum + 4 * likely + maximum) / 6

    def _get_top_remediations(
        self,
        df: pd.DataFrame,
        risk_scores: Dict[str, float]
    ) -> List[Dict[str, Any]]:
        """
        Get top remediation actions ranked by risk reduction impact.
        Groups findings by plugin/package for actionable recommendations.
        """
        if df.empty:
            return []

        # Group by plugin to aggregate impact
        plugin_impact = {}

        for idx, row in df.iterrows():
            plugin_id = row.get('plugin_id', '')
            plugin_name = row.get('plugin_name', 'Unknown')
            finding_key = f"{row.get('hostname', '')}|{plugin_id}"

            risk = risk_scores.get(finding_key, 0)

            if plugin_id not in plugin_impact:
                plugin_impact[plugin_id] = {
                    'plugin_id': plugin_id,
                    'plugin_name': plugin_name,
                    'severity': row.get('severity_text', 'Unknown'),
                    'total_risk': 0,
                    'host_count': 0,
                    'is_kev': row.get('is_kev', False),
                    'cvss': row.get('cvss3_base_score', 0),
                    'hosts': []
                }

            plugin_impact[plugin_id]['total_risk'] += risk
            plugin_impact[plugin_id]['host_count'] += 1
            plugin_impact[plugin_id]['hosts'].append(row.get('hostname', ''))

        # Sort by total risk reduction potential
        sorted_plugins = sorted(
            plugin_impact.values(),
            key=lambda x: x['total_risk'],
            reverse=True
        )[:10]  # Top 10

        # Calculate risk reduction percentage
        total_risk = sum(risk_scores.values())

        remediations = []
        for plugin in sorted_plugins:
            risk_reduction_pct = (plugin['total_risk'] / total_risk * 100) if total_risk > 0 else 0

            remediations.append({
                'plugin_id': plugin['plugin_id'],
                'plugin_name': plugin['plugin_name'],
                'severity': plugin['severity'],
                'host_count': plugin['host_count'],
                'risk_score': round(plugin['total_risk'], 1),
                'risk_reduction_pct': round(risk_reduction_pct, 1),
                'is_kev': plugin['is_kev'],
                'cvss': plugin['cvss'],
                'recommendation': f"Remediate on {plugin['host_count']} host(s) for {risk_reduction_pct:.1f}% risk reduction"
            })

        return remediations

    def calculate_remediation_roi(
        self,
        remediation_cost: float,
        risk_reduction_pct: float,
        current_exposure: float
    ) -> Dict[str, float]:
        """
        Calculate ROI for a remediation action.

        Args:
            remediation_cost: Cost to implement remediation
            risk_reduction_pct: Expected % reduction in risk
            current_exposure: Current total financial exposure

        Returns:
            Dict with ROI metrics
        """
        exposure_reduction = current_exposure * (risk_reduction_pct / 100)
        net_benefit = exposure_reduction - remediation_cost
        roi = (net_benefit / remediation_cost * 100) if remediation_cost > 0 else 0
        payback_period = (remediation_cost / exposure_reduction * 12) if exposure_reduction > 0 else float('inf')

        return {
            'exposure_reduction': exposure_reduction,
            'net_benefit': net_benefit,
            'roi_pct': roi,
            'payback_months': payback_period if payback_period != float('inf') else None
        }


def format_currency(value: float, symbol: str = "$") -> str:
    """Format a value as currency."""
    if value >= 1_000_000:
        return f"{symbol}{value/1_000_000:.2f}M"
    elif value >= 1_000:
        return f"{symbol}{value/1_000:.1f}K"
    else:
        return f"{symbol}{value:.0f}"


def get_risk_color(rating: str) -> str:
    """Get color for risk rating."""
    colors = {
        'Critical': '#dc3545',
        'High': '#fd7e14',
        'Medium': '#B8860B',
        'Low': '#28a745',
        'Minimal': '#17a2b8'
    }
    return colors.get(rating, '#6c757d')
