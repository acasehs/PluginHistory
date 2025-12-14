"""
Vulnerability Predictions Module
Builds prompts and processes AI analysis for vulnerability data.
"""

import json
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta

from .openwebui_client import OpenWebUIClient, ChatMessage, ChatResponse


class AnalysisMode(Enum):
    """Analysis mode selection."""
    QUICK = "quick"
    COMPREHENSIVE = "comprehensive"


class PredictionType(Enum):
    """Types of predictions available."""
    TIME_TO_REMEDIATE = "time_to_remediate"
    SLA_BREACH_FORECAST = "sla_breach_forecast"
    PRIORITIZATION = "prioritization"
    TREND_ANALYSIS = "trend_analysis"
    FULL_ANALYSIS = "full_analysis"


@dataclass
class AnalysisRequest:
    """Request for AI analysis."""
    prediction_type: PredictionType
    mode: AnalysisMode = AnalysisMode.QUICK
    top_n_findings: int = 50  # For quick mode
    include_recommendations: bool = True


@dataclass
class AnalysisResult:
    """Result from AI analysis."""
    success: bool
    prediction_type: PredictionType
    mode: AnalysisMode
    content: str = ""
    error: str = ""
    model_used: str = ""
    tokens_used: Dict[str, int] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    conversation_history: List[Dict[str, str]] = field(default_factory=list)


class VulnerabilityPredictor:
    """
    AI-powered vulnerability analysis and predictions.
    Uses OpenWebUI to analyze vulnerability data and generate insights.
    """

    # System prompt for vulnerability analysis
    SYSTEM_PROMPT = """You are a cybersecurity vulnerability analyst assistant. Your role is to analyze vulnerability scan data and provide actionable insights for remediation prioritization and forecasting.

When analyzing data:
1. Focus on practical, actionable recommendations
2. Consider both technical severity (CVSS) and operational context (age, affected hosts)
3. Reference CVE/IAVM identifiers when discussing specific vulnerabilities
4. Provide time-based predictions grounded in historical patterns
5. Highlight any findings that appear in known exploited vulnerability lists (KEV) or have high EPSS scores

Format your responses clearly with sections and bullet points for readability."""

    def __init__(self, client: OpenWebUIClient):
        """Initialize predictor with OpenWebUI client."""
        self.client = client
        self._conversation_history: List[Dict[str, str]] = []

    def clear_conversation(self):
        """Clear conversation history for fresh analysis."""
        self._conversation_history = []

    def _build_quick_payload(
        self,
        findings_df: pd.DataFrame,
        lifecycle_df: pd.DataFrame,
        top_n: int = 50
    ) -> Dict[str, Any]:
        """
        Build quick mode payload with aggregated stats and top findings.
        Includes plugin names and CVE/IAVMs for context.
        """
        payload = {
            "summary": {},
            "findings_snapshot": [],
            "mttr_by_severity": {},
            "mttr_by_family": {},
            "velocity": {},
            "sla_status": {}
        }

        # Summary stats
        if not findings_df.empty:
            payload["summary"] = {
                "total_findings": len(findings_df),
                "unique_plugins": findings_df['plugin_id'].nunique() if 'plugin_id' in findings_df.columns else 0,
                "affected_hosts": findings_df['hostname'].nunique() if 'hostname' in findings_df.columns else 0,
                "by_severity": findings_df['severity_text'].value_counts().to_dict() if 'severity_text' in findings_df.columns else {}
            }

        # Top findings snapshot (sorted by severity and age)
        if not lifecycle_df.empty:
            # Get active findings, sorted by severity (desc) and days_open (desc)
            active = lifecycle_df[lifecycle_df['status'] == 'Active'].copy() if 'status' in lifecycle_df.columns else lifecycle_df.copy()

            if not active.empty:
                # Sort by severity value (desc) then days_open (desc)
                if 'severity_value' in active.columns and 'days_open' in active.columns:
                    active = active.sort_values(['severity_value', 'days_open'], ascending=[False, False])

                # Take top N
                top_findings = active.head(top_n)

                for _, row in top_findings.iterrows():
                    finding = {
                        "plugin_id": str(row.get('plugin_id', '')),
                        "plugin_name": row.get('plugin_name', row.get('name', 'Unknown')),
                        "severity": row.get('severity_text', 'Unknown'),
                        "days_open": int(row.get('days_open', 0)),
                        "host_count": 1  # Will be aggregated below
                    }

                    # Add CVEs if present
                    cves = row.get('cves', '')
                    if cves and pd.notna(cves):
                        finding["cves"] = cves.split(',') if isinstance(cves, str) else []

                    # Add IAVMs if present
                    iavms = row.get('iavx', row.get('iavm', ''))
                    if iavms and pd.notna(iavms):
                        finding["iavms"] = iavms.split(',') if isinstance(iavms, str) else []

                    # Add CVSS if present
                    cvss = row.get('cvss3_base_score')
                    if cvss and pd.notna(cvss):
                        finding["cvss"] = float(cvss)

                    payload["findings_snapshot"].append(finding)

            # Calculate host counts per plugin
            if 'plugin_id' in lifecycle_df.columns:
                host_counts = lifecycle_df.groupby('plugin_id').size().to_dict()
                for finding in payload["findings_snapshot"]:
                    pid = finding.get('plugin_id')
                    if pid in host_counts:
                        finding["host_count"] = host_counts[pid]

            # MTTR by severity
            resolved = lifecycle_df[lifecycle_df['status'] == 'Resolved'] if 'status' in lifecycle_df.columns else pd.DataFrame()
            if not resolved.empty and 'severity_text' in resolved.columns and 'days_open' in resolved.columns:
                mttr_sev = resolved.groupby('severity_text')['days_open'].agg(['mean', 'median', 'count'])
                payload["mttr_by_severity"] = {
                    sev: {
                        "avg_days": round(row['mean'], 1),
                        "median_days": round(row['median'], 1),
                        "sample_size": int(row['count'])
                    }
                    for sev, row in mttr_sev.iterrows()
                }

            # Velocity (last 30 days vs prior 30 days)
            if 'last_seen' in lifecycle_df.columns and 'status' in lifecycle_df.columns:
                now = datetime.now()
                last_30 = now - timedelta(days=30)
                prior_30 = now - timedelta(days=60)

                lifecycle_df['last_seen_dt'] = pd.to_datetime(lifecycle_df['last_seen'])
                recent_resolved = lifecycle_df[
                    (lifecycle_df['status'] == 'Resolved') &
                    (lifecycle_df['last_seen_dt'] >= last_30)
                ]
                prior_resolved = lifecycle_df[
                    (lifecycle_df['status'] == 'Resolved') &
                    (lifecycle_df['last_seen_dt'] >= prior_30) &
                    (lifecycle_df['last_seen_dt'] < last_30)
                ]

                payload["velocity"] = {
                    "last_30d_resolved": len(recent_resolved),
                    "prior_30d_resolved": len(prior_resolved),
                    "trend": "improving" if len(recent_resolved) > len(prior_resolved) else "declining"
                }

        return payload

    def _build_comprehensive_payload(
        self,
        findings_df: pd.DataFrame,
        lifecycle_df: pd.DataFrame
    ) -> Dict[str, Any]:
        """
        Build comprehensive mode payload with full finding details.
        """
        payload = self._build_quick_payload(findings_df, lifecycle_df, top_n=len(lifecycle_df))

        # Add full finding details
        if not lifecycle_df.empty:
            detailed_findings = []
            for _, row in lifecycle_df.iterrows():
                finding = {
                    "plugin_id": str(row.get('plugin_id', '')),
                    "plugin_name": row.get('plugin_name', row.get('name', 'Unknown')),
                    "hostname": row.get('hostname', ''),
                    "ip_address": row.get('ip_address', ''),
                    "severity": row.get('severity_text', 'Unknown'),
                    "severity_value": int(row.get('severity_value', 0)),
                    "first_seen": str(row.get('first_seen', '')),
                    "last_seen": str(row.get('last_seen', '')),
                    "days_open": int(row.get('days_open', 0)),
                    "status": row.get('status', 'Unknown'),
                    "reappearances": int(row.get('reappearances', 0))
                }

                # Add all available enrichment fields
                for field in ['cves', 'iavx', 'cvss3_base_score', 'solution', 'description']:
                    val = row.get(field)
                    if val and pd.notna(val):
                        finding[field] = val if not isinstance(val, float) else round(val, 1)

                detailed_findings.append(finding)

            payload["detailed_findings"] = detailed_findings

        return payload

    def _build_prompt(
        self,
        prediction_type: PredictionType,
        data_payload: Dict[str, Any],
        include_recommendations: bool = True
    ) -> str:
        """Build the analysis prompt based on prediction type."""

        data_json = json.dumps(data_payload, indent=2, default=str)

        prompts = {
            PredictionType.TIME_TO_REMEDIATE: f"""Analyze the following vulnerability data and predict remediation timelines.

VULNERABILITY DATA:
{data_json}

Please provide:
1. **Predicted Time-to-Remediate** for each severity level based on historical MTTR patterns
2. **At-Risk Findings** - findings that may exceed typical remediation windows
3. **Factors Affecting Remediation** - identify patterns (plugin families, host types) with slower remediation
{"4. **Recommendations** - specific actions to improve remediation velocity" if include_recommendations else ""}

Focus on actionable predictions with specific timeframes.""",

            PredictionType.SLA_BREACH_FORECAST: f"""Analyze the following vulnerability data and forecast potential SLA breaches.

VULNERABILITY DATA:
{data_json}

Typical SLA targets:
- Critical: 15 days
- High: 30 days
- Medium: 60 days
- Low: 90 days

Please provide:
1. **Breach Forecast** - count and list of findings likely to breach SLA at current velocity
2. **High-Risk Findings** - specific findings closest to SLA breach
3. **Trend Analysis** - is the situation improving or deteriorating?
{"4. **Mitigation Strategies** - recommendations to avoid breaches" if include_recommendations else ""}""",

            PredictionType.PRIORITIZATION: f"""Analyze the following vulnerability data and provide prioritized remediation recommendations.

VULNERABILITY DATA:
{data_json}

Please provide:
1. **Priority Ranking** - top 10-15 findings to address immediately, with justification
2. **Quick Wins** - findings that can be resolved quickly with high impact
3. **Risk Clusters** - groups of related vulnerabilities that can be addressed together
{"4. **Remediation Strategy** - suggested approach for tackling the backlog" if include_recommendations else ""}

Consider CVSS scores, exploit availability (KEV/EPSS if referenced), affected host count, and age.""",

            PredictionType.TREND_ANALYSIS: f"""Analyze the following vulnerability data and identify trends.

VULNERABILITY DATA:
{data_json}

Please provide:
1. **Velocity Trends** - is remediation keeping pace with new findings?
2. **Problem Areas** - plugin families, host groups, or severity levels with concerning trends
3. **Positive Developments** - areas showing improvement
4. **Reappearance Patterns** - findings that keep coming back and why
{"5. **Strategic Recommendations** - process improvements to address root causes" if include_recommendations else ""}""",

            PredictionType.FULL_ANALYSIS: f"""Perform a comprehensive vulnerability analysis on the following data.

VULNERABILITY DATA:
{data_json}

Please provide a complete analysis covering:

1. **Executive Summary** - key metrics and overall posture assessment

2. **Remediation Timeline Predictions**
   - Expected time to remediate by severity
   - At-risk findings approaching deadlines

3. **Prioritization**
   - Top 10 findings requiring immediate attention
   - Quick wins for rapid risk reduction

4. **Trend Analysis**
   - Velocity trends (improving/declining)
   - Problem areas and root causes

5. **SLA Compliance Forecast**
   - Predicted breaches at current velocity
   - Resources needed to avoid breaches

{"6. **Recommendations**" if include_recommendations else ""}
{"   - Immediate actions (next 7 days)" if include_recommendations else ""}
{"   - Short-term improvements (30 days)" if include_recommendations else ""}
{"   - Process changes for long-term improvement" if include_recommendations else ""}

Be specific and actionable. Reference specific CVEs, IAVMs, and plugin IDs where relevant."""
        }

        return prompts.get(prediction_type, prompts[PredictionType.FULL_ANALYSIS])

    def analyze(
        self,
        findings_df: pd.DataFrame,
        lifecycle_df: pd.DataFrame,
        request: AnalysisRequest,
        collection_ids: Optional[List[str]] = None
    ) -> AnalysisResult:
        """
        Perform AI analysis on vulnerability data.

        Args:
            findings_df: Raw findings DataFrame
            lifecycle_df: Lifecycle analysis DataFrame
            request: Analysis request configuration
            collection_ids: Optional RAG collection IDs for threat intel context

        Returns:
            AnalysisResult with AI-generated insights
        """
        # Build data payload based on mode
        if request.mode == AnalysisMode.QUICK:
            payload = self._build_quick_payload(
                findings_df, lifecycle_df, request.top_n_findings
            )
        else:
            payload = self._build_comprehensive_payload(findings_df, lifecycle_df)

        # Build prompt
        prompt = self._build_prompt(
            request.prediction_type,
            payload,
            request.include_recommendations
        )

        # Clear conversation for fresh analysis
        self.clear_conversation()

        # Send to OpenWebUI
        response = self.client.simple_query(
            prompt=prompt,
            system_prompt=self.SYSTEM_PROMPT,
            collection_ids=collection_ids
        )

        # Build result
        if response.success:
            # Store in conversation history for follow-ups
            self._conversation_history = [
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
                {"role": "assistant", "content": response.content}
            ]

            return AnalysisResult(
                success=True,
                prediction_type=request.prediction_type,
                mode=request.mode,
                content=response.content,
                model_used=response.model,
                tokens_used=response.usage,
                conversation_history=self._conversation_history
            )
        else:
            return AnalysisResult(
                success=False,
                prediction_type=request.prediction_type,
                mode=request.mode,
                error=response.error,
                model_used=response.model
            )

    def follow_up(
        self,
        question: str,
        collection_ids: Optional[List[str]] = None
    ) -> AnalysisResult:
        """
        Ask a follow-up question about the previous analysis.

        Args:
            question: Follow-up question from user
            collection_ids: Optional RAG collection IDs

        Returns:
            AnalysisResult with follow-up response
        """
        if not self._conversation_history:
            return AnalysisResult(
                success=False,
                prediction_type=PredictionType.FULL_ANALYSIS,
                mode=AnalysisMode.QUICK,
                error="No previous analysis to follow up on. Please run an analysis first."
            )

        # Send follow-up with conversation context
        response = self.client.query_with_conversation(
            conversation_history=self._conversation_history,
            new_message=question,
            collection_ids=collection_ids,
            system_prompt=self.SYSTEM_PROMPT
        )

        if response.success:
            # Add to conversation history
            self._conversation_history.append({"role": "user", "content": question})
            self._conversation_history.append({"role": "assistant", "content": response.content})

            return AnalysisResult(
                success=True,
                prediction_type=PredictionType.FULL_ANALYSIS,
                mode=AnalysisMode.QUICK,
                content=response.content,
                model_used=response.model,
                tokens_used=response.usage,
                conversation_history=self._conversation_history
            )
        else:
            return AnalysisResult(
                success=False,
                prediction_type=PredictionType.FULL_ANALYSIS,
                mode=AnalysisMode.QUICK,
                error=response.error,
                model_used=response.model
            )

    def analyze_single_finding(
        self,
        finding: Dict[str, Any],
        historical_mttr: Dict[str, float],
        collection_ids: Optional[List[str]] = None
    ) -> AnalysisResult:
        """
        Analyze a single finding for remediation prediction.

        Args:
            finding: Single finding dictionary
            historical_mttr: Historical MTTR by severity/family
            collection_ids: Optional RAG collection IDs

        Returns:
            AnalysisResult with prediction for this finding
        """
        prompt = f"""Analyze this specific vulnerability finding and predict its remediation timeline.

FINDING:
{json.dumps(finding, indent=2, default=str)}

HISTORICAL REMEDIATION DATA:
{json.dumps(historical_mttr, indent=2)}

Please provide:
1. **Predicted Remediation Time** - estimated days to resolve based on historical patterns
2. **Risk Assessment** - urgency level and justification
3. **Similar Vulnerabilities** - if this CVE/plugin has known patterns
4. **Recommended Actions** - specific steps for this finding

Be concise but specific."""

        response = self.client.simple_query(
            prompt=prompt,
            system_prompt=self.SYSTEM_PROMPT,
            collection_ids=collection_ids
        )

        if response.success:
            return AnalysisResult(
                success=True,
                prediction_type=PredictionType.TIME_TO_REMEDIATE,
                mode=AnalysisMode.QUICK,
                content=response.content,
                model_used=response.model,
                tokens_used=response.usage
            )
        else:
            return AnalysisResult(
                success=False,
                prediction_type=PredictionType.TIME_TO_REMEDIATE,
                mode=AnalysisMode.QUICK,
                error=response.error
            )
