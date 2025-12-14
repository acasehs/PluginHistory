"""
AI Predictions Module
OpenWebUI integration for vulnerability analysis and predictions.
"""

# Lazy imports to avoid circular dependencies
def __getattr__(name):
    if name == 'OpenWebUIClient':
        from .openwebui_client import OpenWebUIClient
        return OpenWebUIClient
    elif name == 'OpenWebUIConfig':
        from .openwebui_client import OpenWebUIConfig
        return OpenWebUIConfig
    elif name == 'VulnerabilityPredictor':
        from .predictions import VulnerabilityPredictor
        return VulnerabilityPredictor
    elif name == 'AnalysisMode':
        from .predictions import AnalysisMode
        return AnalysisMode
    elif name == 'PredictionType':
        from .predictions import PredictionType
        return PredictionType
    elif name == 'AnalysisRequest':
        from .predictions import AnalysisRequest
        return AnalysisRequest
    elif name == 'ThreatIntelManager':
        from .threat_intel import ThreatIntelManager
        return ThreatIntelManager
    elif name == 'RAGSyncManager':
        from .rag_sync import RAGSyncManager
        return RAGSyncManager
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
    'OpenWebUIClient',
    'OpenWebUIConfig',
    'VulnerabilityPredictor',
    'AnalysisMode',
    'PredictionType',
    'AnalysisRequest',
    'ThreatIntelManager',
    'RAGSyncManager'
]
