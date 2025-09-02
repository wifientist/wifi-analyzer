"""
Wireless Expert Agent - AI persona for analysis interpretation.

This module provides expert analysis and recommendations based on
wireless analysis findings.
"""

from typing import Dict, List, Any
from ..core.models import AnalysisResults, Finding, Severity, AnalysisCategory


class WirelessExpertAgent:
    """
    AI Expert Agent for interpreting wireless analysis results.
    
    This agent acts as a wireless networking expert, providing:
    - Executive summaries of findings
    - Risk assessments and scoring
    - Prioritized recommendations
    - Common pathology identification
    """
    
    def __init__(self):
        self.expertise_domains = [
            "802.11 Protocol Analysis & Standards Compliance",
            "Wireless Security Assessment & Threat Detection", 
            "RF Performance Optimization & Channel Planning",
            "Enterprise Network Troubleshooting",
            "Roaming & Load Balancing Strategy",
            "QoS & Application Performance Tuning",
            "802.11ax/be Advanced Features (OFDMA, MU-MIMO, MLO)",
            "6 GHz Band Operations & WPA3 Deployment",
            "Compliance & Best Practices (802.11k/v/r/w)"
        ]
        
    def generate_executive_summary(self, results: AnalysisResults) -> Dict[str, Any]:
        """
        Generate executive summary of analysis results.
        
        Args:
            results: Analysis results to summarize
            
        Returns:
            Executive summary dictionary
        """
        critical_findings = results.get_findings_by_severity(Severity.CRITICAL)
        warning_findings = results.get_findings_by_severity(Severity.WARNING)
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(results)
        
        # Assess overall security posture
        security_assessment = self._assess_security_posture(results)
        
        # Get priority recommendations
        priority_recommendations = self._get_priority_recommendations(results)
        
        # Identify key concerns
        key_concerns = [f.title for f in critical_findings[:5]]
        if len(warning_findings) > len(critical_findings):
            key_concerns.extend([f.title for f in warning_findings[:3]])
        
        summary = {
            "overall_assessment": security_assessment,
            "risk_score": risk_score,
            "key_concerns": key_concerns,
            "priority_recommendations": priority_recommendations,
            "compliance_status": self._assess_compliance(results),
            "performance_summary": self._summarize_performance(results),
            "security_summary": self._summarize_security(results)
        }
        
        return summary
    
    def _calculate_risk_score(self, results: AnalysisResults) -> int:
        """Calculate risk score from 0-100 based on findings."""
        score = 0
        
        # Weight by severity
        score += len(results.get_findings_by_severity(Severity.CRITICAL)) * 25
        score += len(results.get_findings_by_severity(Severity.WARNING)) * 10
        score += len(results.get_findings_by_severity(Severity.ERROR)) * 15
        
        # Weight by category (security issues are more critical)
        security_findings = results.get_findings_by_category(AnalysisCategory.SECURITY_THREATS)
        score += len(security_findings) * 5
        
        return min(score, 100)
    
    def _assess_security_posture(self, results: AnalysisResults) -> str:
        """Assess overall security posture."""
        critical_count = len(results.get_findings_by_severity(Severity.CRITICAL))
        warning_count = len(results.get_findings_by_severity(Severity.WARNING))
        
        security_critical = len(results.get_findings_by_category(AnalysisCategory.SECURITY_THREATS))
        
        if critical_count > 5 or security_critical > 2:
            return "POOR - Multiple critical security issues detected requiring immediate attention"
        elif critical_count > 0 or warning_count > 10 or security_critical > 0:
            return "MODERATE - Some security concerns identified that should be addressed"
        elif warning_count > 5:
            return "ACCEPTABLE - Minor issues detected, regular monitoring recommended"
        else:
            return "GOOD - No major security issues detected, network appears healthy"
    
    def _get_priority_recommendations(self, results: AnalysisResults) -> List[str]:
        """Extract and prioritize recommendations."""
        all_recommendations = []
        
        # Prioritize critical findings first
        critical_findings = results.get_findings_by_severity(Severity.CRITICAL)
        for finding in critical_findings:
            all_recommendations.extend(finding.recommendations)
        
        # Then warning findings
        warning_findings = results.get_findings_by_severity(Severity.WARNING)
        for finding in warning_findings[:5]:  # Limit to top 5 warnings
            all_recommendations.extend(finding.recommendations)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_recommendations = []
        for rec in all_recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)
        
        return unique_recommendations[:10]  # Return top 10
    
    def _assess_compliance(self, results: AnalysisResults) -> Dict[str, str]:
        """Assess compliance with various standards."""
        # This is a stub - would be enhanced based on specific findings
        return {
            "802.11w_pmf": "UNKNOWN - Insufficient data",
            "wpa3_readiness": "UNKNOWN - Insufficient data", 
            "enterprise_security": "UNKNOWN - Insufficient data",
            "performance_standards": "UNKNOWN - Insufficient data"
        }
    
    def _summarize_performance(self, results: AnalysisResults) -> Dict[str, Any]:
        """Summarize performance-related findings."""
        perf_categories = [
            AnalysisCategory.RF_PHY,
            AnalysisCategory.DATA_CONTROL_PLANE,
            AnalysisCategory.QOS_WMM,
            AnalysisCategory.APP_PERFORMANCE
        ]
        
        perf_findings = []
        for category in perf_categories:
            perf_findings.extend(results.get_findings_by_category(category))
        
        critical_perf = [f for f in perf_findings if f.severity == Severity.CRITICAL]
        warning_perf = [f for f in perf_findings if f.severity == Severity.WARNING]
        
        if critical_perf:
            status = "POOR - Critical performance issues detected"
        elif len(warning_perf) > 5:
            status = "MODERATE - Multiple performance concerns"
        elif len(warning_perf) > 0:
            status = "ACCEPTABLE - Minor performance issues"
        else:
            status = "GOOD - No significant performance issues"
        
        return {
            "status": status,
            "critical_issues": len(critical_perf),
            "warnings": len(warning_perf),
            "top_issues": [f.title for f in critical_perf[:3]]
        }
    
    def _summarize_security(self, results: AnalysisResults) -> Dict[str, Any]:
        """Summarize security-related findings."""
        security_categories = [
            AnalysisCategory.SECURITY_THREATS,
            AnalysisCategory.ENTERPRISE_SECURITY,
            AnalysisCategory.EAPOL_HANDSHAKE
        ]
        
        security_findings = []
        for category in security_categories:
            security_findings.extend(results.get_findings_by_category(category))
        
        critical_sec = [f for f in security_findings if f.severity == Severity.CRITICAL]
        warning_sec = [f for f in security_findings if f.severity == Severity.WARNING]
        
        if critical_sec:
            status = "HIGH RISK - Critical security vulnerabilities detected"
        elif len(warning_sec) > 3:
            status = "MEDIUM RISK - Multiple security concerns"
        elif len(warning_sec) > 0:
            status = "LOW RISK - Minor security issues"
        else:
            status = "SECURE - No significant security issues detected"
        
        return {
            "risk_level": status,
            "critical_vulnerabilities": len(critical_sec),
            "security_warnings": len(warning_sec),
            "top_threats": [f.title for f in critical_sec[:3]]
        }
