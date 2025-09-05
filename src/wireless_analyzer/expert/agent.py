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
        Generate comprehensive executive summary of analysis results.
        
        Args:
            results: Analysis results to summarize
            
        Returns:
            Executive summary dictionary
        """
        import logging
        logger = logging.getLogger(__name__)
        
        # Get findings by severity
        critical_findings = results.get_findings_by_severity(Severity.CRITICAL)
        warning_findings = results.get_findings_by_severity(Severity.WARNING)
        error_findings = results.get_findings_by_severity(Severity.ERROR)
        info_findings = results.get_findings_by_severity(Severity.INFO)
        
        logger.info(f"Expert analysis processing: {len(critical_findings)} critical, "
                   f"{len(warning_findings)} warning, {len(error_findings)} error, "
                   f"{len(info_findings)} info findings")
        
        # Analyze findings by category to ensure all are considered
        category_analysis = self._analyze_by_category(results)
        
        # Calculate comprehensive risk score
        risk_score = self._calculate_risk_score(results)
        
        # Assess overall security posture
        security_assessment = self._assess_security_posture(results)
        
        # Get priority recommendations from ALL findings
        priority_recommendations = self._get_priority_recommendations(results)
        
        # Identify key concerns across all categories
        key_concerns = self._identify_key_concerns(results)
        
        summary = {
            "overall_assessment": security_assessment,
            "risk_score": risk_score,
            "key_concerns": key_concerns,
            "priority_recommendations": priority_recommendations,
            "category_breakdown": category_analysis,
            "findings_summary": {
                "total_findings": len(results.findings),
                "critical": len(critical_findings),
                "warning": len(warning_findings),
                "error": len(error_findings),
                "info": len(info_findings)
            },
            "compliance_status": self._assess_compliance(results),
            "performance_summary": self._summarize_performance(results),
            "security_summary": self._summarize_security(results),
            "network_health": self._assess_network_health(results)
        }
        
        logger.info(f"Expert summary generated with risk score {risk_score} and "
                   f"{len(priority_recommendations)} priority recommendations")
        
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
        """Extract and prioritize recommendations from ALL findings."""
        all_recommendations = []
        recommendation_weights = {}  # Track importance by source severity
        
        # Prioritize critical findings first (highest weight)
        critical_findings = results.get_findings_by_severity(Severity.CRITICAL)
        for finding in critical_findings:
            for rec in finding.recommendations:
                all_recommendations.append(rec)
                recommendation_weights[rec] = recommendation_weights.get(rec, 0) + 10
        
        # Then error findings (medium-high weight)
        error_findings = results.get_findings_by_severity(Severity.ERROR)
        for finding in error_findings:
            for rec in finding.recommendations:
                all_recommendations.append(rec)
                recommendation_weights[rec] = recommendation_weights.get(rec, 0) + 7
        
        # Then warning findings (medium weight)
        warning_findings = results.get_findings_by_severity(Severity.WARNING)
        for finding in warning_findings:
            for rec in finding.recommendations:
                all_recommendations.append(rec)
                recommendation_weights[rec] = recommendation_weights.get(rec, 0) + 5
        
        # Finally info findings (low weight but still included)
        info_findings = results.get_findings_by_severity(Severity.INFO)
        for finding in info_findings:
            for rec in finding.recommendations:
                all_recommendations.append(rec)
                recommendation_weights[rec] = recommendation_weights.get(rec, 0) + 2
        
        # Remove duplicates and sort by weight (importance)
        unique_recommendations = list(set(all_recommendations))
        unique_recommendations.sort(key=lambda x: recommendation_weights.get(x, 0), reverse=True)
        
        return unique_recommendations[:15]  # Return top 15 most important
    
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
    
    def _analyze_by_category(self, results: AnalysisResults) -> Dict[str, Dict[str, Any]]:
        """
        Analyze findings by category to ensure comprehensive coverage.
        
        Args:
            results: Analysis results
            
        Returns:
            Category breakdown with counts and top issues
        """
        category_breakdown = {}
        
        # Analyze all AnalysisCategory values
        for category in AnalysisCategory:
            category_findings = results.get_findings_by_category(category)
            
            if category_findings:
                critical_count = len([f for f in category_findings if f.severity == Severity.CRITICAL])
                warning_count = len([f for f in category_findings if f.severity == Severity.WARNING])
                
                category_breakdown[category.value] = {
                    "total_findings": len(category_findings),
                    "critical": critical_count,
                    "warning": warning_count,
                    "top_issues": [f.title for f in category_findings[:3]],
                    "status": self._get_category_status(critical_count, warning_count, len(category_findings))
                }
        
        return category_breakdown
    
    def _identify_key_concerns(self, results: AnalysisResults) -> List[str]:
        """
        Identify key concerns across all categories and severities.
        
        Args:
            results: Analysis results
            
        Returns:
            List of key concern titles
        """
        key_concerns = []
        
        # Always include all critical findings
        critical_findings = results.get_findings_by_severity(Severity.CRITICAL)
        key_concerns.extend([f.title for f in critical_findings])
        
        # Add significant warning findings if we have room
        warning_findings = results.get_findings_by_severity(Severity.WARNING)
        remaining_slots = max(0, 10 - len(key_concerns))
        key_concerns.extend([f.title for f in warning_findings[:remaining_slots]])
        
        # If still have room, add error findings
        remaining_slots = max(0, 10 - len(key_concerns))
        if remaining_slots > 0:
            error_findings = results.get_findings_by_severity(Severity.ERROR)
            key_concerns.extend([f.title for f in error_findings[:remaining_slots]])
        
        return key_concerns
    
    def _get_category_status(self, critical: int, warning: int, total: int) -> str:
        """Get status assessment for a category."""
        if critical > 0:
            return "CRITICAL"
        elif warning > 2:
            return "CONCERNING"
        elif warning > 0:
            return "ATTENTION_NEEDED"
        elif total > 0:
            return "INFORMATIONAL"
        else:
            return "OK"
    
    def _assess_network_health(self, results: AnalysisResults) -> Dict[str, Any]:
        """
        Assess overall network health across all categories.
        
        Args:
            results: Analysis results
            
        Returns:
            Network health assessment
        """
        total_findings = len(results.findings)
        critical_count = len(results.get_findings_by_severity(Severity.CRITICAL))
        warning_count = len(results.get_findings_by_severity(Severity.WARNING))
        
        # Calculate health score (0-100, higher is better)
        health_score = max(0, 100 - (critical_count * 15) - (warning_count * 5))
        
        # Determine health status
        if health_score >= 85:
            status = "EXCELLENT"
            message = "Network appears healthy with minimal issues"
        elif health_score >= 70:
            status = "GOOD"
            message = "Network is generally healthy with minor issues"
        elif health_score >= 50:
            status = "FAIR"
            message = "Network has some issues that should be addressed"
        elif health_score >= 30:
            status = "POOR"
            message = "Network has significant issues requiring attention"
        else:
            status = "CRITICAL"
            message = "Network has serious issues requiring immediate action"
        
        return {
            "health_score": health_score,
            "status": status,
            "message": message,
            "total_findings": total_findings,
            "issues_breakdown": {
                "critical_issues": critical_count,
                "warning_issues": warning_count,
                "total_issues": critical_count + warning_count
            }
        }
