"""
Main wireless PCAP analyzer orchestrator.

Simplified version that delegates to dual-pipeline analyzer for both
single and dual analysis modes.
"""

import logging
import time
from pathlib import Path
from typing import List, Optional, Dict, Any

from .core.models import (
    AnalysisError
)
from .core.enhanced_dual_pipeline_analyzer import EnhancedDualPipelineAnalyzer
from .core.analyzer_registry import analyzer_registry
from .expert.agent import WirelessExpertAgent


class WirelessPCAPAnalyzer:
    """
    Main analyzer class that orchestrates wireless PCAP analysis.
    
    This simplified version delegates to the enhanced dual-pipeline analyzer
    for all analysis tasks, supporting both single-parser and dual-parser modes.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the main analyzer.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.expert_agent = WirelessExpertAgent()
        self.dual_pipeline_analyzer = EnhancedDualPipelineAnalyzer(config)
        
        # Performance tracking  
        self.analysis_stats = {
            'total_analyses': 0,
            'total_dual_analyses': 0,
            'total_analysis_time': 0.0
        }
        
    def list_analyzers(self) -> List[Dict[str, Any]]:
        """
        Get list of all available analyzer pairs with metadata.
        
        Returns:
            List of analyzer pair information dictionaries
        """
        registry_info = analyzer_registry.get_registry_summary()
        analyzers_info = []
        
        for name, info in registry_info['analyzer_list'].items():
            analyzers_info.append({
                'name': name,
                'category': info['category'],
                'description': info['description'],
                'enabled': info['enabled'],
                'analysis_order': info['analysis_order']
            })
        
        return sorted(analyzers_info, key=lambda x: x['analysis_order'])
        
    def enable_analyzer(self, name: str) -> bool:
        """
        Enable a specific analyzer pair.
        
        Args:
            name: Analyzer name
            
        Returns:
            True if analyzer was found and enabled
        """
        success = analyzer_registry.enable_analyzer(name)
        if success:
            self.logger.info(f"Enabled analyzer pair: {name}")
        return success
        
    def disable_analyzer(self, name: str) -> bool:
        """
        Disable a specific analyzer pair.
        
        Args:
            name: Analyzer name
            
        Returns:
            True if analyzer was found and disabled
        """
        success = analyzer_registry.disable_analyzer(name)
        if success:
            self.logger.info(f"Disabled analyzer pair: {name}")
        return success
        
    def analyze_pcap(
        self, 
        pcap_file: str, 
        max_packets: Optional[int] = None,
        analyzers: Optional[List[str]] = None,
        parser_preference: str = 'scapy',
        debug_mode: bool = False,
        skip_validation: bool = False
    ) -> Dict[str, Any]:
        """
        Analyze a PCAP file using single parser preference.
        
        Args:
            pcap_file: Path to PCAP file
            max_packets: Maximum number of packets to analyze
            analyzers: List of specific analyzer names to run (None = all enabled)
            parser_preference: Preferred parser ('scapy' or 'pyshark')
            debug_mode: Enable debug logging
            skip_validation: Skip pre-analysis PCAP validation
            
        Returns:
            Analysis results from preferred parser
            
        Raises:
            AnalysisError: If analysis fails
        """
        self.logger.info(f"Starting pcap analysis from main analyzer")
        
        # Use the dual pipeline analyzer but run only one pipeline
        if parser_preference.lower() == 'pyshark':
            return self.dual_pipeline_analyzer.analyze_pcap_comprehensive(
                pcap_file=pcap_file,
                max_packets=max_packets,
                run_both=False,
                run_scapy=False,
                run_pyshark=True,
                specific_analyzers=analyzers,
                parallel_execution=False,
                debug_mode=debug_mode,
                skip_validation=skip_validation
            )
        else:
            return self.dual_pipeline_analyzer.analyze_pcap_comprehensive(
                pcap_file=pcap_file,
                max_packets=max_packets,
                run_both=False,
                run_scapy=True,
                run_pyshark=False,
                specific_analyzers=analyzers,
                parallel_execution=False,
                debug_mode=debug_mode,
                skip_validation=skip_validation
            )
    
    def analyze_pcap_dual_comparison(
        self,
        pcap_file: str,
        max_packets: Optional[int] = None,
        analyzer_categories: Optional[List[str]] = None,
        specific_analyzers: Optional[List[str]] = None,
        parallel_execution: bool = True,
        debug_mode: bool = False,
        skip_validation: bool = False
    ) -> Dict[str, Any]:
        """
        Analyze PCAP file using dual pipelines (Scapy and PyShark) for comparison.
        
        Args:
            pcap_file: Path to PCAP file
            max_packets: Maximum number of packets to analyze
            analyzer_categories: Filter to specific categories (baseline, security)
            specific_analyzers: Filter to specific analyzer names
            parallel_execution: Run pipelines in parallel when possible
            debug_mode: Enable debug logging
            skip_validation: Skip pre-analysis PCAP validation
            
        Returns:
            Comprehensive dual-pipeline analysis results with comparison
        """
        self.logger.info(f"Starting dual-pipeline comparison analysis of {pcap_file}")
        
        try:
            results = self.dual_pipeline_analyzer.analyze_pcap_comprehensive(
                pcap_file=pcap_file,
                max_packets=max_packets,
                run_both=True,
                run_scapy=True,
                run_pyshark=True,
                analyzer_categories=analyzer_categories,
                specific_analyzers=specific_analyzers,
                parallel_execution=parallel_execution,
                debug_mode=debug_mode,
                skip_validation=skip_validation
            )
            
            # Update stats
            self.analysis_stats['total_analyses'] += 1
            self.analysis_stats['total_dual_analyses'] += 1
            self.analysis_stats['total_analysis_time'] += results['performance']['total_analysis_time']
            
            self.logger.info(f"Dual-pipeline analysis complete with comparison data")
            return results
            
        except Exception as e:
            self.logger.error(f"Dual-pipeline analysis failed: {e}")
            raise AnalysisError(f"Dual-pipeline analysis failed: {e}") from e
    
    def get_analyzer_registry_info(self) -> Dict[str, Any]:
        """
        Get information about available analyzer pairs in the registry.
        
        Returns:
            Registry information with available analyzers
        """
        return self.dual_pipeline_analyzer.get_registry_info()
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """
        Get performance statistics.
        
        Returns:
            Performance statistics dictionary
        """
        return dict(self.analysis_stats)
    
    def validate_pcap_dual(
        self,
        pcap_file: str,
        quick_mode: bool = False,
        max_packets: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Validate a PCAP file using both Scapy and PyShark for comprehensive analysis.
        
        Args:
            pcap_file: Path to PCAP file
            quick_mode: Quick validation (limit packets if max_packets not specified)
            max_packets: Maximum packets to validate (overrides quick_mode)
            
        Returns:
            Comprehensive validation results from both parsers
        """
        self.logger.info(f"Starting dual-pipeline PCAP validation of {pcap_file}")
        
        # Determine packet limit
        if max_packets is None and quick_mode:
            max_packets = 1000
            
        try:
            results = self.dual_pipeline_analyzer.validate_pcap_comprehensive(
                pcap_file=pcap_file,
                max_packets=max_packets
            )
            
            self.logger.info(f"Dual-pipeline validation complete")
            return results
            
        except Exception as e:
            self.logger.error(f"Dual-pipeline validation failed: {e}")
            raise AnalysisError(f"Dual-pipeline validation failed: {e}") from e

    def generate_report(
        self, 
        results: Dict[str, Any], 
        output_format: str = 'json',
        include_expert_analysis: bool = True
    ) -> str:
        """
        Generate a formatted report of analysis results.
        
        Args:
            results: Analysis results (dual pipeline format)
            output_format: Output format ('json', 'html', 'text')  
            include_expert_analysis: Include expert agent analysis
            
        Returns:
            Formatted report string
        """
        import json
        
        if include_expert_analysis:
            # Combine findings from both pipelines for expert analysis
            combined_findings = []
            
            # Get findings from Scapy pipeline
            scapy_results = results.get('scapy_results', {})
            scapy_count = 0
            if scapy_results and scapy_results.get('success', False):
                scapy_findings = scapy_results.get('all_findings', [])
                scapy_count = len(scapy_findings)
                combined_findings.extend(scapy_findings)
                self.logger.debug(f"Added {scapy_count} findings from Scapy pipeline")
            
            # Get findings from PyShark pipeline  
            pyshark_results = results.get('pyshark_results', {})
            pyshark_count = 0
            if pyshark_results and pyshark_results.get('success', False):
                pyshark_findings = pyshark_results.get('all_findings', [])
                pyshark_count = len(pyshark_findings)
                combined_findings.extend(pyshark_findings)
                self.logger.debug(f"Added {pyshark_count} findings from PyShark pipeline")
            
            self.logger.info(f"Combined {scapy_count + pyshark_count} total findings for expert analysis")
            
            # Deduplicate findings based on category, severity, and title
            if combined_findings:
                deduplicated_findings = self._deduplicate_findings(combined_findings)
                self.logger.info(f"After deduplication: {len(deduplicated_findings)} unique findings")
                combined_findings = deduplicated_findings
            
            if combined_findings:
                # Create AnalysisResults object for expert agent
                from .core.models import AnalysisResults, AnalysisMetrics
                
                # Create enhanced metrics combining both pipelines
                combined_metrics = AnalysisMetrics()
                if scapy_results.get('metrics'):
                    combined_metrics.total_packets = scapy_results['metrics'].get('total_packets', 0)
                elif pyshark_results.get('metrics'):
                    combined_metrics.total_packets = pyshark_results['metrics'].get('total_packets', 0)
                
                # Get list of analyzers that actually ran
                analyzers_used = []
                if scapy_results.get('analyzers_run'):
                    analyzers_used.extend(scapy_results['analyzers_run'])
                if pyshark_results.get('analyzers_run'):
                    analyzers_used.extend(pyshark_results['analyzers_run'])
                
                expert_input = AnalysisResults(
                    pcap_file=results.get('pcap_file', ''),
                    findings=combined_findings,
                    metrics=combined_metrics,
                    analyzers_run=list(set(analyzers_used))  # Remove duplicates
                )
                
                self.logger.info(f"Sending {len(combined_findings)} findings from "
                               f"{len(set(analyzers_used))} unique analyzers to expert agent")
                
                try:
                    expert_summary = self.expert_agent.generate_executive_summary(expert_input)
                    results['expert_analysis'] = expert_summary
                    
                    # Log expert analysis summary
                    risk_score = expert_summary.get('risk_score', 0)
                    health_status = expert_summary.get('network_health', {}).get('status', 'UNKNOWN')
                    self.logger.info(f"Expert analysis complete: Risk Score {risk_score}, "
                                   f"Health Status {health_status}")
                    
                    # Also log the full expert text summary for easy reading
                    self._log_expert_text_summary(expert_summary)
                    
                except Exception as e:
                    import traceback
                    self.logger.error(f"Expert analysis failed: {e}")
                    self.logger.debug(f"Expert analysis traceback: {traceback.format_exc()}")
                    results['expert_analysis'] = {
                        'error': f'Expert analysis failed: {e}',
                        'findings_available': len(combined_findings),
                        'analyzers_available': len(set(analyzers_used))
                    }
            else:
                self.logger.info("No findings available for expert analysis")
                results['expert_analysis'] = {
                    'message': 'No findings available for expert analysis'
                }
            
        if output_format.lower() == 'json':
            return json.dumps(results, indent=2, default=str)
        elif output_format.lower() == 'html':
            return self._generate_html_report(results)
        elif output_format.lower() == 'markdown' or output_format.lower() == 'md':
            return self._generate_markdown_report(results)
        elif output_format.lower() == 'text' or output_format.lower() == 'txt':
            return self._generate_text_report(results)
        else:
            # Default to JSON for unknown formats
            return json.dumps(results, indent=2, default=str)
    
    def _deduplicate_findings(self, findings: List[Any]) -> List[Any]:
        """
        Deduplicate findings from both pipelines based on similarity.
        
        Args:
            findings: List of findings from both pipelines
            
        Returns:
            Deduplicated list of findings
        """
        unique_findings = []
        seen_signatures = set()
        
        for i, finding in enumerate(findings):
            try:
                # Create a signature for the finding
                # Handle both dict and Finding object formats
                if hasattr(finding, 'category'):
                    # Finding object - safely extract all fields
                    title = str(getattr(finding, 'title', 'Unknown'))
                    
                    # Safely extract category
                    try:
                        if hasattr(finding.category, 'value'):
                            category = finding.category.value
                        else:
                            category_str = str(finding.category)
                            if category_str in ['1.0', '1', '0.0', '0'] or (category_str.replace('.', '').isdigit() and '.' in category_str):
                                category = 'CORRUPTED_CATEGORY'
                                if i < 5:
                                    self.logger.warning(f"Found corrupted category '{category_str}' in finding '{title}' - analyzer needs fixing")
                            else:
                                category = category_str
                    except Exception as cat_e:
                        category = 'ERROR_CATEGORY'
                        if i < 3:
                            self.logger.error(f"Category extraction failed for finding {i}: {cat_e}")
                    
                    # Safely extract severity  
                    try:
                        if hasattr(finding.severity, 'value'):
                            severity = finding.severity.value
                        else:
                            severity = str(finding.severity)
                    except Exception as sev_e:
                        severity = 'ERROR_SEVERITY'
                        if i < 3:
                            self.logger.error(f"Severity extraction failed for finding {i}: {sev_e}")
                    
                    signature = f"{category}|{severity}|{title}"
                    
                    # Safely create finding_dict - avoid to_dict() if category is corrupted
                    if category == 'CORRUPTED_CATEGORY' or category == 'ERROR_CATEGORY':
                        # Don't call to_dict() on corrupted findings, create dict manually
                        finding_dict = {'title': title, 'category': category, 'severity': severity}
                    else:
                        try:
                            finding_dict = finding.to_dict() if hasattr(finding, 'to_dict') else finding
                        except Exception as dict_e:
                            finding_dict = {'title': title, 'category': category, 'severity': severity}
                            if i < 3:
                                self.logger.error(f"Finding.to_dict() failed for finding {i}: {dict_e}")
                else:
                    # Dict format
                    signature = f"{finding.get('category', '')}|{finding.get('severity', '')}|{finding.get('title', '')}"
                    finding_dict = finding
                
                if signature not in seen_signatures:
                    seen_signatures.add(signature)
                    unique_findings.append(finding)
                else:
                    self.logger.debug(f"Duplicate finding filtered: {finding_dict.get('title', 'Unknown')}")
                    
            except Exception as e:
                self.logger.error(f"Error processing finding {i}: {e}")
                self.logger.error(f"Finding type: {type(finding)}")
                if hasattr(finding, 'category'):
                    self.logger.error(f"Category type: {type(finding.category)}, value: {finding.category}")
                if hasattr(finding, 'severity'):
                    self.logger.error(f"Severity type: {type(finding.severity)}, value: {finding.severity}")
                # Skip this finding but continue processing
                continue
        
        return unique_findings
    
    def _generate_html_report(self, results: Dict[str, Any]) -> str:
        """Generate a human-readable HTML report."""
        from datetime import datetime
        
        # Extract key information
        pcap_file = results.get('pcap_file', 'Unknown')
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        expert_analysis = results.get('expert_analysis', {})
        
        # Build HTML report
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Wireless Network Analysis Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
               line-height: 1.6; color: #333; max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                   color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
                          gap: 20px; margin: 30px 0; }}
        .metric-card {{ background: #f8f9fa; border-left: 4px solid #007bff; padding: 20px; border-radius: 5px; }}
        .critical {{ border-left-color: #dc3545; }}
        .warning {{ border-left-color: #ffc107; }}
        .info {{ border-left-color: #17a2b8; }}
        .good {{ border-left-color: #28a745; }}
        .section {{ margin: 30px 0; }}
        .findings-list {{ background: #fff; border: 1px solid #dee2e6; border-radius: 8px; }}
        .finding-item {{ padding: 15px; border-bottom: 1px solid #eee; }}
        .finding-item:last-child {{ border-bottom: none; }}
        .severity-badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; 
                            color: white; font-size: 0.8em; font-weight: bold; }}
        .severity-critical {{ background-color: #dc3545; }}
        .severity-warning {{ background-color: #ffc107; color: #000; }}
        .severity-error {{ background-color: #fd7e14; }}
        .severity-info {{ background-color: #17a2b8; }}
        .recommendations {{ background: #e8f5e8; padding: 20px; border-radius: 8px; }}
        .rec-item {{ margin: 10px 0; padding: 10px; background: white; border-radius: 5px; }}
        h1, h2, h3 {{ color: #2c3e50; }}
        .health-score {{ font-size: 2em; font-weight: bold; }}
        .category-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px; }}
        .category-card {{ background: white; border: 1px solid #ddd; padding: 15px; border-radius: 8px; }}
        .status-critical {{ color: #dc3545; font-weight: bold; }}
        .status-concerning {{ color: #fd7e14; font-weight: bold; }}
        .status-attention {{ color: #ffc107; font-weight: bold; }}
        .status-ok {{ color: #28a745; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Wireless Network Security Analysis Report</h1>
        <p><strong>File:</strong> {pcap_file}</p>
        <p><strong>Generated:</strong> {timestamp}</p>
        <p><strong>Analysis Type:</strong> Dual Pipeline (Scapy + PyShark)</p>
    </div>
"""
        
        if expert_analysis:
            # Executive Summary
            html += self._generate_html_executive_summary(expert_analysis)
            
            # Detailed Analysis
            html += self._generate_html_detailed_analysis(results, expert_analysis)
        else:
            html += '<div class="section"><h2>❌ No Expert Analysis Available</h2><p>Expert analysis could not be generated for this capture.</p></div>'
        
        # Footer
        html += f"""
    <div class="section" style="border-top: 1px solid #ddd; padding-top: 20px; color: #6c757d; text-align: center;">
        <p>Generated by Wireless PCAP Analysis Framework | {timestamp}</p>
    </div>
</body>
</html>"""
        
        return html
    
    def _generate_html_executive_summary(self, expert_analysis: Dict[str, Any]) -> str:
        """Generate HTML executive summary section."""
        network_health = expert_analysis.get('network_health', {})
        findings_summary = expert_analysis.get('findings_summary', {})
        
        # Determine health color class
        health_status = network_health.get('status', 'UNKNOWN')
        health_class = {
            'EXCELLENT': 'good',
            'GOOD': 'good', 
            'FAIR': 'warning',
            'POOR': 'critical',
            'CRITICAL': 'critical'
        }.get(health_status, 'info')
        
        html = f"""
    <div class="section">
        <h2>📊 Executive Summary</h2>
        <div class="summary-grid">
            <div class="metric-card {health_class}">
                <h3>Network Health</h3>
                <div class="health-score">{network_health.get('health_score', 0)}/100</div>
                <p><strong>{health_status}</strong></p>
                <p>{network_health.get('message', 'No assessment available')}</p>
            </div>
            
            <div class="metric-card">
                <h3>Risk Assessment</h3>
                <div class="health-score">{expert_analysis.get('risk_score', 0)}/100</div>
                <p><strong>Risk Level</strong></p>
                <p>{expert_analysis.get('overall_assessment', 'No assessment available')}</p>
            </div>
            
            <div class="metric-card">
                <h3>Findings Overview</h3>
                <p><strong>Total Findings:</strong> {findings_summary.get('total_findings', 0)}</p>
                <p><span class="severity-badge severity-critical">Critical: {findings_summary.get('critical', 0)}</span></p>
                <p><span class="severity-badge severity-warning">Warning: {findings_summary.get('warning', 0)}</span></p>
                <p><span class="severity-badge severity-error">Error: {findings_summary.get('error', 0)}</span></p>
            </div>
        </div>
    </div>
"""
        
        # Priority Recommendations
        recommendations = expert_analysis.get('priority_recommendations', [])
        if recommendations:
            html += f"""
    <div class="section">
        <h2>🎯 Priority Recommendations</h2>
        <div class="recommendations">
"""
            for i, rec in enumerate(recommendations[:10], 1):
                html += f'            <div class="rec-item"><strong>{i}.</strong> {rec}</div>\n'
            
            html += """        </div>
    </div>
"""
        
        return html
    
    def _generate_html_detailed_analysis(self, results: Dict[str, Any], expert_analysis: Dict[str, Any]) -> str:
        """Generate detailed analysis sections."""
        html = ""
        
        # Category breakdown
        category_breakdown = expert_analysis.get('category_breakdown', {})
        if category_breakdown:
            html += """
    <div class="section">
        <h2>📋 Analysis by Category</h2>
        <div class="category-grid">
"""
            for category, data in category_breakdown.items():
                status = data.get('status', 'OK')
                status_class = {
                    'CRITICAL': 'status-critical',
                    'CONCERNING': 'status-concerning', 
                    'ATTENTION_NEEDED': 'status-attention',
                    'INFORMATIONAL': 'status-ok',
                    'OK': 'status-ok'
                }.get(status, 'status-ok')
                
                category_name = category.replace('_', ' ').title()
                html += f"""
            <div class="category-card">
                <h4>{category_name}</h4>
                <p class="{status_class}">Status: {status}</p>
                <p><strong>Total:</strong> {data.get('total_findings', 0)} findings</p>
                <p><strong>Critical:</strong> {data.get('critical', 0)} | <strong>Warning:</strong> {data.get('warning', 0)}</p>
"""
                top_issues = data.get('top_issues', [])
                if top_issues:
                    html += "                <p><strong>Top Issues:</strong></p><ul>"
                    for issue in top_issues[:3]:
                        html += f"<li>{issue}</li>"
                    html += "</ul>"
                
                html += "            </div>\n"
            
            html += """        </div>
    </div>
"""
        
        # Key concerns
        key_concerns = expert_analysis.get('key_concerns', [])
        if key_concerns:
            html += f"""
    <div class="section">
        <h2>⚠️ Key Concerns</h2>
        <div class="findings-list">
"""
            for concern in key_concerns[:10]:
                html += f"""            <div class="finding-item">• {concern}</div>\n"""
            
            html += """        </div>
    </div>
"""
        
        return html
    
    def _generate_markdown_report(self, results: Dict[str, Any]) -> str:
        """Generate a markdown report."""
        from datetime import datetime
        
        pcap_file = results.get('pcap_file', 'Unknown')
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        expert_analysis = results.get('expert_analysis', {})
        
        md = f"""# 🛡️ Wireless Network Security Analysis Report

**File:** {pcap_file}  
**Generated:** {timestamp}  
**Analysis Type:** Dual Pipeline (Scapy + PyShark)

---

"""
        
        if expert_analysis:
            md += self._generate_markdown_executive_summary(expert_analysis)
            md += self._generate_markdown_detailed_analysis(expert_analysis)
        else:
            md += "## ❌ No Expert Analysis Available\n\nExpert analysis could not be generated for this capture.\n\n"
        
        md += f"---\n\n*Generated by Wireless PCAP Analysis Framework | {timestamp}*\n"
        
        return md
    
    def _generate_markdown_executive_summary(self, expert_analysis: Dict[str, Any]) -> str:
        """Generate markdown executive summary."""
        network_health = expert_analysis.get('network_health', {})
        findings_summary = expert_analysis.get('findings_summary', {})
        
        md = f"""## 📊 Executive Summary

| Metric | Score | Status |
|--------|-------|--------|
| **Network Health** | {network_health.get('health_score', 0)}/100 | {network_health.get('status', 'UNKNOWN')} |
| **Risk Level** | {expert_analysis.get('risk_score', 0)}/100 | {expert_analysis.get('overall_assessment', 'No assessment')[:50]}... |
| **Total Findings** | {findings_summary.get('total_findings', 0)} | Critical: {findings_summary.get('critical', 0)}, Warning: {findings_summary.get('warning', 0)} |

### Overall Assessment
{expert_analysis.get('overall_assessment', 'No assessment available')}

### Network Health
{network_health.get('message', 'No health assessment available')}

"""
        
        # Priority Recommendations
        recommendations = expert_analysis.get('priority_recommendations', [])
        if recommendations:
            md += "## 🎯 Priority Recommendations\n\n"
            for i, rec in enumerate(recommendations[:10], 1):
                md += f"{i}. {rec}\n"
            md += "\n"
        
        return md
    
    def _generate_markdown_detailed_analysis(self, expert_analysis: Dict[str, Any]) -> str:
        """Generate detailed markdown analysis."""
        md = ""
        
        # Category breakdown
        category_breakdown = expert_analysis.get('category_breakdown', {})
        if category_breakdown:
            md += "## 📋 Analysis by Category\n\n"
            md += "| Category | Status | Findings | Critical | Warning | Top Issues |\n"
            md += "|----------|--------|----------|----------|---------|------------|\n"
            
            for category, data in category_breakdown.items():
                category_name = category.replace('_', ' ').title()
                top_issues = ', '.join(data.get('top_issues', [])[:2])
                if len(top_issues) > 50:
                    top_issues = top_issues[:47] + "..."
                
                md += f"| {category_name} | {data.get('status', 'OK')} | {data.get('total_findings', 0)} | {data.get('critical', 0)} | {data.get('warning', 0)} | {top_issues} |\n"
            
            md += "\n"
        
        # Key concerns
        key_concerns = expert_analysis.get('key_concerns', [])
        if key_concerns:
            md += "## ⚠️ Key Concerns\n\n"
            for concern in key_concerns[:10]:
                md += f"- {concern}\n"
            md += "\n"
        
        return md
    
    def _generate_text_report(self, results: Dict[str, Any]) -> str:
        """Generate a plain text report."""
        from datetime import datetime
        
        pcap_file = results.get('pcap_file', 'Unknown')
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        expert_analysis = results.get('expert_analysis', {})
        
        text = f"""
========================================================================
           WIRELESS NETWORK SECURITY ANALYSIS REPORT
========================================================================

File: {pcap_file}
Generated: {timestamp}
Analysis Type: Dual Pipeline (Scapy + PyShark)

"""
        
        if expert_analysis:
            text += self._generate_text_executive_summary(expert_analysis)
            text += self._generate_text_detailed_analysis(expert_analysis)
        else:
            text += """
NO EXPERT ANALYSIS AVAILABLE
============================

Expert analysis could not be generated for this capture.

"""
        
        text += f"""
========================================================================
Generated by Wireless PCAP Analysis Framework | {timestamp}
========================================================================
"""
        
        return text
    
    def _generate_text_executive_summary(self, expert_analysis: Dict[str, Any]) -> str:
        """Generate text executive summary."""
        network_health = expert_analysis.get('network_health', {})
        findings_summary = expert_analysis.get('findings_summary', {})
        
        text = f"""
EXECUTIVE SUMMARY
================

Network Health Score: {network_health.get('health_score', 0)}/100 ({network_health.get('status', 'UNKNOWN')})
Risk Level: {expert_analysis.get('risk_score', 0)}/100

Overall Assessment:
{expert_analysis.get('overall_assessment', 'No assessment available')}

Network Health:
{network_health.get('message', 'No health assessment available')}

Findings Summary:
- Total Findings: {findings_summary.get('total_findings', 0)}
- Critical: {findings_summary.get('critical', 0)}
- Warning: {findings_summary.get('warning', 0)}
- Error: {findings_summary.get('error', 0)}
- Info: {findings_summary.get('info', 0)}

"""
        
        # Priority Recommendations
        recommendations = expert_analysis.get('priority_recommendations', [])
        if recommendations:
            text += "PRIORITY RECOMMENDATIONS\n"
            text += "=======================\n\n"
            for i, rec in enumerate(recommendations[:10], 1):
                text += f"{i:2}. {rec}\n"
            text += "\n"
        
        return text
    
    def _generate_text_detailed_analysis(self, expert_analysis: Dict[str, Any]) -> str:
        """Generate detailed text analysis."""
        text = ""
        
        # Category breakdown
        category_breakdown = expert_analysis.get('category_breakdown', {})
        if category_breakdown:
            text += "ANALYSIS BY CATEGORY\n"
            text += "===================\n\n"
            
            for category, data in category_breakdown.items():
                category_name = category.replace('_', ' ').title()
                text += f"{category_name}:\n"
                text += f"  Status: {data.get('status', 'OK')}\n"
                text += f"  Total Findings: {data.get('total_findings', 0)}\n"
                text += f"  Critical: {data.get('critical', 0)} | Warning: {data.get('warning', 0)}\n"
                
                top_issues = data.get('top_issues', [])
                if top_issues:
                    text += "  Top Issues:\n"
                    for issue in top_issues[:3]:
                        text += f"    - {issue}\n"
                text += "\n"
        
        # Key concerns
        key_concerns = expert_analysis.get('key_concerns', [])
        if key_concerns:
            text += "KEY CONCERNS\n"
            text += "============\n\n"
            for i, concern in enumerate(key_concerns[:10], 1):
                text += f"{i:2}. {concern}\n"
            text += "\n"
        
        return text
    
    def _log_expert_text_summary(self, expert_analysis: Dict[str, Any]) -> None:
        """
        Log the expert text summary to the console/logs for immediate visibility.
        
        Args:
            expert_analysis: Expert analysis results
        """
        try:
            # Generate a condensed version of the text summary for logs
            network_health = expert_analysis.get('network_health', {})
            findings_summary = expert_analysis.get('findings_summary', {})
            
            # Log header
            self.logger.info("=" * 70)
            self.logger.info("                    EXPERT ANALYSIS SUMMARY")
            self.logger.info("=" * 70)
            
            # Network health and risk
            health_score = network_health.get('health_score', 0)
            health_status = network_health.get('status', 'UNKNOWN')
            risk_score = expert_analysis.get('risk_score', 0)
            
            self.logger.info(f"Network Health: {health_score}/100 ({health_status})")
            self.logger.info(f"Risk Level: {risk_score}/100")
            self.logger.info("")
            
            # Overall assessment
            assessment = expert_analysis.get('overall_assessment', 'No assessment available')
            self.logger.info(f"Assessment: {assessment}")
            self.logger.info("")
            
            # Findings breakdown
            total = findings_summary.get('total_findings', 0)
            critical = findings_summary.get('critical', 0)
            warning = findings_summary.get('warning', 0)
            error = findings_summary.get('error', 0)
            
            self.logger.info(f"Findings: {total} total ({critical} critical, {warning} warning, {error} error)")
            self.logger.info("")
            
            # Top priority recommendations (first 5)
            recommendations = expert_analysis.get('priority_recommendations', [])
            if recommendations:
                self.logger.info("TOP PRIORITY RECOMMENDATIONS:")
                for i, rec in enumerate(recommendations[:5], 1):
                    self.logger.info(f"  {i}. {rec}")
                if len(recommendations) > 5:
                    self.logger.info(f"  ... and {len(recommendations) - 5} more recommendations")
                self.logger.info("")
            
            # Key concerns (first 5)
            key_concerns = expert_analysis.get('key_concerns', [])
            if key_concerns:
                self.logger.info("KEY CONCERNS:")
                for i, concern in enumerate(key_concerns[:5], 1):
                    self.logger.info(f"  • {concern}")
                if len(key_concerns) > 5:
                    self.logger.info(f"  ... and {len(key_concerns) - 5} more concerns")
                self.logger.info("")
            
            # Category status summary
            category_breakdown = expert_analysis.get('category_breakdown', {})
            if category_breakdown:
                critical_categories = []
                concerning_categories = []
                
                for category, data in category_breakdown.items():
                    status = data.get('status', 'OK')
                    if status == 'CRITICAL':
                        critical_categories.append(category.replace('_', ' ').title())
                    elif status in ['CONCERNING', 'ATTENTION_NEEDED']:
                        concerning_categories.append(category.replace('_', ' ').title())
                
                if critical_categories:
                    self.logger.info(f"CRITICAL AREAS: {', '.join(critical_categories)}")
                if concerning_categories:
                    self.logger.info(f"NEEDS ATTENTION: {', '.join(concerning_categories)}")
                if critical_categories or concerning_categories:
                    self.logger.info("")
            
            # Footer
            self.logger.info("=" * 70)
            self.logger.info("Use --format text/html/markdown for detailed reports")
            self.logger.info("=" * 70)
            
        except Exception as e:
            self.logger.error(f"Failed to log expert summary: {e}")
            # Don't fail the whole analysis if logging fails