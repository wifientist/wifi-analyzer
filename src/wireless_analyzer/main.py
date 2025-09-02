"""
Main wireless PCAP analyzer orchestrator.

This module coordinates the execution of all registered analyzers
and manages the overall analysis workflow.
"""

import logging
import time
from pathlib import Path
from typing import List, Optional, Dict, Any
import statistics

from scapy.all import rdpcap, Packet

from .core.models import (
    AnalysisResults, 
    AnalysisContext, 
    AnalysisMetrics,
    NetworkEntity,
    Finding,
    Severity,
    AnalysisCategory,
    AnalysisError,
    PacketParsingError
)
from .core.base_analyzer import BaseAnalyzer, AnalyzerRegistry
from .utils.packet_utils import PacketAnalyzer
from .expert.agent import WirelessExpertAgent


class WirelessPCAPAnalyzer:
    """
    Main analyzer class that orchestrates all analysis modules.
    
    This class manages the overall analysis workflow:
    1. Load and validate PCAP files
    2. Initialize analysis context
    3. Run all enabled analyzers in order
    4. Collect and consolidate results
    5. Generate expert recommendations
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
        self.registry = AnalyzerRegistry()
        self.packet_analyzer = PacketAnalyzer()
        self.expert_agent = WirelessExpertAgent()
        
        # Performance tracking
        self.analysis_stats = {
            'total_analyses': 0,
            'total_packets_processed': 0,
            'total_analysis_time': 0.0,
            'analyzer_performance': {}
        }
        
        # Auto-discover and register analyzers
        self._register_default_analyzers()
        
    def _register_default_analyzers(self):
        """Register default analyzers."""
        try:
            # Import and register core analyzers
            from .analyzers.security.deauth_detector import DeauthFloodDetector
            
            self.registry.register(DeauthFloodDetector())
            
            self.logger.info(f"Registered {len(self.registry.get_all_analyzers())} analyzers")
            
        except ImportError as e:
            self.logger.warning(f"Could not import some analyzers: {e}")
            
    def register_analyzer(self, analyzer: BaseAnalyzer) -> None:
        """
        Register a new analyzer.
        
        Args:
            analyzer: Analyzer instance to register
        """
        self.registry.register(analyzer)
        self.logger.info(f"Registered analyzer: {analyzer.name}")
        
    def list_analyzers(self) -> List[Dict[str, Any]]:
        """
        Get list of all registered analyzers with metadata.
        
        Returns:
            List of analyzer information dictionaries
        """
        analyzers_info = []
        for analyzer in self.registry.get_all_analyzers():
            info = {
                'name': analyzer.name,
                'category': analyzer.category.value,
                'version': analyzer.version,
                'enabled': analyzer.enabled,
                'description': analyzer.description,
                'analysis_order': analyzer.analysis_order,
                'wireshark_filters': analyzer.get_display_filters(),
                'dependencies': analyzer.get_dependencies()
            }
            analyzers_info.append(info)
            
        return sorted(analyzers_info, key=lambda x: x['analysis_order'])
        
    def enable_analyzer(self, name: str) -> bool:
        """
        Enable a specific analyzer.
        
        Args:
            name: Analyzer name
            
        Returns:
            True if analyzer was found and enabled
        """
        analyzer = self.registry.get_analyzer(name)
        if analyzer:
            analyzer.enabled = True
            self.logger.info(f"Enabled analyzer: {name}")
            return True
        return False
        
    def disable_analyzer(self, name: str) -> bool:
        """
        Disable a specific analyzer.
        
        Args:
            name: Analyzer name
            
        Returns:
            True if analyzer was found and disabled
        """
        analyzer = self.registry.get_analyzer(name)
        if analyzer:
            analyzer.enabled = False
            self.logger.info(f"Disabled analyzer: {name}")
            return True
        return False
        
    def analyze_pcap(
        self, 
        pcap_file: str, 
        max_packets: Optional[int] = None,
        analyzers: Optional[List[str]] = None
    ) -> AnalysisResults:
        """
        Analyze a PCAP file and return comprehensive results.
        
        Args:
            pcap_file: Path to PCAP file
            max_packets: Maximum number of packets to analyze
            analyzers: List of specific analyzer names to run (None = all enabled)
            
        Returns:
            Comprehensive analysis results
            
        Raises:
            AnalysisError: If analysis fails
            PacketParsingError: If PCAP parsing fails
        """
        start_time = time.time()
        self.logger.info(f"Starting analysis of {pcap_file}")
        
        try:
            # Validate file
            pcap_path = Path(pcap_file)
            if not pcap_path.exists():
                raise AnalysisError(f"PCAP file not found: {pcap_file}")
                
            # Load packets
            packets = self._load_packets(pcap_file, max_packets)
            self.logger.info(f"Loaded {len(packets)} packets")
            
            # Initialize results and context
            results = AnalysisResults(pcap_file=pcap_file)
            context = self._create_analysis_context(pcap_file, packets)
            
            # Gather basic metrics
            results.metrics = self._gather_basic_metrics(packets, context)
            
            # Get analyzers to run
            analyzers_to_run = self._get_analyzers_to_run(analyzers)
            self.logger.info(f"Running {len(analyzers_to_run)} analyzers")
            
            # Run analyzers
            all_findings = []
            for analyzer in analyzers_to_run:
                try:
                    analyzer_start = time.time()
                    
                    # Pre-analysis setup
                    analyzer.pre_analysis_setup(context)
                    
                    # Filter applicable packets
                    applicable_packets = [
                        p for p in packets 
                        if analyzer.is_applicable(p)
                    ]
                    
                    self.logger.debug(
                        f"Running {analyzer.name} on {len(applicable_packets)} applicable packets"
                    )
                    
                    # Run analysis
                    findings = analyzer.analyze(applicable_packets, context)
                    
                    # Post-analysis cleanup
                    analyzer.post_analysis_cleanup(context)
                    
                    # Track performance
                    analyzer_time = time.time() - analyzer_start
                    analyzer.processing_time = analyzer_time
                    analyzer.packets_processed = len(applicable_packets)
                    
                    # Add findings
                    all_findings.extend(findings)
                    results.analyzers_run.append(analyzer.name)
                    
                    self.logger.info(
                        f"{analyzer.name}: {len(findings)} findings in {analyzer_time:.2f}s"
                    )
                    
                except Exception as e:
                    self.logger.error(f"Error in {analyzer.name}: {e}")
                    
                    # Create error finding
                    error_finding = Finding(
                        category=AnalysisCategory.ANOMALY_DETECTION,
                        severity=Severity.ERROR,
                        title=f"Analyzer Error: {analyzer.name}",
                        description=f"Error occurred during analysis: {str(e)}",
                        details={
                            "analyzer": analyzer.name,
                            "error_type": type(e).__name__,
                            "error_message": str(e)
                        },
                        analyzer_name=analyzer.name,
                        analyzer_version=analyzer.version
                    )
                    all_findings.append(error_finding)
                    
            # Add all findings to results
            results.findings = all_findings
            
            # Extract network entities from context
            results.network_entities = context.network_entities
            
            # Store analysis configuration
            results.analysis_config = {
                'max_packets': max_packets,
                'analyzers_requested': analyzers,
                'config': self.config
            }
            
            # Update performance stats
            total_time = time.time() - start_time
            results.metrics.analysis_duration_seconds = total_time
            
            self._update_performance_stats(total_time, len(packets), analyzers_to_run)
            
            self.logger.info(
                f"Analysis complete: {len(all_findings)} findings in {total_time:.2f}s"
            )
            
            return results
            
        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            raise AnalysisError(f"Analysis failed: {e}") from e
            
    def _load_packets(self, pcap_file: str, max_packets: Optional[int]) -> List[Packet]:
        """
        Load packets from PCAP file.
        
        Args:
            pcap_file: Path to PCAP file
            max_packets: Maximum packets to load
            
        Returns:
            List of packets
            
        Raises:
            PacketParsingError: If PCAP parsing fails
        """
        try:
            packets = rdpcap(pcap_file)
            
            if max_packets and len(packets) > max_packets:
                self.logger.info(f"Limiting to {max_packets} packets (total: {len(packets)})")
                packets = packets[:max_packets]
                
            return packets
            
        except Exception as e:
            raise PacketParsingError(f"Failed to load PCAP file {pcap_file}: {e}") from e
            
    def _create_analysis_context(self, pcap_file: str, packets: List[Packet]) -> AnalysisContext:
        """
        Create analysis context from packets.
        
        Args:
            pcap_file: Path to PCAP file
            packets: List of packets
            
        Returns:
            Analysis context
        """
        if not packets:
            return AnalysisContext(
                pcap_file=pcap_file,
                packet_count=0,
                start_time=0,
                end_time=0,
                duration=0,
                config=self.config
            )
            
        # Extract timing info
        timestamps = [getattr(p, 'time', 0) for p in packets if hasattr(p, 'time')]
        
        if timestamps:
            start_time = min(timestamps)
            end_time = max(timestamps)
            duration = end_time - start_time
        else:
            start_time = end_time = duration = 0
            
        context = AnalysisContext(
            pcap_file=pcap_file,
            packet_count=len(packets),
            start_time=start_time,
            end_time=end_time,
            duration=duration,
            config=self.config
        )
        
        # Pre-populate network entities
        self._extract_network_entities(packets, context)
        
        return context
        
    def _extract_network_entities(self, packets: List[Packet], context: AnalysisContext) -> None:
        """
        Extract network entities from packets.
        
        Args:
            packets: List of packets
            context: Analysis context to populate
        """
        # Use packet analyzer utility to extract entities
        entities = self.packet_analyzer.extract_network_entities(packets)
        
        for entity in entities:
            context.add_entity(entity)
            
    def _gather_basic_metrics(self, packets: List[Packet], context: AnalysisContext) -> AnalysisMetrics:
        """
        Gather basic metrics from packets.
        
        Args:
            packets: List of packets
            context: Analysis context
            
        Returns:
            Analysis metrics
        """
        metrics = AnalysisMetrics()
        
        # Basic counts
        metrics.total_packets = len(packets)
        metrics.capture_duration_seconds = context.duration
        
        # Use packet analyzer to get detailed metrics
        detailed_metrics = self.packet_analyzer.analyze_packet_distribution(packets)
        
        # Update metrics object
        metrics.management_frames = detailed_metrics.get('management_frames', 0)
        metrics.control_frames = detailed_metrics.get('control_frames', 0)
        metrics.data_frames = detailed_metrics.get('data_frames', 0)
        
        metrics.beacon_frames = detailed_metrics.get('beacon_frames', 0)
        metrics.probe_requests = detailed_metrics.get('probe_requests', 0)
        metrics.probe_responses = detailed_metrics.get('probe_responses', 0)
        metrics.auth_frames = detailed_metrics.get('auth_frames', 0)
        metrics.assoc_frames = detailed_metrics.get('assoc_frames', 0)
        metrics.deauth_frames = detailed_metrics.get('deauth_frames', 0)
        metrics.disassoc_frames = detailed_metrics.get('disassoc_frames', 0)
        metrics.eapol_frames = detailed_metrics.get('eapol_frames', 0)
        
        metrics.fcs_errors = detailed_metrics.get('fcs_errors', 0)
        metrics.retry_frames = detailed_metrics.get('retry_frames', 0)
        
        metrics.unique_aps = len([e for e in context.network_entities.values() 
                                if e.entity_type == 'ap'])
        metrics.unique_stations = len([e for e in context.network_entities.values() 
                                     if e.entity_type == 'sta'])
        
        metrics.channels_observed = set(detailed_metrics.get('channels', []))
        metrics.frequency_bands = set(detailed_metrics.get('bands', []))
        
        # Timing
        if context.start_time > 0:
            from datetime import datetime
            metrics.first_packet_time = datetime.fromtimestamp(context.start_time)
            metrics.last_packet_time = datetime.fromtimestamp(context.end_time)
            
        return metrics
        
    def _get_analyzers_to_run(self, analyzer_names: Optional[List[str]]) -> List[BaseAnalyzer]:
        """
        Get list of analyzers to run.
        
        Args:
            analyzer_names: Specific analyzer names or None for all enabled
            
        Returns:
            List of analyzers to run
        """
        if analyzer_names is None:
            # Run all enabled analyzers
            return self.registry.get_enabled_analyzers()
        else:
            # Run specific analyzers
            analyzers = []
            for name in analyzer_names:
                analyzer = self.registry.get_analyzer(name)
                if analyzer and analyzer.enabled:
                    analyzers.append(analyzer)
                elif analyzer:
                    self.logger.warning(f"Analyzer {name} is disabled")
                else:
                    self.logger.error(f"Unknown analyzer: {name}")
                    
            return sorted(analyzers, key=lambda x: x.analysis_order)
            
    def _update_performance_stats(
        self, 
        analysis_time: float, 
        packet_count: int, 
        analyzers: List[BaseAnalyzer]
    ) -> None:
        """
        Update performance statistics.
        
        Args:
            analysis_time: Total analysis time
            packet_count: Number of packets processed
            analyzers: List of analyzers that ran
        """
        self.analysis_stats['total_analyses'] += 1
        self.analysis_stats['total_packets_processed'] += packet_count
        self.analysis_stats['total_analysis_time'] += analysis_time
        
        for analyzer in analyzers:
            if analyzer.name not in self.analysis_stats['analyzer_performance']:
                self.analysis_stats['analyzer_performance'][analyzer.name] = {
                    'total_runs': 0,
                    'total_time': 0.0,
                    'total_packets': 0,
                    'total_findings': 0
                }
                
            perf = self.analysis_stats['analyzer_performance'][analyzer.name]
            perf['total_runs'] += 1
            perf['total_time'] += analyzer.processing_time
            perf['total_packets'] += analyzer.packets_processed
            perf['total_findings'] += analyzer.findings_generated
            
    def get_performance_stats(self) -> Dict[str, Any]:
        """
        Get performance statistics.
        
        Returns:
            Performance statistics dictionary
        """
        stats = dict(self.analysis_stats)
        
        # Calculate averages
        if stats['total_analyses'] > 0:
            stats['average_analysis_time'] = stats['total_analysis_time'] / stats['total_analyses']
            stats['average_packets_per_analysis'] = stats['total_packets_processed'] / stats['total_analyses']
            
        # Calculate analyzer averages
        for analyzer_name, perf in stats['analyzer_performance'].items():
            if perf['total_runs'] > 0:
                perf['average_time_per_run'] = perf['total_time'] / perf['total_runs']
                perf['average_packets_per_run'] = perf['total_packets'] / perf['total_runs']
                perf['average_findings_per_run'] = perf['total_findings'] / perf['total_runs']
                
        return stats
        
    def generate_report(
        self, 
        results: AnalysisResults, 
        output_format: str = 'json',
        include_expert_analysis: bool = True
    ) -> str:
        """
        Generate a formatted report of analysis results.
        
        Args:
            results: Analysis results
            output_format: Output format ('json', 'html', 'text')
            include_expert_analysis: Include expert agent analysis
            
        Returns:
            Formatted report string
        """
        if include_expert_analysis:
            # Get expert analysis
            expert_summary = self.expert_agent.generate_executive_summary(results)
            results.metadata['expert_summary'] = expert_summary
            
        if output_format.lower() == 'json':
            return results.to_json(indent=2)
        elif output_format.lower() == 'html':
            return self._generate_html_report(results)
        elif output_format.lower() == 'text':
            return self._generate_text_report(results)
        else:
            raise ValueError(f"Unsupported output format: {output_format}")
            
    def _generate_html_report(self, results: AnalysisResults) -> str:
        """Generate HTML report (placeholder)."""
        # TODO: Implement HTML report generation
        return f"<html><body><h1>Analysis Report</h1><pre>{results.to_json(indent=2)}</pre></body></html>"
        
    def _generate_text_report(self, results: AnalysisResults) -> str:
        """Generate text report (placeholder)."""
        # TODO: Implement text report generation
        summary = results.get_summary_stats()
        
        report = f"""
Wireless PCAP Analysis Report
============================

File: {results.pcap_file}
Analysis Time: {results.analysis_timestamp}
Duration: {results.metrics.analysis_duration_seconds:.2f} seconds

Summary Statistics:
- Total Packets: {results.metrics.total_packets}
- Capture Duration: {results.metrics.capture_duration_seconds:.2f} seconds
- Total Findings: {summary['total_findings']}
- Network Entities: {summary['network_entities']}
- Analyzers Run: {summary['analyzers_run']}

Findings by Severity:
"""
        
        for severity, count in summary['findings_by_severity'].items():
            if count > 0:
                report += f"- {severity.upper()}: {count}\n"
                
        report += "\nFindings by Category:\n"
        for category, count in summary['findings_by_category'].items():
            if count > 0:
                report += f"- {category}: {count}\n"
                
        # Add critical findings
        critical_findings = results.get_findings_by_severity(Severity.CRITICAL)
        if critical_findings:
            report += f"\nCritical Findings ({len(critical_findings)}):\n"
            for finding in critical_findings[:5]:  # Top 5
                report += f"- {finding.title}\n"
                
        return report
