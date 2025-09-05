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
from .core.enhanced_dual_pipeline_analyzer import EnhancedDualPipelineAnalyzer
from .core.analyzer_registry import analyzer_registry
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
        parser_preference: str = 'scapy'
    ) -> Dict[str, Any]:
        """
        Analyze a PCAP file using single parser preference.
        
        Args:
            pcap_file: Path to PCAP file
            max_packets: Maximum number of packets to analyze
            analyzers: List of specific analyzer names to run (None = all enabled)
            parser_preference: Preferred parser ('scapy' or 'pyshark')
            
        Returns:
            Analysis results from preferred parser
            
        Raises:
            AnalysisError: If analysis fails
        """
        self.logger.info(f"Starting single-pipeline analysis with {parser_preference}")
        
        # Use the dual pipeline analyzer but run only one pipeline
        if parser_preference.lower() == 'pyshark':
            return self.dual_pipeline_analyzer.analyze_pcap_comprehensive(
                pcap_file=pcap_file,
                max_packets=max_packets,
                run_both=False,
                run_scapy=False,
                run_pyshark=True,
                specific_analyzers=analyzers,
                parallel_execution=False
            )
        else:
            return self.dual_pipeline_analyzer.analyze_pcap_comprehensive(
                pcap_file=pcap_file,
                max_packets=max_packets,
                run_both=False,
                run_scapy=True,
                run_pyshark=False,
                specific_analyzers=analyzers,
                parallel_execution=False
            )
    
    def analyze_pcap_dual_comparison(
        self,
        pcap_file: str,
        max_packets: Optional[int] = None,
        analyzer_categories: Optional[List[str]] = None,
        specific_analyzers: Optional[List[str]] = None,
        parallel_execution: bool = True,
        debug_mode: bool = False
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
                debug_mode=debug_mode
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
    
    def _is_packet_applicable(self, unified_packet: UnifiedPacketInfo, analyzer: BaseAnalyzer) -> bool:
        """Check if unified packet is applicable to analyzer."""
        # For analyzers expecting raw packets, we need to check using the raw packet
        if unified_packet.raw_packet is None:
            return False
            
        # Try the analyzer's is_applicable method with the raw packet
        try:
            return analyzer.is_applicable(unified_packet.raw_packet)
        except Exception as e:
            # If the analyzer's method fails, fall back to frame type checking
            self.logger.debug(f"Analyzer {analyzer.name} is_applicable failed: {e}")
            
            # Basic frame type compatibility check based on analyzer name/category
            analyzer_name = analyzer.name.lower()
            frame_name = unified_packet.frame_name.lower()
            
            # Common mappings
            if "beacon" in analyzer_name and "beacon" in frame_name:
                return True
            elif "deauth" in analyzer_name and "deauth" in frame_name:
                return True
            elif "probe" in analyzer_name and "probe" in frame_name:
                return True
            elif "security" in analyzer_name and unified_packet.frame_type == 0:  # Management frames
                return True
            elif "signal" in analyzer_name and unified_packet.rssi is not None:  # Has RSSI data
                return True
                
            return False
    
    def _run_analyzer_with_retry(
        self, 
        analyzer: BaseAnalyzer, 
        current_packets: List[UnifiedPacketInfo], 
        context: AnalysisContext,
        pcap_file: str,
        max_packets: Optional[int]
    ) -> List[Finding]:
        """
        Run analyzer with adaptive retry using different parsers if needed.
        
        Args:
            analyzer: Analyzer to run
            current_packets: Currently loaded unified packets
            context: Analysis context
            pcap_file: Path to PCAP file for retry loading
            max_packets: Maximum packets to load
            
        Returns:
            List of findings from successful analysis
        """
        # Update retry statistics
        self.retry_stats['total_analyzers_run'] += 1
        
        # First attempt with current packets
        result = self._attempt_analyzer_run(analyzer, current_packets, context, attempt=1)
        
        if result['success'] and not self._should_retry_with_different_parser(result):
            # First attempt succeeded and results are satisfactory
            return result['findings']
        
        # Determine if we should retry with a different parser
        if self._should_retry_with_different_parser(result):
            self.retry_stats['analyzers_retried'] += 1
            
            original_parser = current_packets[0].parsing_library if current_packets else 'unknown'
            self.logger.warning(
                f"{analyzer.name}: Poor results with {original_parser} parser. "
                f"Attempting retry with alternative parser."
            )
            
            # Try alternative parsers
            retry_findings = self._retry_with_alternative_parsers(
                analyzer, pcap_file, max_packets, context, 
                current_library=original_parser
            )
            
            if retry_findings:
                self.retry_stats['successful_retries'] += 1
                return retry_findings
            else:
                self.retry_stats['failed_retries'] += 1
        
        # If we get here, return whatever we got from the first attempt (might be error findings)
        return result['findings']
    
    def _attempt_analyzer_run(
        self, 
        analyzer: BaseAnalyzer, 
        unified_packets: List[UnifiedPacketInfo], 
        context: AnalysisContext, 
        attempt: int = 1
    ) -> Dict[str, Any]:
        """
        Attempt to run analyzer and evaluate the results.
        
        Returns:
            Dict with 'success', 'findings', 'quality_metrics' keys
        """
        result = {
            'success': False,
            'findings': [],
            'quality_metrics': {},
            'error': None
        }
        
        try:
            analyzer_start = time.time()
            
            # Pre-analysis setup
            analyzer.pre_analysis_setup(context)
            
            # Filter applicable packets
            applicable_packets = [
                p.raw_packet for p in unified_packets 
                if self._is_packet_applicable(p, analyzer)
            ]
            
            self.logger.info(
                f"Attempt {attempt}: Running {analyzer.name} on {len(applicable_packets)} applicable packets "
                f"(out of {len(unified_packets)} total packets)"
            )
            
            # Check for critically low applicable packet count
            if len(applicable_packets) == 0:
                result['error'] = "No applicable packets found"
                result['quality_metrics']['applicable_packet_rate'] = 0.0
                return result
            
            applicable_rate = len(applicable_packets) / len(unified_packets) if unified_packets else 0
            result['quality_metrics']['applicable_packet_rate'] = applicable_rate
            
            # Log concerns about low applicability
            if applicable_rate < 0.05:  # Less than 5% applicable
                self.logger.warning(
                    f"{analyzer.name}: Very low applicability rate ({applicable_rate:.1%}). "
                    f"Parser may not be extracting {analyzer.name.split()[0].lower()} frames correctly."
                )
            
            # Run analysis
            findings = analyzer.analyze(applicable_packets, context)
            
            # Post-analysis cleanup
            analyzer.post_analysis_cleanup(context)
            
            # Track performance
            analyzer_time = time.time() - analyzer_start
            analyzer.processing_time = analyzer_time
            analyzer.packets_processed = len(applicable_packets)
            analyzer.findings_generated = len(findings)
            
            # Evaluate result quality
            result['success'] = True
            result['findings'] = findings
            result['quality_metrics'].update({
                'findings_count': len(findings),
                'processing_time': analyzer_time,
                'packets_processed': len(applicable_packets)
            })
            
            self.logger.info(
                f"{analyzer.name}: {len(findings)} findings in {analyzer_time:.2f}s "
                f"(applicability: {applicable_rate:.1%})"
            )
            
        except Exception as e:
            self.logger.error(f"Error in {analyzer.name} attempt {attempt}: {e}")
            
            result['error'] = str(e)
            result['findings'] = [Finding(
                category=AnalysisCategory.ANOMALY_DETECTION,
                severity=Severity.ERROR,
                title=f"Analyzer Error: {analyzer.name}",
                description=f"Error occurred during analysis attempt {attempt}: {str(e)}",
                details={
                    "analyzer": analyzer.name,
                    "attempt": attempt,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "parser_used": unified_packets[0].parsing_library if unified_packets else "unknown"
                },
                analyzer_name=analyzer.name,
                analyzer_version=analyzer.version
            )]
            
        return result
    
    def _should_retry_with_different_parser(self, result: Dict[str, Any]) -> bool:
        """
        Determine if we should retry with a different parser based on result quality.
        
        Args:
            result: Result dictionary from _attempt_analyzer_run
            
        Returns:
            True if we should retry with different parser
        """
        # Always retry if the analysis failed completely
        if not result['success']:
            return True
            
        metrics = result.get('quality_metrics', {})
        
        # Retry if applicable packet rate is very low (suggests parser issues)
        applicable_rate = metrics.get('applicable_packet_rate', 0)
        if applicable_rate < 0.02:  # Less than 2% applicable packets
            return True
            
        # Retry if zero findings for analyzers that should typically find something
        findings_count = metrics.get('findings_count', 0)
        if findings_count == 0:
            # Some analyzers expected to find issues in typical captures
            analyzer_name = result['findings'][0].analyzer_name if result['findings'] else ''
            if any(keyword in analyzer_name.lower() for keyword in 
                   ['beacon', 'deauth', 'security', 'signal']):
                return True
        
        # Don't retry if results seem reasonable
        return False
    
    def _retry_with_alternative_parsers(
        self,
        analyzer: BaseAnalyzer,
        pcap_file: str,
        max_packets: Optional[int],
        context: AnalysisContext,
        current_library: Optional[str]
    ) -> List[Finding]:
        """
        Retry analysis with alternative parsers.
        
        Returns:
            Best findings from alternative parser attempts
        """
        # Get available alternative parsers (excluding current one)
        available_parsers = self.packet_loader.available_parsers.copy()
        if current_library in available_parsers:
            available_parsers.remove(current_library)
            
        if not available_parsers:
            self.logger.warning("No alternative parsers available for retry")
            return []
            
        best_result = None
        best_score = -1
        
        for alt_parser in available_parsers:
            try:
                self.logger.info(f"Retrying {analyzer.name} with {alt_parser} parser")
                
                # Create temporary packet loader for this parser
                temp_loader = UnifiedPacketLoader(prefer_library=alt_parser)
                
                # Load packets with alternative parser
                alt_packets, alt_metadata = temp_loader.load_packets(pcap_file, max_packets)
                
                current_packet_count = self.packet_loader.stats.get('total_packets_loaded', 0)
                self.logger.info(
                    f"Alternative parser {alt_parser} loaded {len(alt_packets)} packets "
                    f"(vs {current_packet_count} with {current_library})"
                )
                
                # Attempt analysis with alternative packets
                alt_result = self._attempt_analyzer_run(analyzer, alt_packets, context, attempt=2)
                
                # Score this result
                score = self._score_analysis_result(alt_result, alt_parser)
                
                if score > best_score:
                    best_score = score
                    best_result = alt_result
                    
                    self.logger.info(
                        f"{analyzer.name} with {alt_parser}: score={score:.1f}, "
                        f"findings={alt_result['quality_metrics'].get('findings_count', 0)}, "
                        f"applicability={alt_result['quality_metrics'].get('applicable_packet_rate', 0):.1%}"
                    )
                    
            except Exception as e:
                self.logger.warning(f"Failed to retry {analyzer.name} with {alt_parser}: {e}")
                continue
        
        if best_result and best_score > 0:
            # Track successful parser switch
            alt_parser = available_parsers[0]  # We'll determine which was best from the result
            switch_key = f"{current_library} -> {alt_parser}"
            self.retry_stats['parser_switches'][switch_key] = self.retry_stats['parser_switches'].get(switch_key, 0) + 1
            
            self.logger.info(f"{analyzer.name}: Using results from alternative parser (score: {best_score:.1f})")
            return best_result['findings']
        else:
            self.logger.warning(f"{analyzer.name}: No alternative parser produced better results")
            return []
    
    def _score_analysis_result(self, result: Dict[str, Any], parser_name: str) -> float:
        """
        Score analysis result quality to compare different parser attempts.
        
        Returns:
            Score (higher = better)
        """
        if not result['success']:
            return -1.0
            
        metrics = result['quality_metrics']
        score = 0.0
        
        # Higher score for more applicable packets (suggests better parsing)
        applicable_rate = metrics.get('applicable_packet_rate', 0)
        score += applicable_rate * 50  # Up to 50 points for 100% applicability
        
        # Higher score for finding results (suggests working analysis)
        findings_count = metrics.get('findings_count', 0)
        if findings_count > 0:
            score += min(findings_count * 2, 20)  # Up to 20 points for findings
        
        # Reasonable processing time (not too slow)
        processing_time = metrics.get('processing_time', float('inf'))
        if processing_time < 10:  # Under 10 seconds is good
            score += 10
        elif processing_time < 30:  # Under 30 seconds is okay
            score += 5
            
        # Bonus points for parsers known to be good for certain analysis types
        if parser_name == 'pyshark':
            score += 5  # Generally comprehensive
        elif parser_name == 'scapy':
            score += 3  # Good balance
        
        return score
            
    def _create_analysis_context(self, pcap_file: str, unified_packets: List[UnifiedPacketInfo]) -> AnalysisContext:
        """
        Create analysis context from packets.
        
        Args:
            pcap_file: Path to PCAP file
            unified_packets: List of unified packets
            
        Returns:
            Analysis context
        """
        if not unified_packets:
            return AnalysisContext(
                pcap_file=pcap_file,
                packet_count=0,
                start_time=0,
                end_time=0,
                duration=0,
                config=self.config
            )
            
        # Extract timing info from unified packets
        timestamps = [p.timestamp for p in unified_packets if p.timestamp > 0]
                
        if timestamps:
            start_time = min(timestamps)
            end_time = max(timestamps)
            duration = end_time - start_time
        else:
            start_time = end_time = duration = 0
            
        context = AnalysisContext(
            pcap_file=pcap_file,
            packet_count=len(unified_packets),
            start_time=start_time,
            end_time=end_time,
            duration=duration,
            config=self.config
        )
        
        # Pre-populate network entities from unified packets
        try:
            self._extract_network_entities_unified(unified_packets, context)
        except Exception as e:
            self.logger.warning(f"Error extracting network entities: {e}")
            
        return context
        
    def _extract_network_entities_unified(self, unified_packets: List[UnifiedPacketInfo], context: AnalysisContext) -> None:
        """
        Extract network entities from unified packets.
        
        Args:
            unified_packets: List of unified packets
            context: Analysis context to populate
        """
        entities = {}
        
        for packet in unified_packets:
            # Create entities from available address information
            if packet.src_mac:
                if packet.src_mac not in entities:
                    entity_type = 'ap' if packet.frame_name == 'beacon' else 'sta'
                    entities[packet.src_mac] = NetworkEntity(
                        mac_address=packet.src_mac,
                        entity_type=entity_type
                    )
                    
                # Update entity with packet info
                entity = entities[packet.src_mac]
                if packet.timestamp > 0:
                    from datetime import datetime
                    timestamp_dt = datetime.fromtimestamp(packet.timestamp)
                    if entity.first_seen is None:
                        entity.first_seen = timestamp_dt
                    entity.last_seen = timestamp_dt
                    
                # Add capabilities from unified packet
                if packet.ssid:
                    entity.capabilities['ssid'] = packet.ssid
                if packet.channel:
                    entity.capabilities['channel'] = packet.channel
                if packet.beacon_interval:
                    entity.capabilities['beacon_interval'] = packet.beacon_interval
                    
        # Add entities to context
        for entity in entities.values():
            context.add_entity(entity)
            
    def _gather_basic_metrics(self, unified_packets: List[UnifiedPacketInfo], context: AnalysisContext) -> AnalysisMetrics:
        """
        Gather basic metrics from packets.
        
        Args:
            unified_packets: List of unified packets
            context: Analysis context
            
        Returns:
            Analysis metrics
        """
        metrics = AnalysisMetrics()
        
        # Basic counts
        metrics.total_packets = len(unified_packets)
        metrics.capture_duration_seconds = context.duration
        
        # Count frame types from unified packets
        frame_counts = {}
        management_subtypes = {}
        rssi_values = []
        channels = set()
        ssids = set()
        fcs_errors = 0
        retry_frames = 0
        
        for packet in unified_packets:
            # Frame type counting
            frame_name = packet.frame_name
            frame_counts[frame_name] = frame_counts.get(frame_name, 0) + 1
            
            # Management frame subcounting
            if packet.frame_type == 0:  # Management
                metrics.management_frames += 1
                if frame_name == 'beacon':
                    metrics.beacon_frames += 1
                elif frame_name == 'probe_request':
                    metrics.probe_requests += 1
                elif frame_name == 'probe_response':
                    metrics.probe_responses += 1
                elif frame_name == 'authentication':
                    metrics.auth_frames += 1
                elif frame_name in ['association_request', 'association_response']:
                    metrics.assoc_frames += 1
                elif frame_name == 'deauthentication':
                    metrics.deauth_frames += 1
                elif frame_name == 'disassociation':
                    metrics.disassoc_frames += 1
            elif packet.frame_type == 1:  # Control
                metrics.control_frames += 1
            elif packet.frame_type == 2:  # Data
                metrics.data_frames += 1
                
            # Collect other metrics
            if packet.rssi is not None:
                rssi_values.append(packet.rssi)
            if packet.channel:
                channels.add(packet.channel)
            if packet.ssid:
                ssids.add(packet.ssid)
            if packet.fcs_bad:
                fcs_errors += 1
            if packet.retry:
                retry_frames += 1
                
        # Update metrics
        metrics.fcs_errors = fcs_errors
        metrics.retry_frames = retry_frames
        metrics.channels_observed = channels
        metrics.unique_ssids = len(ssids)
        
        # Network entities from context
        metrics.unique_aps = len([e for e in context.network_entities.values() 
                                if e.entity_type == 'ap'])
        metrics.unique_stations = len([e for e in context.network_entities.values() 
                                     if e.entity_type == 'sta'])
        
        # RSSI statistics
        if rssi_values:
            metrics.average_rssi = sum(rssi_values) / len(rssi_values)
            if len(rssi_values) > 1:
                import statistics
                metrics.rssi_std_dev = statistics.stdev(rssi_values)
        
        # Determine frequency bands from channels
        bands = set()
        for channel in channels:
            if 1 <= channel <= 14:
                bands.add("2.4GHz")
            elif 36 <= channel <= 165:
                bands.add("5GHz")
            elif channel > 200:
                bands.add("6GHz")
        metrics.frequency_bands = bands
        
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
    
    def get_adaptive_retry_stats(self) -> Dict[str, Any]:
        """
        Get adaptive retry statistics.
        
        Returns:
            Dictionary with retry performance metrics
        """
        stats = self.retry_stats.copy()
        
        # Calculate percentages
        if stats['total_analyzers_run'] > 0:
            stats['retry_rate'] = (stats['analyzers_retried'] / stats['total_analyzers_run']) * 100
            if stats['analyzers_retried'] > 0:
                stats['retry_success_rate'] = (stats['successful_retries'] / stats['analyzers_retried']) * 100
            else:
                stats['retry_success_rate'] = 0
        else:
            stats['retry_rate'] = 0
            stats['retry_success_rate'] = 0
            
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
    
    def analyze_pcap_dual_comparison(
        self,
        pcap_file: str,
        max_packets: Optional[int] = None,
        analyzer_categories: Optional[List[str]] = None,
        specific_analyzers: Optional[List[str]] = None,
        parallel_execution: bool = True,
        debug_mode: bool = False
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
                debug_mode=debug_mode
            )
            
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