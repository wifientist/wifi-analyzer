"""
Enhanced Dual-Pipeline Wireless PCAP Analyzer.

This analyzer runs both Scapy and PyShark parsing pipelines independently,
providing comprehensive analysis with parser-specific results and comparison
across all available analyzers.
"""

import time
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

from .models import (
    AnalysisResults,
    AnalysisContext,
    AnalysisMetrics,
    Finding,
    Severity,
    AnalysisCategory,
    AnalysisError
)

from .analyzer_registry import analyzer_registry
from ..loaders.scapy_loader import ScapyPacketLoader
from ..loaders.pyshark_loader import PySharkPacketLoader


class EnhancedDualPipelineAnalyzer:
    """
    Enhanced Dual-Pipeline Wireless PCAP Analyzer.
    
    This class orchestrates analysis using both Scapy and PyShark parsers
    across all registered analyzers, providing comprehensive analysis and
    detailed parser comparison.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the enhanced dual-pipeline analyzer.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Initialize loaders
        self.scapy_loader = ScapyPacketLoader()
        self.pyshark_loader = PySharkPacketLoader()
        
        # Performance tracking
        self.analysis_stats = {
            'total_analyses': 0,
            'scapy_analyses': 0,
            'pyshark_analyses': 0,
            'dual_analyses': 0,
            'average_scapy_time': 0.0,
            'average_pyshark_time': 0.0,
            'parser_comparison_stats': [],
            'analyzer_performance': defaultdict(dict)
        }
    
    def analyze_pcap_comprehensive(
        self,
        pcap_file: str,
        max_packets: Optional[int] = None,
        run_both: bool = True,
        run_scapy: bool = True,
        run_pyshark: bool = True,
        analyzer_categories: Optional[List[str]] = None,
        specific_analyzers: Optional[List[str]] = None,
        parallel_execution: bool = True,
        debug_mode: bool = False,
        skip_validation: bool = False
    ) -> Dict[str, Any]:
        """
        Analyze PCAP file using enhanced dual pipelines.
        
        Args:
            pcap_file: Path to PCAP file
            max_packets: Maximum number of packets to analyze
            run_both: Run both pipelines (overrides individual flags)
            run_scapy: Run Scapy pipeline
            run_pyshark: Run PyShark pipeline
            analyzer_categories: Filter to specific categories (core, baseline, security)
            specific_analyzers: Filter to specific analyzer names
            parallel_execution: Run pipelines in parallel when possible
            debug_mode: Enable debug logging
            skip_validation: Skip pre-analysis PCAP validation
            
        Returns:
            Dictionary with comprehensive results from both pipelines
        """
        start_time = time.time()
        self.logger.info(f"Starting enhanced dual-pipeline analysis of {pcap_file}")
        self.logger.debug(f"Configuration: run_both={run_both}, run_scapy={run_scapy}, run_pyshark={run_pyshark}, "
                          f"analyzer_categories={analyzer_categories}, specific_analyzers={specific_analyzers}, "
                          f"parallel_execution={parallel_execution}, debug_mode={debug_mode}")

        # Validate file existence
        pcap_path = Path(pcap_file)
        if not pcap_path.exists():
            raise AnalysisError(f"PCAP file not found: {pcap_file}")
        
        # Run pre-analysis validation (unless skipped)
        validation_results = None
        if not skip_validation:
            self.logger.info("🔍 Running pre-analysis PCAP validation...")
            validation_results = self.validate_pcap_comprehensive(pcap_file, max_packets)
            
            # Log validation summary
            self._log_validation_summary(validation_results)
            
            # Check if capture is suitable for analysis
            summary = validation_results.get('summary', {})
            if summary.get('overall_status') == 'failed':
                raise AnalysisError("PCAP validation failed - both parsers unable to process file")
        else:
            self.logger.info("⚠️ Skipping pre-analysis PCAP validation")
        
        # Determine which pipelines to run
        if run_both:
            run_scapy = run_pyshark = True
        
        # Get analyzer configuration
        analyzer_config = self._get_analyzer_config(
            analyzer_categories, specific_analyzers
        )
        
        results = {
            'pcap_file': pcap_file,
            'analysis_timestamp': time.time(),
            'validation': validation_results,  # Include validation results
            'config': {
                'max_packets': max_packets,
                'run_scapy': run_scapy,
                'run_pyshark': run_pyshark,
                'analyzer_categories': analyzer_categories,
                'specific_analyzers': specific_analyzers,
                'parallel_execution': parallel_execution,
                'debug_mode': debug_mode,
                'analyzers_used': analyzer_config
            },
            'scapy_results': None,
            'pyshark_results': None,
            'comparison': None,
            'performance': {},
            'summary': {}
        }
        
        # Run pipelines
        if run_scapy and run_pyshark and parallel_execution:
            # Run both in parallel
            self.logger.info("Running both pipelines in parallel")
            scapy_result, pyshark_result = self._run_pipelines_parallel(
                pcap_file, max_packets, analyzer_config, debug_mode
            )
            self.logger.debug(f"Parallel execution returned - Scapy: {type(scapy_result)}, PyShark: {type(pyshark_result)}")
            self.logger.debug(f"Scapy result is None: {scapy_result is None}")
            self.logger.debug(f"PyShark result is None: {pyshark_result is None}")
            results['scapy_results'] = scapy_result
            results['pyshark_results'] = pyshark_result
            self.analysis_stats['dual_analyses'] += 1
            
        else:
            # Run sequentially or single pipeline
            if run_scapy:
                self.logger.info("Running Scapy pipeline")
                scapy_result = self._run_scapy_pipeline(
                    pcap_file, max_packets, analyzer_config, debug_mode
                )
                self.logger.debug(f"Sequential Scapy pipeline returned: {type(scapy_result)}, None: {scapy_result is None}")
                results['scapy_results'] = scapy_result
                self.analysis_stats['scapy_analyses'] += 1
                
            if run_pyshark:
                self.logger.info("Running PyShark pipeline")
                pyshark_result = self._run_pyshark_pipeline(
                    pcap_file, max_packets, analyzer_config, debug_mode
                )
                self.logger.debug(f"Sequential PyShark pipeline returned: {type(pyshark_result)}, None: {pyshark_result is None}")
                results['pyshark_results'] = pyshark_result
                self.analysis_stats['pyshark_analyses'] += 1
        
        # Generate comprehensive comparison if both ran
        if results['scapy_results'] and results['pyshark_results']:
            self.logger.info("🔄 Starting comprehensive comparison analysis...")
            self.logger.debug(f"Scapy results type: {type(results['scapy_results'])}, None: {results['scapy_results'] is None}")
            self.logger.debug(f"PyShark results type: {type(results['pyshark_results'])}, None: {results['pyshark_results'] is None}")
            try:
                results['comparison'] = self._compare_comprehensive_results(
                    results['scapy_results'], 
                    results['pyshark_results']
                )
                self.logger.info("✅ Comprehensive comparison complete")
            except Exception as e:
                self.logger.error(f"❌ Comprehensive comparison failed: {e}")
                import traceback
                self.logger.error(f"Traceback: {traceback.format_exc()}")
                results['comparison'] = None
        else:
            self.logger.info("⏭️ Skipping comparison - not both pipelines available")
            results['comparison'] = None
        
        # Generate analysis summary
        self.logger.info("📊 Starting analysis summary generation...")
        try:
            results['summary'] = self._generate_analysis_summary(results)
            self.logger.info("✅ Analysis summary complete")
        except Exception as e:
            self.logger.error(f"❌ Analysis summary failed: {e}")
            import traceback
            self.logger.error(f"Traceback: {traceback.format_exc()}")
            results['summary'] = {}
        
        # Performance metrics
        self.logger.info("⏱️ Starting performance metrics calculation...")
        total_time = time.time() - start_time
        try:
            results['performance'] = self._calculate_performance_metrics(results, total_time)
            self.logger.info("✅ Performance metrics complete")
        except Exception as e:
            self.logger.error(f"❌ Performance metrics failed: {e}")
            import traceback
            self.logger.error(f"Traceback: {traceback.format_exc()}")
            results['performance'] = {'total_analysis_time': total_time}
        
        self.analysis_stats['total_analyses'] += 1
        self._update_performance_stats(results)
        
        self.logger.info(f"Enhanced dual-pipeline analysis complete in {total_time:.2f}s")
        
        return results
    
    def _get_analyzer_config(
        self, 
        categories: Optional[List[str]], 
        specific_analyzers: Optional[List[str]]
    ) -> Dict[str, Any]:
        """Get analyzer configuration based on filters."""
        registry_summary = analyzer_registry.get_registry_summary()
        available_analyzers = registry_summary['analyzer_list']
        
        if specific_analyzers:
            # Filter to specific analyzers
            config = {name: info for name, info in available_analyzers.items() 
                     if name in specific_analyzers}
        elif categories:
            # Filter by categories
            config = {name: info for name, info in available_analyzers.items() 
                     if info['category'] in categories}
        else:
            # Use all enabled analyzers
            config = {name: info for name, info in available_analyzers.items() 
                     if info['enabled']}
        
        self.logger.info(f"Will run {len(config)} analyzers: {list(config.keys())}")
        return config
    
    def _run_pipelines_parallel(
        self,
        pcap_file: str,
        max_packets: Optional[int],
        analyzer_config: Dict[str, Any],
        debug_mode: bool
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Run both pipelines in parallel using ThreadPoolExecutor."""
        
        with ThreadPoolExecutor(max_workers=2) as executor:
            # Submit both tasks
            scapy_future = executor.submit(
                self._run_scapy_pipeline, pcap_file, max_packets, analyzer_config, debug_mode
            )
            self.logger.info("Scapy pipeline task submitted")
            pyshark_future = executor.submit(
                self._run_pyshark_pipeline, pcap_file, max_packets, analyzer_config, debug_mode
            )
            self.logger.info("PyShark pipeline task submitted")

            # Wait for completion
            scapy_result = None
            pyshark_result = None
            
            for future in as_completed([scapy_future, pyshark_future]):
                try:
                    if future == scapy_future:
                        scapy_result = future.result()
                        self.logger.info("Scapy pipeline completed")
                    else:
                        pyshark_result = future.result()
                        self.logger.info("PyShark pipeline completed")
                except Exception as e:
                    self.logger.error(f"Pipeline failed: {e}")
                    # Set failed pipeline result instead of leaving as None
                    failed_result = {
                        'parser': 'scapy' if future == scapy_future else 'pyshark',
                        'success': False,
                        'error': str(e),
                        'analyzers': {},
                        'all_findings': [],
                        'total_findings': 0,
                        'performance': {'total_time': 0}
                    }
                    if future == scapy_future:
                        scapy_result = failed_result
                    else:
                        pyshark_result = failed_result
        
        # Ensure we never return None results
        if scapy_result is None:
            scapy_result = {
                'parser': 'scapy',
                'success': False,
                'error': 'Pipeline did not complete',
                'analyzers': {},
                'all_findings': [],
                'total_findings': 0,
                'performance': {'total_time': 0}
            }
            self.logger.error("Scapy pipeline result was None - creating fallback")
            
        if pyshark_result is None:
            pyshark_result = {
                'parser': 'pyshark',
                'success': False,
                'error': 'Pipeline did not complete',
                'analyzers': {},
                'all_findings': [],
                'total_findings': 0,
                'performance': {'total_time': 0}
            }
            self.logger.error("PyShark pipeline result was None - creating fallback")
        
        return scapy_result, pyshark_result
    
    def _run_scapy_pipeline(
        self,
        pcap_file: str,
        max_packets: Optional[int],
        analyzer_config: Dict[str, Any],
        debug_mode: bool
    ) -> Dict[str, Any]:
        """Run the Scapy analysis pipeline with all configured analyzers."""
        pipeline_start = time.time()
        
        try:
            # Load packets with Scapy
            self.logger.info("Loading packets with Scapy loader")
            packets, loading_metadata = self.scapy_loader.load_packets(pcap_file, max_packets)
            
            # Create analysis context
            context = AnalysisContext(
                pcap_file=pcap_file,
                packet_count=len(packets),
                start_time=0,
                end_time=0,
                duration=0,
                config=self.config
            )
            
            # Create analyzers
            analyzers = analyzer_registry.create_scapy_analyzers(
                enabled_only=False,  # We handle filtering via analyzer_config
                filter_categories=None
            )
            
            # Filter analyzers based on configuration
            active_analyzers = {name: analyzer for name, analyzer in analyzers.items() 
                              if name in analyzer_config}
            
            self.logger.info(f"🚀 Running {len(active_analyzers)} Scapy analyzers")
            
            # Run analyzers and collect results
            analyzer_results = {}
            all_findings = []
            
            for analyzer_name, analyzer in active_analyzers.items():
                analyzer_start = time.time()
                
                # Log analyzer start
                self.logger.info(f"🔍 Starting Scapy analyzer: {analyzer_name}")
                
                try:
                    # Filter applicable packets for this analyzer
                    applicable_packets = [pkt for pkt in packets if analyzer.is_applicable(pkt)]
                    
                    self.logger.info(f"   → {len(applicable_packets)} applicable packets found for {analyzer_name}")
                    
                    # Run analysis using the analyzer's analyze method
                    self.logger.debug(f"   → Running analysis on {analyzer_name}...")
                    findings = analyzer.analyze(applicable_packets, context)
                    
                    # Get summary if available
                    summary = None
                    if hasattr(analyzer, 'get_analysis_summary'):
                        try:
                            summary = analyzer.get_analysis_summary()
                        except Exception as e:
                            self.logger.debug(f"Error getting {analyzer_name} summary: {e}")
                    
                    analyzer_time = time.time() - analyzer_start
                    
                    analyzer_results[analyzer_name] = {
                        'analyzer_name': analyzer.name,
                        'findings': findings,
                        'findings_count': len(findings),
                        'packets_processed': len(applicable_packets),
                        'analysis_time': analyzer_time,
                        'summary': summary,
                        'success': True,
                        'error': None
                    }
                    
                    all_findings.extend(findings)
                    
                    self.logger.info(
                        f"✅ Completed Scapy analyzer: {analyzer_name} - {len(findings)} findings from {len(applicable_packets)} packets in {analyzer_time:.2f}s"
                    )
                    
                except Exception as e:
                    analyzer_time = time.time() - analyzer_start
                    self.logger.error(f"❌ Failed Scapy analyzer: {analyzer_name} after {analyzer_time:.2f}s - {e}")
                    analyzer_results[analyzer_name] = {
                        'analyzer_name': analyzer_name,
                        'findings': [],
                        'findings_count': 0,
                        'packets_processed': 0,
                        'analysis_time': time.time() - analyzer_start,
                        'summary': None,
                        'success': False,
                        'error': str(e)
                    }
            
            # Build result
            result = {
                'parser': 'scapy',
                'success': True,
                'error': None,
                'loading_metadata': loading_metadata,
                'total_packets': len(packets),
                'analyzers': analyzer_results,
                'all_findings': all_findings,
                'total_findings': len(all_findings),
                'performance': {
                    'loading_time': loading_metadata['loading_time'],
                    'analysis_time': sum(ar['analysis_time'] for ar in analyzer_results.values()),
                    'total_time': time.time() - pipeline_start
                }
            }
            
            successful_analyzers = sum(1 for r in analyzer_results.values() if r['success'])
            failed_analyzers = len(active_analyzers) - successful_analyzers
            
            self.logger.info(
                f"🏁 Scapy pipeline complete: {len(all_findings)} total findings from {successful_analyzers}/{len(active_analyzers)} analyzers in {result['performance']['total_time']:.2f}s"
            )
            
            if failed_analyzers > 0:
                self.logger.warning(f"   ⚠️  {failed_analyzers} analyzers failed during Scapy pipeline")
            
            self.logger.debug(f"Scapy pipeline about to return result: {type(result)}")
            return result
            
        except Exception as e:
            self.logger.error(f"Scapy pipeline failed: {e}")
            error_result = {
                'parser': 'scapy',
                'success': False,
                'error': str(e),
                'performance': {'total_time': time.time() - pipeline_start}
            }
            self.logger.debug(f"Scapy pipeline returning error result: {type(error_result)}")
            return error_result
    
    def _run_pyshark_pipeline(
        self,
        pcap_file: str,
        max_packets: Optional[int],
        analyzer_config: Dict[str, Any],
        debug_mode: bool
    ) -> Dict[str, Any]:
        """Run the PyShark analysis pipeline with all configured analyzers."""
        pipeline_start = time.time()
        
        try:
            # Load packets with PyShark
            self.logger.info("Loading packets with PyShark loader")
            packets, loading_metadata = self.pyshark_loader.load_packets(pcap_file, max_packets)
            
            # Create analysis context
            context = AnalysisContext(
                pcap_file=pcap_file,
                packet_count=len(packets),
                start_time=0,
                end_time=0,
                duration=0,
                config=self.config
            )
            
            # Create analyzers
            analyzers = analyzer_registry.create_pyshark_analyzers(
                enabled_only=False,  # We handle filtering via analyzer_config
                filter_categories=None
            )
            
            # Filter analyzers based on configuration
            active_analyzers = {name: analyzer for name, analyzer in analyzers.items() 
                              if name in analyzer_config}
            
            self.logger.info(f"🚀 Running {len(active_analyzers)} PyShark analyzers")
            
            # Run analyzers and collect results
            analyzer_results = {}
            all_findings = []
            
            for analyzer_name, analyzer in active_analyzers.items():
                analyzer_start = time.time()
                
                # Log analyzer start
                self.logger.info(f"🔍 Starting PyShark analyzer: {analyzer_name}")
                
                try:
                    # Filter applicable packets for this analyzer
                    applicable_packets = [pkt for pkt in packets if analyzer.is_applicable(pkt)]
                    
                    self.logger.info(f"   → {len(applicable_packets)} applicable packets found for {analyzer_name}")
                    
                    # Run analysis using the analyzer's analyze method
                    self.logger.debug(f"   → Running analysis on {analyzer_name}...")
                    findings = analyzer.analyze(applicable_packets, context)
                    processed_count = len(applicable_packets)
                    
                    # Get summary if available
                    summary = None
                    if hasattr(analyzer, 'get_analysis_summary'):
                        try:
                            summary = analyzer.get_analysis_summary()
                        except Exception as e:
                            self.logger.debug(f"Error getting {analyzer_name} summary: {e}")
                    
                    analyzer_time = time.time() - analyzer_start
                    
                    analyzer_results[analyzer_name] = {
                        'analyzer_name': analyzer.name,
                        'findings': findings,
                        'findings_count': len(findings),
                        'packets_processed': processed_count,
                        'analysis_time': analyzer_time,
                        'summary': summary,
                        'success': True,
                        'error': None
                    }
                    
                    all_findings.extend(findings)
                    
                    self.logger.info(
                        f"✅ Completed PyShark analyzer: {analyzer_name} - {len(findings)} findings from {processed_count} packets in {analyzer_time:.2f}s"
                    )
                    
                except Exception as e:
                    analyzer_time = time.time() - analyzer_start
                    self.logger.error(f"❌ Failed PyShark analyzer: {analyzer_name} after {analyzer_time:.2f}s - {e}")
                    analyzer_results[analyzer_name] = {
                        'analyzer_name': analyzer_name,
                        'findings': [],
                        'findings_count': 0,
                        'packets_processed': 0,
                        'analysis_time': time.time() - analyzer_start,
                        'summary': None,
                        'success': False,
                        'error': str(e)
                    }
            
            # Build result
            result = {
                'parser': 'pyshark',
                'success': True,
                'error': None,
                'loading_metadata': loading_metadata,
                'total_packets': len(packets),
                'analyzers': analyzer_results,
                'all_findings': all_findings,
                'total_findings': len(all_findings),
                'performance': {
                    'loading_time': loading_metadata['loading_time'],
                    'analysis_time': sum(ar['analysis_time'] for ar in analyzer_results.values()),
                    'total_time': time.time() - pipeline_start
                }
            }
            
            successful_analyzers = sum(1 for r in analyzer_results.values() if r['success'])
            failed_analyzers = len(active_analyzers) - successful_analyzers
            
            self.logger.info(
                f"🏁 PyShark pipeline complete: {len(all_findings)} total findings from {successful_analyzers}/{len(active_analyzers)} analyzers in {result['performance']['total_time']:.2f}s"
            )
            
            if failed_analyzers > 0:
                self.logger.warning(f"   ⚠️  {failed_analyzers} analyzers failed during PyShark pipeline")
            
            self.logger.debug(f"PyShark pipeline about to return result: {type(result)}")
            return result
            
        except Exception as e:
            self.logger.error(f"PyShark pipeline failed: {e}")
            error_result = {
                'parser': 'pyshark',
                'success': False,
                'error': str(e),
                'performance': {'total_time': time.time() - pipeline_start}
            }
            self.logger.debug(f"PyShark pipeline returning error result: {type(error_result)}")
            return error_result
    
    def _compare_comprehensive_results(
        self,
        scapy_result: Dict[str, Any],
        pyshark_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Compare comprehensive results from both pipelines."""
        
        # Add null safety checks
        if scapy_result is None or pyshark_result is None:
            self.logger.error(f"Cannot compare - one result is None: scapy={scapy_result is None}, pyshark={pyshark_result is None}")
            return {
                'comparison_available': False,
                'reason': 'One or both pipeline results are None'
            }
        
        if not scapy_result.get('success', False) or not pyshark_result.get('success', False):
            return {
                'comparison_available': False,
                'reason': 'One or both pipelines failed'
            }
        
        comparison = {
            'comparison_available': True,
            'packet_counts': {
                'scapy_total': scapy_result['total_packets'],
                'pyshark_total': pyshark_result['total_packets'],
                'packet_count_diff': scapy_result['total_packets'] - pyshark_result['total_packets']
            },
            'findings_comparison': {
                'scapy_total': scapy_result['total_findings'],
                'pyshark_total': pyshark_result['total_findings'],
                'findings_diff': scapy_result['total_findings'] - pyshark_result['total_findings']
            },
            'performance_comparison': {
                'scapy_total_time': scapy_result['performance']['total_time'],
                'pyshark_total_time': pyshark_result['performance']['total_time'],
                'scapy_analysis_time': scapy_result['performance']['analysis_time'],
                'pyshark_analysis_time': pyshark_result['performance']['analysis_time'],
                'time_difference': scapy_result['performance']['total_time'] - pyshark_result['performance']['total_time']
            },
            'analyzer_comparison': {}
        }
        
        # Compare individual analyzers
        scapy_analyzers = scapy_result.get('analyzers', {})
        pyshark_analyzers = pyshark_result.get('analyzers', {})
        
        for analyzer_name in set(scapy_analyzers.keys()) | set(pyshark_analyzers.keys()):
            scapy_data = scapy_analyzers.get(analyzer_name, {})
            pyshark_data = pyshark_analyzers.get(analyzer_name, {})
            
            comparison['analyzer_comparison'][analyzer_name] = {
                'scapy_findings': scapy_data.get('findings_count', 0),
                'pyshark_findings': pyshark_data.get('findings_count', 0),
                'findings_diff': scapy_data.get('findings_count', 0) - pyshark_data.get('findings_count', 0),
                'scapy_time': scapy_data.get('analysis_time', 0),
                'pyshark_time': pyshark_data.get('analysis_time', 0),
                'time_diff': scapy_data.get('analysis_time', 0) - pyshark_data.get('analysis_time', 0),
                'scapy_success': scapy_data.get('success', False),
                'pyshark_success': pyshark_data.get('success', False)
            }
        
        # Performance winners
        if comparison['performance_comparison']['scapy_total_time'] < comparison['performance_comparison']['pyshark_total_time']:
            comparison['performance_winner'] = 'scapy'
            time_diff = comparison['performance_comparison']['pyshark_total_time'] - comparison['performance_comparison']['scapy_total_time']
            comparison['performance_advantage'] = f"Scapy was {time_diff:.2f}s faster"
        else:
            comparison['performance_winner'] = 'pyshark'
            time_diff = comparison['performance_comparison']['scapy_total_time'] - comparison['performance_comparison']['pyshark_total_time']
            comparison['performance_advantage'] = f"PyShark was {time_diff:.2f}s faster"
        
        # Findings winner
        if comparison['findings_comparison']['scapy_total'] > comparison['findings_comparison']['pyshark_total']:
            comparison['detection_winner'] = 'scapy'
        elif comparison['findings_comparison']['pyshark_total'] > comparison['findings_comparison']['scapy_total']:
            comparison['detection_winner'] = 'pyshark'  
        else:
            comparison['detection_winner'] = 'tie'
        
        return comparison
    
    def _generate_analysis_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive analysis summary."""
        summary = {
            'analysis_overview': {},
            'findings_summary': {},
            'performance_summary': {},
            'parser_summary': {}
        }
        
        # Analysis overview
        total_findings = 0
        scapy_results = results.get('scapy_results')
        pyshark_results = results.get('pyshark_results')
        
        if scapy_results and scapy_results.get('success', False):
            total_findings += scapy_results.get('total_findings', 0)
        if pyshark_results and pyshark_results.get('success', False):
            total_findings += pyshark_results.get('total_findings', 0)
        
        summary['analysis_overview'] = {
            'pcap_file': results['pcap_file'],
            'total_findings_across_parsers': total_findings,
            'scapy_ran': results.get('scapy_results') is not None,
            'pyshark_ran': results.get('pyshark_results') is not None,
            'both_successful': (
                (scapy_results and scapy_results.get('success', False)) and 
                (pyshark_results and pyshark_results.get('success', False))
            )
        }
        
        # Findings summary by category and severity
        findings_by_type = defaultdict(int)
        findings_by_severity = defaultdict(int)
        
        for parser in ['scapy_results', 'pyshark_results']:
            parser_result = results.get(parser)
            if parser_result and parser_result.get('success', False):
                all_findings = parser_result.get('all_findings', [])
                for finding in all_findings:
                    if hasattr(finding, 'finding_type'):
                        # Convert any enum to string for JSON serialization
                        type_key = finding.finding_type.value if hasattr(finding.finding_type, 'value') else str(finding.finding_type)
                        findings_by_type[type_key] += 1
                    if hasattr(finding, 'severity'):
                        # Convert Severity enum to string for JSON serialization
                        severity_key = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
                        findings_by_severity[severity_key] += 1
        
        summary['findings_summary'] = {
            'by_type': dict(findings_by_type),
            'by_severity': dict(findings_by_severity)
        }
        
        return summary
    
    def _calculate_performance_metrics(
        self, 
        results: Dict[str, Any], 
        total_time: float
    ) -> Dict[str, Any]:
        """Calculate comprehensive performance metrics."""
        metrics = {
            'total_analysis_time': total_time,
            'scapy_time': 0,
            'pyshark_time': 0,
            'loading_times': {},
            'analysis_times': {}
        }
        
        scapy_results = results.get('scapy_results')
        if scapy_results and scapy_results.get('success', False):
            scapy_perf = scapy_results.get('performance', {})
            metrics['scapy_time'] = scapy_perf.get('total_time', 0)
            metrics['loading_times']['scapy'] = scapy_perf.get('loading_time', 0)
            metrics['analysis_times']['scapy'] = scapy_perf.get('analysis_time', 0)
        
        pyshark_results = results.get('pyshark_results')
        if pyshark_results and pyshark_results.get('success', False):
            pyshark_perf = pyshark_results.get('performance', {})
            metrics['pyshark_time'] = pyshark_perf.get('total_time', 0)
            metrics['loading_times']['pyshark'] = pyshark_perf.get('loading_time', 0)
            metrics['analysis_times']['pyshark'] = pyshark_perf.get('analysis_time', 0)
        
        return metrics
    
    def _update_performance_stats(self, results: Dict[str, Any]) -> None:
        """Update performance statistics."""
        scapy_results = results.get('scapy_results')
        if scapy_results and scapy_results.get('success', False):
            scapy_perf = scapy_results.get('performance', {})
            scapy_time = scapy_perf.get('total_time', 0)
            if scapy_time > 0:
                self.analysis_stats['average_scapy_time'] = (
                    (self.analysis_stats['average_scapy_time'] * self.analysis_stats['scapy_analyses'] + scapy_time) /
                    (self.analysis_stats['scapy_analyses'] + 1)
                )
        
        pyshark_results = results.get('pyshark_results')
        if pyshark_results and pyshark_results.get('success', False):
            pyshark_perf = pyshark_results.get('performance', {})
            pyshark_time = pyshark_perf.get('total_time', 0)
            if pyshark_time > 0:
                self.analysis_stats['average_pyshark_time'] = (
                    (self.analysis_stats['average_pyshark_time'] * self.analysis_stats['pyshark_analyses'] + pyshark_time) /
                    (self.analysis_stats['pyshark_analyses'] + 1)
                )
        
        if results.get('comparison'):
            self.analysis_stats['parser_comparison_stats'].append(results['comparison'])
    
    def get_registry_info(self) -> Dict[str, Any]:
        """Get analyzer registry information."""
        return analyzer_registry.get_registry_summary()
    
    def validate_pcap_comprehensive(
        self,
        pcap_file: str,
        max_packets: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Validate PCAP file using both Scapy and PyShark parsers for comprehensive analysis.
        
        Args:
            pcap_file: Path to PCAP file
            max_packets: Maximum number of packets to validate
            
        Returns:
            Dictionary with comprehensive validation results from both parsers
        """
        start_time = time.time()
        self.logger.info(f"Starting comprehensive PCAP validation of {pcap_file}")
        
        # Validate file
        pcap_path = Path(pcap_file)
        if not pcap_path.exists():
            raise AnalysisError(f"PCAP file not found: {pcap_file}")
        
        results = {
            'pcap_file': pcap_file,
            'validation_timestamp': time.time(),
            'max_packets': max_packets,
            'scapy_validation': None,
            'pyshark_validation': None,
            'comparison': None,
            'summary': {},
            'recommendations': []
        }
        
        # Run both validations in parallel
        with ThreadPoolExecutor(max_workers=2) as executor:
            scapy_future = executor.submit(self._validate_scapy, pcap_file, max_packets)
            pyshark_future = executor.submit(self._validate_pyshark, pcap_file, max_packets)
            
            # Collect results
            for future in as_completed([scapy_future, pyshark_future]):
                try:
                    if future == scapy_future:
                        results['scapy_validation'] = future.result()
                        self.logger.info("Scapy validation completed")
                    else:
                        results['pyshark_validation'] = future.result()
                        self.logger.info("PyShark validation completed")
                except Exception as e:
                    parser_name = 'Scapy' if future == scapy_future else 'PyShark'
                    self.logger.error(f"{parser_name} validation failed: {e}")
                    failed_result = {
                        'parser': parser_name.lower(),
                        'success': False,
                        'error': str(e),
                        'validation_time': 0
                    }
                    if future == scapy_future:
                        results['scapy_validation'] = failed_result
                    else:
                        results['pyshark_validation'] = failed_result
        
        # Generate comparison and summary
        results['comparison'] = self._compare_validation_results(
            results['scapy_validation'], 
            results['pyshark_validation']
        )
        results['summary'] = self._generate_validation_summary(results)
        results['recommendations'] = self._generate_validation_recommendations(results)
        
        total_time = time.time() - start_time
        results['total_validation_time'] = total_time
        
        self.logger.info(f"Comprehensive PCAP validation complete in {total_time:.2f}s")
        return results

    def _validate_scapy(self, pcap_file: str, max_packets: Optional[int]) -> Dict[str, Any]:
        """Validate PCAP using Scapy parser."""
        start_time = time.time()
        
        try:
            from scapy.all import rdpcap
            from scapy.layers.dot11 import Dot11
            
            self.logger.info("🔍 Starting Scapy validation")
            
            # Load packets
            if max_packets:
                packets = rdpcap(pcap_file, count=max_packets)
            else:
                packets = rdpcap(pcap_file)
                
            total_packets = len(packets)
            dot11_packets = sum(1 for p in packets if p.haslayer(Dot11))
            
            # Analyze packet types
            management_frames = sum(1 for p in packets if p.haslayer(Dot11) and p[Dot11].type == 0)
            control_frames = sum(1 for p in packets if p.haslayer(Dot11) and p[Dot11].type == 1)  
            data_frames = sum(1 for p in packets if p.haslayer(Dot11) and p[Dot11].type == 2)
            
            # Check timestamps
            timestamped_packets = sum(1 for p in packets if hasattr(p, 'time'))
            
            # Check for RadioTap headers
            radiotap_packets = sum(1 for p in packets if p.haslayer('RadioTap'))
            
            validation_time = time.time() - start_time
            
            result = {
                'parser': 'scapy',
                'success': True,
                'error': None,
                'validation_time': validation_time,
                'total_packets': total_packets,
                'dot11_packets': dot11_packets,
                'dot11_percentage': (dot11_packets / max(total_packets, 1)) * 100,
                'frame_types': {
                    'management': management_frames,
                    'control': control_frames,
                    'data': data_frames
                },
                'timestamped_packets': timestamped_packets,
                'radiotap_packets': radiotap_packets,
                'monitor_mode_indicators': {
                    'has_management_frames': management_frames > 0,
                    'has_radiotap': radiotap_packets > 0,
                    'frame_type_diversity': len([x for x in [management_frames, control_frames, data_frames] if x > 0])
                }
            }
            
            self.logger.info(f"✅ Scapy validation complete: {dot11_packets}/{total_packets} 802.11 packets")
            return result
            
        except Exception as e:
            self.logger.error(f"Scapy validation failed: {e}")
            return {
                'parser': 'scapy',
                'success': False,
                'error': str(e),
                'validation_time': time.time() - start_time
            }

    def _validate_pyshark(self, pcap_file: str, max_packets: Optional[int]) -> Dict[str, Any]:
        """Validate PCAP using PyShark parser.""" 
        start_time = time.time()
        
        try:
            import pyshark
            
            self.logger.info("🔍 Starting PyShark validation")
            
            # Open capture
            if max_packets:
                cap = pyshark.FileCapture(pcap_file)
                packets = list(cap)[:max_packets]
                cap.close()
            else:
                cap = pyshark.FileCapture(pcap_file)
                packets = list(cap)
                cap.close()
                
            total_packets = len(packets)
            dot11_packets = sum(1 for p in packets if hasattr(p, 'wlan') or 'wlan' in p)
            
            # Analyze frame types using PyShark
            management_frames = sum(1 for p in packets 
                                 if hasattr(p, 'wlan') and hasattr(p.wlan, 'fc_type') 
                                 and str(p.wlan.fc_type) == '0')
            control_frames = sum(1 for p in packets 
                               if hasattr(p, 'wlan') and hasattr(p.wlan, 'fc_type') 
                               and str(p.wlan.fc_type) == '1')
            data_frames = sum(1 for p in packets 
                            if hasattr(p, 'wlan') and hasattr(p.wlan, 'fc_type') 
                            and str(p.wlan.fc_type) == '2')
            
            # Check timestamps
            timestamped_packets = sum(1 for p in packets if hasattr(p, 'sniff_timestamp'))
            
            # Check for RadioTap 
            radiotap_packets = sum(1 for p in packets if hasattr(p, 'radiotap'))
            
            validation_time = time.time() - start_time
            
            result = {
                'parser': 'pyshark',
                'success': True,
                'error': None,
                'validation_time': validation_time,
                'total_packets': total_packets,
                'dot11_packets': dot11_packets,
                'dot11_percentage': (dot11_packets / max(total_packets, 1)) * 100,
                'frame_types': {
                    'management': management_frames,
                    'control': control_frames,
                    'data': data_frames
                },
                'timestamped_packets': timestamped_packets,
                'radiotap_packets': radiotap_packets,
                'monitor_mode_indicators': {
                    'has_management_frames': management_frames > 0,
                    'has_radiotap': radiotap_packets > 0,
                    'frame_type_diversity': len([x for x in [management_frames, control_frames, data_frames] if x > 0])
                }
            }
            
            self.logger.info(f"✅ PyShark validation complete: {dot11_packets}/{total_packets} 802.11 packets")
            return result
            
        except Exception as e:
            self.logger.error(f"PyShark validation failed: {e}")
            return {
                'parser': 'pyshark', 
                'success': False,
                'error': str(e),
                'validation_time': time.time() - start_time
            }

    def _compare_validation_results(self, scapy_result: Dict[str, Any], pyshark_result: Dict[str, Any]) -> Dict[str, Any]:
        """Compare validation results between parsers."""
        if not scapy_result['success'] or not pyshark_result['success']:
            return {
                'comparison_available': False,
                'reason': 'One or both validations failed'
            }
            
        return {
            'comparison_available': True,
            'packet_count_match': scapy_result['total_packets'] == pyshark_result['total_packets'],
            'dot11_detection_match': abs(scapy_result['dot11_percentage'] - pyshark_result['dot11_percentage']) < 5,
            'performance': {
                'scapy_time': scapy_result['validation_time'],
                'pyshark_time': pyshark_result['validation_time'],
                'faster_parser': 'scapy' if scapy_result['validation_time'] < pyshark_result['validation_time'] else 'pyshark'
            },
            'frame_analysis_consistency': {
                'management_frames_similar': abs(scapy_result['frame_types']['management'] - pyshark_result['frame_types']['management']) < 10,
                'data_frames_similar': abs(scapy_result['frame_types']['data'] - pyshark_result['frame_types']['data']) < 10
            }
        }

    def _generate_validation_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate validation summary."""
        self.logger.info("Generating validation summary")
        scapy = results.get('scapy_validation', {})
        pyshark = results.get('pyshark_validation', {})
        
        return {
            'overall_status': 'success' if scapy.get('success') and pyshark.get('success') else 'partial' if scapy.get('success') or pyshark.get('success') else 'failed',
            'parsers_successful': [p['parser'] for p in [scapy, pyshark] if p.get('success')],
            'parsers_failed': [p['parser'] for p in [scapy, pyshark] if not p.get('success')],
            'wireless_capture_quality': self._assess_capture_quality(scapy, pyshark),
            'monitor_mode_likely': self._assess_monitor_mode(scapy, pyshark)
        }

    def _generate_validation_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate validation recommendations."""
        self.logger.info("Generating validation recommendations")
        recommendations = []
        scapy = results.get('scapy_validation', {})
        pyshark = results.get('pyshark_validation', {})
        
        # Check for low 802.11 percentage
        for parser_result in [scapy, pyshark]:
            if parser_result.get('success') and parser_result.get('dot11_percentage', 0) < 50:
                recommendations.append(f"Low 802.11 packet percentage ({parser_result['dot11_percentage']:.1f}%) detected - consider using monitor mode capture")
                break
                
        # Check for missing monitor mode indicators
        for parser_result in [scapy, pyshark]:
            if parser_result.get('success'):
                indicators = parser_result.get('monitor_mode_indicators', {})
                if not indicators.get('has_management_frames'):
                    recommendations.append("No management frames detected - capture may not be in monitor mode")
                if not indicators.get('has_radiotap'):
                    recommendations.append("No RadioTap headers found - capture may lack RF metadata")
                break
        
        return recommendations

    def _assess_capture_quality(self, scapy: Dict[str, Any], pyshark: Dict[str, Any]) -> str:
        """Assess overall capture quality."""
        for result in [scapy, pyshark]:
            if result.get('success'):
                dot11_pct = result.get('dot11_percentage', 0)
                if dot11_pct >= 80:
                    return 'excellent'
                elif dot11_pct >= 50:
                    return 'good'
                elif dot11_pct >= 20:
                    return 'fair'
                else:
                    return 'poor'
        return 'unknown'

    def _assess_monitor_mode(self, scapy: Dict[str, Any], pyshark: Dict[str, Any]) -> bool:
        """Assess if capture was likely taken in monitor mode."""
        for result in [scapy, pyshark]:
            if result.get('success'):
                indicators = result.get('monitor_mode_indicators', {})
                return (indicators.get('has_management_frames', False) and 
                       indicators.get('frame_type_diversity', 0) >= 2)
        return False

    def _log_validation_summary(self, validation_results: Dict[str, Any]) -> None:
        """Log a concise validation summary during analysis."""
        self.logger.info("Logging validation summary")
        summary = validation_results.get('summary', {})
        scapy_result = validation_results.get('scapy_validation', {})
        pyshark_result = validation_results.get('pyshark_validation', {})
        
        # Overall status
        status = summary.get('overall_status', 'unknown').upper()
        quality = summary.get('wireless_capture_quality', 'unknown').upper()
        monitor_mode = '✅' if summary.get('monitor_mode_likely') else '⚠️'
        
        self.logger.info(f"📊 Validation Summary: {status} | Quality: {quality} | Monitor Mode: {monitor_mode}")
        
        # Parser results
        successful_parsers = summary.get('parsers_successful', [])
        if len(successful_parsers) == 2:
            # Both parsers successful - show brief comparison
            scapy_packets = scapy_result.get('dot11_packets', 0)
            pyshark_packets = pyshark_result.get('dot11_packets', 0)
            scapy_time = scapy_result.get('validation_time', 0)
            pyshark_time = pyshark_result.get('validation_time', 0)
            
            self.logger.info(f"   📡 Scapy: {scapy_packets} 802.11 packets ({scapy_time:.2f}s)")
            self.logger.info(f"   📡 PyShark: {pyshark_packets} 802.11 packets ({pyshark_time:.2f}s)")
        elif len(successful_parsers) == 1:
            parser = successful_parsers[0]
            result = scapy_result if parser == 'scapy' else pyshark_result
            packets = result.get('dot11_packets', 0)
            validation_time = result.get('validation_time', 0)
            
            self.logger.info(f"   📡 {parser.title()}: {packets} 802.11 packets ({validation_time:.2f}s)")
            failed_parser = 'pyshark' if parser == 'scapy' else 'scapy'
            self.logger.warning(f"   ❌ {failed_parser.title()} validation failed")
        
        # Show recommendations if any
        recommendations = validation_results.get('recommendations', [])
        if recommendations:
            self.logger.warning("   💡 Validation recommendations:")
            for rec in recommendations[:2]:  # Show first 2 recommendations
                self.logger.warning(f"      • {rec}")

    def get_analysis_stats(self) -> Dict[str, Any]:
        """Get comprehensive analysis statistics."""
        return dict(self.analysis_stats)