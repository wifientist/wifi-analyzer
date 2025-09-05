"""
Dual-Pipeline Wireless PCAP Analyzer.

This analyzer runs both Scapy and PyShark parsing pipelines independently,
providing comprehensive analysis with parser-specific results and comparison.
"""

import time
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from .models import (
    AnalysisResults,
    AnalysisContext,
    AnalysisMetrics,
    Finding,
    Severity,
    AnalysisCategory,
    AnalysisError
)

from ..loaders.scapy_loader import ScapyPacketLoader
from ..loaders.pyshark_loader import PySharkPacketLoader
from ..analyzers.scapy.baseline.beacon_inventory import ScapyBeaconInventoryAnalyzer
from ..analyzers.pyshark.baseline.beacon_inventory import PySharkBeaconInventoryAnalyzer


class DualPipelineAnalyzer:
    """
    Dual-Pipeline Wireless PCAP Analyzer.
    
    This class orchestrates analysis using both Scapy and PyShark parsers,
    allowing for comprehensive analysis and parser comparison.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the dual-pipeline analyzer.
        
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
            'parser_comparison_stats': []
        }
    
    def analyze_pcap_dual(
        self,
        pcap_file: str,
        max_packets: Optional[int] = None,
        run_both: bool = True,
        run_scapy: bool = True,
        run_pyshark: bool = True,
        debug_mode: bool = False,
        debug_pause_on_first: bool = False
    ) -> Dict[str, Any]:
        """
        Analyze PCAP file using dual pipelines.
        
        Args:
            pcap_file: Path to PCAP file
            max_packets: Maximum number of packets to analyze
            run_both: Run both pipelines (overrides individual flags)
            run_scapy: Run Scapy pipeline
            run_pyshark: Run PyShark pipeline
            debug_mode: Enable debug logging
            debug_pause_on_first: Pause on first beacon for debugging
            
        Returns:
            Dictionary with results from both pipelines
        """
        start_time = time.time()
        self.logger.info(f"Starting dual-pipeline analysis of {pcap_file}")
        
        # Validate file
        pcap_path = Path(pcap_file)
        if not pcap_path.exists():
            raise AnalysisError(f"PCAP file not found: {pcap_file}")
        
        # Determine which pipelines to run
        if run_both:
            run_scapy = run_pyshark = True
        
        results = {
            'pcap_file': pcap_file,
            'analysis_timestamp': time.time(),
            'config': {
                'max_packets': max_packets,
                'run_scapy': run_scapy,
                'run_pyshark': run_pyshark,
                'debug_mode': debug_mode,
                'debug_pause_on_first': debug_pause_on_first
            },
            'scapy_results': None,
            'pyshark_results': None,
            'comparison': None,
            'performance': {}
        }
        
        # Run pipelines (potentially in parallel)
        if run_scapy and run_pyshark and not debug_pause_on_first:
            # Run both in parallel (no debug pause to avoid conflicts)
            self.logger.info("Running both pipelines in parallel")
            scapy_result, pyshark_result = self._run_pipelines_parallel(
                pcap_file, max_packets, debug_mode, debug_pause_on_first
            )
            results['scapy_results'] = scapy_result
            results['pyshark_results'] = pyshark_result
            self.analysis_stats['dual_analyses'] += 1
            
        else:
            # Run sequentially or single pipeline
            if run_scapy:
                self.logger.info("Running Scapy pipeline")
                results['scapy_results'] = self._run_scapy_pipeline(
                    pcap_file, max_packets, debug_mode, debug_pause_on_first
                )
                self.analysis_stats['scapy_analyses'] += 1
                
            if run_pyshark:
                self.logger.info("Running PyShark pipeline")
                results['pyshark_results'] = self._run_pyshark_pipeline(
                    pcap_file, max_packets, debug_mode, debug_pause_on_first
                )
                self.analysis_stats['pyshark_analyses'] += 1
        
        # Generate comparison if both ran
        if results['scapy_results'] and results['pyshark_results']:
            results['comparison'] = self._compare_results(
                results['scapy_results'], 
                results['pyshark_results']
            )
        
        # Performance metrics
        total_time = time.time() - start_time
        results['performance'] = {
            'total_analysis_time': total_time,
            'scapy_time': results['scapy_results']['performance']['analysis_time'] if results['scapy_results'] else 0,
            'pyshark_time': results['pyshark_results']['performance']['analysis_time'] if results['pyshark_results'] else 0,
        }
        
        self.analysis_stats['total_analyses'] += 1
        self._update_performance_stats(results)
        
        self.logger.info(f"Dual-pipeline analysis complete in {total_time:.2f}s")
        
        return results
    
    def _run_pipelines_parallel(
        self,
        pcap_file: str,
        max_packets: Optional[int],
        debug_mode: bool,
        debug_pause_on_first: bool
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Run both pipelines in parallel using ThreadPoolExecutor."""
        
        with ThreadPoolExecutor(max_workers=2) as executor:
            # Submit both tasks
            scapy_future = executor.submit(
                self._run_scapy_pipeline, pcap_file, max_packets, debug_mode, debug_pause_on_first
            )
            pyshark_future = executor.submit(
                self._run_pyshark_pipeline, pcap_file, max_packets, debug_mode, debug_pause_on_first
            )
            
            # Wait for completion
            scapy_result = None
            pyshark_result = None
            
            for future in as_completed([scapy_future, pyshark_future]):
                try:
                    if future == scapy_future:
                        scapy_result = future.result()
                    else:
                        pyshark_result = future.result()
                except Exception as e:
                    self.logger.error(f"Pipeline failed: {e}")
                    # Continue with the other pipeline
        
        return scapy_result, pyshark_result
    
    def _run_scapy_pipeline(
        self,
        pcap_file: str,
        max_packets: Optional[int],
        debug_mode: bool,
        debug_pause_on_first: bool
    ) -> Dict[str, Any]:
        """Run the Scapy analysis pipeline."""
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
            
            # Create analyzer
            analyzer = ScapyBeaconInventoryAnalyzer(
                debug_mode=debug_mode,
                debug_pause_on_first=debug_pause_on_first
            )
            
            # Filter beacon packets
            beacon_packets = [pkt for pkt in packets if analyzer.is_applicable(pkt)]
            
            self.logger.info(f"Scapy: Found {len(beacon_packets)} beacon frames out of {len(packets)} packets")
            
            # Run analysis
            analysis_start = time.time()
            findings = analyzer.analyze(beacon_packets, context)
            analysis_time = time.time() - analysis_start
            
            # Build result
            result = {
                'parser': 'scapy',
                'success': True,
                'error': None,
                'loading_metadata': loading_metadata,
                'total_packets': len(packets),
                'beacon_packets': len(beacon_packets),
                'beacon_applicability_rate': len(beacon_packets) / len(packets) if packets else 0,
                'findings': findings,
                'bss_inventory': analyzer.bss_inventory,
                'inventory_summary': analyzer.get_inventory_summary(),
                'performance': {
                    'loading_time': loading_metadata['loading_time'],
                    'analysis_time': analysis_time,
                    'total_time': time.time() - pipeline_start
                }
            }
            
            self.logger.info(
                f"Scapy pipeline complete: {len(findings)} findings, "
                f"{len(analyzer.bss_inventory)} networks in {result['performance']['total_time']:.2f}s"
            )
            
            return result
            
        except Exception as e:
            self.logger.error(f"Scapy pipeline failed: {e}")
            return {
                'parser': 'scapy',
                'success': False,
                'error': str(e),
                'performance': {'total_time': time.time() - pipeline_start}
            }
    
    def _run_pyshark_pipeline(
        self,
        pcap_file: str,
        max_packets: Optional[int],
        debug_mode: bool,
        debug_pause_on_first: bool
    ) -> Dict[str, Any]:
        """Run the PyShark analysis pipeline."""
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
            
            # Create analyzer
            analyzer = PySharkBeaconInventoryAnalyzer(
                debug_mode=debug_mode,
                debug_pause_on_first=debug_pause_on_first
            )
            
            # Filter beacon packets
            beacon_packets = [pkt for pkt in packets if analyzer.is_applicable(pkt)]
            
            self.logger.info(f"PyShark: Found {len(beacon_packets)} beacon frames out of {len(packets)} packets")
            
            # Run analysis
            analysis_start = time.time()
            findings = analyzer.analyze(beacon_packets, context)
            analysis_time = time.time() - analysis_start
            
            # Build result
            result = {
                'parser': 'pyshark',
                'success': True,
                'error': None,
                'loading_metadata': loading_metadata,
                'total_packets': len(packets),
                'beacon_packets': len(beacon_packets),
                'beacon_applicability_rate': len(beacon_packets) / len(packets) if packets else 0,
                'findings': findings,
                'bss_inventory': analyzer.bss_inventory,
                'inventory_summary': analyzer.get_inventory_summary(),
                'performance': {
                    'loading_time': loading_metadata['loading_time'],
                    'analysis_time': analysis_time,
                    'total_time': time.time() - pipeline_start
                }
            }
            
            self.logger.info(
                f"PyShark pipeline complete: {len(findings)} findings, "
                f"{len(analyzer.bss_inventory)} networks in {result['performance']['total_time']:.2f}s"
            )
            
            return result
            
        except Exception as e:
            self.logger.error(f"PyShark pipeline failed: {e}")
            return {
                'parser': 'pyshark',
                'success': False,
                'error': str(e),
                'performance': {'total_time': time.time() - pipeline_start}
            }
    
    def _compare_results(
        self,
        scapy_result: Dict[str, Any],
        pyshark_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Compare results from both pipelines."""
        
        if not scapy_result['success'] or not pyshark_result['success']:
            return {
                'comparison_available': False,
                'reason': 'One or both pipelines failed'
            }
        
        comparison = {
            'comparison_available': True,
            'packet_counts': {
                'scapy_total': scapy_result['total_packets'],
                'pyshark_total': pyshark_result['total_packets'],
                'scapy_beacons': scapy_result['beacon_packets'],
                'pyshark_beacons': pyshark_result['beacon_packets'],
                'beacon_count_diff': scapy_result['beacon_packets'] - pyshark_result['beacon_packets']
            },
            'performance': {
                'scapy_loading_time': scapy_result['performance']['loading_time'],
                'pyshark_loading_time': pyshark_result['performance']['loading_time'],
                'scapy_analysis_time': scapy_result['performance']['analysis_time'],
                'pyshark_analysis_time': pyshark_result['performance']['analysis_time'],
                'loading_time_diff': scapy_result['performance']['loading_time'] - pyshark_result['performance']['loading_time'],
                'analysis_time_diff': scapy_result['performance']['analysis_time'] - pyshark_result['performance']['analysis_time']
            },
            'findings': {
                'scapy_count': len(scapy_result['findings']),
                'pyshark_count': len(pyshark_result['findings']),
                'findings_diff': len(scapy_result['findings']) - len(pyshark_result['findings'])
            },
            'network_inventory': {
                'scapy_networks': len(scapy_result['bss_inventory']),
                'pyshark_networks': len(pyshark_result['bss_inventory']),
                'networks_diff': len(scapy_result['bss_inventory']) - len(pyshark_result['bss_inventory'])
            }
        }
        
        # Compare network detection overlap
        scapy_bssids = set(scapy_result['bss_inventory'].keys())
        pyshark_bssids = set(pyshark_result['bss_inventory'].keys())
        
        comparison['network_overlap'] = {
            'common_networks': len(scapy_bssids & pyshark_bssids),
            'scapy_only': len(scapy_bssids - pyshark_bssids),
            'pyshark_only': len(pyshark_bssids - scapy_bssids),
            'overlap_percentage': (len(scapy_bssids & pyshark_bssids) / max(len(scapy_bssids), len(pyshark_bssids))) * 100 if scapy_bssids or pyshark_bssids else 0
        }
        
        # Performance winner
        scapy_total_time = scapy_result['performance']['total_time']
        pyshark_total_time = pyshark_result['performance']['total_time']
        
        if scapy_total_time < pyshark_total_time:
            comparison['performance_winner'] = 'scapy'
            comparison['performance_advantage'] = f"{((pyshark_total_time - scapy_total_time) / pyshark_total_time * 100):.1f}% faster"
        else:
            comparison['performance_winner'] = 'pyshark'
            comparison['performance_advantage'] = f"{((scapy_total_time - pyshark_total_time) / scapy_total_time * 100):.1f}% faster"
        
        # Detection winner (more beacons found = better)
        if scapy_result['beacon_packets'] > pyshark_result['beacon_packets']:
            comparison['detection_winner'] = 'scapy'
        elif pyshark_result['beacon_packets'] > scapy_result['beacon_packets']:
            comparison['detection_winner'] = 'pyshark'
        else:
            comparison['detection_winner'] = 'tie'
        
        return comparison
    
    def _update_performance_stats(self, results: Dict[str, Any]) -> None:
        """Update performance statistics."""
        if results['scapy_results'] and results['scapy_results']['success']:
            scapy_time = results['scapy_results']['performance']['total_time']
            self.analysis_stats['average_scapy_time'] = (
                (self.analysis_stats['average_scapy_time'] * self.analysis_stats['scapy_analyses'] + scapy_time) /
                (self.analysis_stats['scapy_analyses'] + 1)
            )
        
        if results['pyshark_results'] and results['pyshark_results']['success']:
            pyshark_time = results['pyshark_results']['performance']['total_time']
            self.analysis_stats['average_pyshark_time'] = (
                (self.analysis_stats['average_pyshark_time'] * self.analysis_stats['pyshark_analyses'] + pyshark_time) /
                (self.analysis_stats['pyshark_analyses'] + 1)
            )
        
        if results['comparison']:
            self.analysis_stats['parser_comparison_stats'].append(results['comparison'])
    
    def get_analysis_stats(self) -> Dict[str, Any]:
        """Get comprehensive analysis statistics."""
        return dict(self.analysis_stats)