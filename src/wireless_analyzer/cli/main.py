#!/usr/bin/env python3
"""
Command line interface for the wireless PCAP analyzer.

This module provides the main CLI entry point for running
wireless packet analysis from the command line.
"""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Optional, List, Dict, Any

import click

from ..main import WirelessPCAPAnalyzer
from ..core.models import AnalysisError


def setup_logging(level: str = "INFO"):
    """Setup logging configuration."""
    numeric_level = getattr(logging, level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f'Invalid log level: {level}')
        
    logging.basicConfig(
        level=numeric_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )


@click.group()
@click.option('--log-level', default='INFO', 
              type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR']),
              help='Set logging level')
@click.option('--config-file', type=click.Path(exists=True),
              help='Configuration file path')
@click.pass_context
def cli(ctx, log_level: str, config_file: Optional[str]):
    """Wireless PCAP Analysis Framework CLI."""
    setup_logging(log_level)
    
    # Load configuration if provided
    config = {}
    if config_file:
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
        except Exception as e:
            click.echo(f"Error loading config file: {e}", err=True)
            sys.exit(1)
        finally:
            click.echo(f"Using configuration from: {config_file}")
            
    ctx.ensure_object(dict)
    ctx.obj['config'] = config
    ctx.obj['log_level'] = log_level


@cli.command()
@click.argument('pcap_file', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), 
              help='Output file path (default: auto-generated)')
@click.option('--output-dir', type=click.Path(),
              help='Output directory (default: ./results)')
@click.option('--format', '-f', default='json',
              type=click.Choice(['json', 'html', 'markdown', 'md', 'text', 'txt']),
              help='Output format')
@click.option('--max-packets', type=int,
              help='Maximum packets to analyze')
@click.option('--analyzers', multiple=True,
              help='Specific analyzers to run (default: all enabled)')
@click.option('--debug', is_flag=True,
              help='Enable debug mode')
@click.option('--no-expert', is_flag=True,
              help='Disable expert analysis')
@click.option('--quiet', '-q', is_flag=True,
              help='Suppress progress output')
@click.option('--skip-validation', is_flag=True,
              help='Skip pre-analysis PCAP validation')
@click.pass_context
def analyze(ctx, pcap_file: str, output: Optional[str], output_dir: Optional[str], 
           format: str, max_packets: Optional[int], analyzers: tuple,
           debug: bool, no_expert: bool, quiet: bool, skip_validation: bool):
    """Analyze a wireless PCAP file."""
    
    # Enable debug logging if --debug flag is set
    if debug:
        setup_logging("DEBUG")
    
    if not quiet:
        click.echo(f"Analyzing PCAP file: {pcap_file}")
        
    try:
        # Initialize analyzer
        analyzer = WirelessPCAPAnalyzer(config=ctx.obj['config'])
        
        if not quiet and not analyzers:
            enabled_analyzers = [a for a in analyzer.list_analyzers() if a['enabled']]
            click.echo(f"Running {len(enabled_analyzers)} analyzers...")
        elif not quiet:
            click.echo(f"Running {len(analyzers)} specific analyzers...")
            
        # Run dual pipeline analysis (both Scapy and PyShark)
        results = analyzer.analyze_pcap_dual_comparison(
            pcap_file=pcap_file,
            max_packets=max_packets,
            specific_analyzers=list(analyzers) if analyzers else None,
            parallel_execution=True,
            debug_mode=debug,
            skip_validation=skip_validation
        )
        
        # Generate report - handle case where results might be None
        if results:
            report = analyzer.generate_report(
                results, 
                output_format=format,
                include_expert_analysis=not no_expert
            )
        else:
            report = '{"error": "Analysis returned no results"}'
        
        # Determine output file
        if not output:
            pcap_path = Path(pcap_file)
            
            # Get timestamp from results or use current time
            import time
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            
            # Create shorter, more meaningful filename
            pcap_stem = pcap_path.stem
            if len(pcap_stem) > 20:
                # For very long names (like hashes), use first 8 chars + last 4 chars
                short_name = f"{pcap_stem[:8]}...{pcap_stem[-4:]}"
            else:
                short_name = pcap_stem
                
            # Set up output directory
            if output_dir:
                output_path = Path(output_dir)
            else:
                output_path = Path("results")
                
            # Create output directory if it doesn't exist
            output_path.mkdir(parents=True, exist_ok=True)
            
            # Generate final output path
            filename = f"analysis_{short_name}_{timestamp}.{format}"
            output = str(output_path / filename)
            
        # Write output
        with open(output, 'w') as f:
            f.write(report)
            
        if not quiet:
            click.echo(f"\nAnalysis Complete!")
            
            # Get summary from results based on the new format
            if results and ('scapy_results' in results or 'pyshark_results' in results):
                total_findings = 0
                if results.get('scapy_results') and results['scapy_results'].get('success'):
                    total_findings += results['scapy_results'].get('total_findings', 0)
                if results.get('pyshark_results') and results['pyshark_results'].get('success'):
                    total_findings += results['pyshark_results'].get('total_findings', 0)
                    
                click.echo(f"Total Findings: {total_findings}")
            else:
                click.echo("Analysis results available in output file")
                
            click.echo(f"Report saved to: {output}")
            
    except AnalysisError as e:
        click.echo(f"Analysis failed: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Unexpected error: {e}", err=True)
        if ctx.obj['log_level'] == 'DEBUG':
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.command()
@click.pass_context
def list_analyzers(ctx):
    """List all available analyzers."""
    analyzer = WirelessPCAPAnalyzer(config=ctx.obj['config'])
    analyzers = analyzer.list_analyzers()
    
    click.echo("Available Analyzers:")
    click.echo("===================")
    
    current_category = None
    for analyzer_info in analyzers:
        category = analyzer_info['category'].replace('_', ' ').title()
        if category != current_category:
            click.echo(f"\n{category}:")
            current_category = category
            
        status = "✓" if analyzer_info['enabled'] else "✗"
        version_str = f" (v{analyzer_info['version']})" if 'version' in analyzer_info else ""
        click.echo(f"  {status} {analyzer_info['name']}{version_str}")
        if analyzer_info.get('description'):
            click.echo(f"    {analyzer_info['description']}")


@cli.command()
@click.argument('analyzer_name')
@click.pass_context
def enable_analyzer(ctx, analyzer_name: str):
    """Enable a specific analyzer."""
    analyzer = WirelessPCAPAnalyzer(config=ctx.obj['config'])
    
    if analyzer.enable_analyzer(analyzer_name):
        click.echo(f"Enabled analyzer: {analyzer_name}")
    else:
        click.echo(f"Analyzer not found: {analyzer_name}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('analyzer_name')
@click.pass_context  
def disable_analyzer(ctx, analyzer_name: str):
    """Disable a specific analyzer."""
    analyzer = WirelessPCAPAnalyzer(config=ctx.obj['config'])
    
    if analyzer.disable_analyzer(analyzer_name):
        click.echo(f"Disabled analyzer: {analyzer_name}")
    else:
        click.echo(f"Analyzer not found: {analyzer_name}", err=True)
        sys.exit(1)


@cli.command()
@click.pass_context
def performance_stats(ctx):
    """Show analyzer performance statistics."""
    analyzer = WirelessPCAPAnalyzer(config=ctx.obj['config'])
    stats = analyzer.get_performance_stats()
    
    click.echo("Performance Statistics:")
    click.echo("======================")
    click.echo(f"Total Analyses: {stats.get('total_analyses', 0)}")
    click.echo(f"Total Packets Processed: {stats.get('total_packets_processed', 0):,}")
    click.echo(f"Total Analysis Time: {stats.get('total_analysis_time', 0):.2f}s")
    
    if stats.get('total_analyses', 0) > 0:
        click.echo(f"Average Analysis Time: {stats.get('average_analysis_time', 0):.2f}s")
        click.echo(f"Average Packets/Analysis: {stats.get('average_packets_per_analysis', 0):.0f}")
        
    # Per-analyzer stats
    analyzer_perf = stats.get('analyzer_performance', {})
    if analyzer_perf:
        click.echo("\nPer-Analyzer Performance:")
        for analyzer_name, perf in analyzer_perf.items():
            click.echo(f"\n  {analyzer_name}:")
            click.echo(f"    Runs: {perf['total_runs']}")
            click.echo(f"    Total Time: {perf['total_time']:.2f}s")
            click.echo(f"    Avg Time/Run: {perf.get('average_time_per_run', 0):.3f}s")
            click.echo(f"    Total Findings: {perf['total_findings']}")


@cli.command()
@click.argument('pcap_file', type=click.Path(exists=True))
@click.option('--quick', is_flag=True, help='Quick validation (first 1000 packets)')
@click.option('--max-packets', type=int, help='Maximum packets to validate (overrides --quick)')
@click.option('--parser', type=click.Choice(['scapy', 'pyshark', 'both']), 
              default='both', help='Parser to use for validation')
@click.option('--json-output', is_flag=True, help='Output results in JSON format')
@click.pass_context
def validate(ctx, pcap_file: str, quick: bool, max_packets: Optional[int], 
            parser: str, json_output: bool):
    """Validate a PCAP file for wireless analysis using dual-pipeline validation."""
    
    try:
        # Initialize analyzer
        analyzer = WirelessPCAPAnalyzer(config=ctx.obj['config'])
        
        if not json_output:
            click.echo(f"Validating PCAP file: {pcap_file}")
            if parser == 'both':
                click.echo("Running dual-pipeline validation (Scapy + PyShark)...")
            else:
                click.echo(f"Running {parser.title()} validation...")
            
        # Determine packet limit
        packet_limit = max_packets
        if packet_limit is None and quick:
            packet_limit = 1000
            if not json_output:
                click.echo(f"Quick validation mode - analyzing first {packet_limit} packets")
                
        # Run validation
        if parser == 'both':
            results = analyzer.validate_pcap_dual(
                pcap_file=pcap_file,
                quick_mode=quick,
                max_packets=packet_limit
            )
        else:
            # For single parser, we'll still use dual pipeline but report only one
            results = analyzer.validate_pcap_dual(
                pcap_file=pcap_file, 
                quick_mode=quick,
                max_packets=packet_limit
            )
            
        # Output results
        if json_output:
            import json
            click.echo(json.dumps(results, indent=2, default=str))
        else:
            _display_validation_results(results, parser)
            
    except AnalysisError as e:
        if json_output:
            click.echo(json.dumps({"error": str(e)}))
        else:
            click.echo(f"Validation error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        if json_output:
            click.echo(json.dumps({"error": str(e)}))
        else:
            click.echo(f"Unexpected validation error: {e}", err=True)
        sys.exit(1)


def _display_validation_results(results: Dict[str, Any], parser_filter: str):
    """Display validation results in human-readable format."""
    
    click.echo(f"\n📊 Validation Results")
    click.echo(f"=====================")
    
    # Overall summary
    summary = results.get('summary', {})
    click.echo(f"Overall Status: {summary.get('overall_status', 'unknown').upper()}")
    click.echo(f"Capture Quality: {summary.get('wireless_capture_quality', 'unknown').upper()}")
    click.echo(f"Monitor Mode: {'✅ Likely' if summary.get('monitor_mode_likely') else '⚠️  Unlikely'}")
    
    # Parser-specific results
    scapy_result = results.get('scapy_validation', {})
    pyshark_result = results.get('pyshark_validation', {})
    
    if parser_filter in ['both', 'scapy'] and scapy_result:
        _display_parser_results("Scapy", scapy_result)
        
    if parser_filter in ['both', 'pyshark'] and pyshark_result:
        _display_parser_results("PyShark", pyshark_result)
    
    # Comparison (only for dual mode)
    if parser_filter == 'both':
        comparison = results.get('comparison', {})
        if comparison.get('comparison_available'):
            click.echo(f"\n🔄 Parser Comparison")
            click.echo(f"===================")
            click.echo(f"Packet Count Match: {'✅' if comparison.get('packet_count_match') else '❌'}")
            click.echo(f"802.11 Detection Match: {'✅' if comparison.get('dot11_detection_match') else '❌'}")
            
            perf = comparison.get('performance', {})
            click.echo(f"Faster Parser: {perf.get('faster_parser', 'unknown').title()}")
            click.echo(f"Performance: Scapy {perf.get('scapy_time', 0):.2f}s | PyShark {perf.get('pyshark_time', 0):.2f}s")
    
    # Recommendations
    recommendations = results.get('recommendations', [])
    if recommendations:
        click.echo(f"\n💡 Recommendations")
        click.echo(f"==================")
        for rec in recommendations:
            click.echo(f"• {rec}")


def _display_parser_results(parser_name: str, result: Dict[str, Any]):
    """Display results for a specific parser."""
    click.echo(f"\n📡 {parser_name} Results")
    click.echo(f"{'='*(len(parser_name)+10)}")
    
    if not result.get('success'):
        click.echo(f"❌ {parser_name} validation failed: {result.get('error', 'Unknown error')}")
        return
        
    total = result.get('total_packets', 0)
    dot11 = result.get('dot11_packets', 0)
    dot11_pct = result.get('dot11_percentage', 0)
    
    click.echo(f"Total Packets: {total:,}")
    click.echo(f"802.11 Packets: {dot11:,} ({dot11_pct:.1f}%)")
    
    # Frame type breakdown
    frames = result.get('frame_types', {})
    click.echo(f"Frame Types:")
    click.echo(f"  Management: {frames.get('management', 0):,}")
    click.echo(f"  Control: {frames.get('control', 0):,}")
    click.echo(f"  Data: {frames.get('data', 0):,}")
    
    # Timestamps and RadioTap
    timestamped = result.get('timestamped_packets', 0)
    radiotap = result.get('radiotap_packets', 0)
    
    click.echo(f"Timestamped Packets: {timestamped:,}")
    click.echo(f"RadioTap Headers: {radiotap:,}")
    
    # Quality assessment
    if dot11_pct == 0:
        click.echo("❌ No 802.11 packets found - this may not be a wireless capture")
    elif dot11_pct < 50:
        click.echo("⚠️  Low 802.11 percentage - mixed capture or potential issues")
    else:
        click.echo("✅ Good 802.11 packet percentage detected")
        
    # Monitor mode indicators
    indicators = result.get('monitor_mode_indicators', {})
    if indicators.get('has_management_frames'):
        click.echo("✅ Management frames present - likely monitor mode")
    else:
        click.echo("⚠️  No management frames - may not be monitor mode")
        
    if indicators.get('has_radiotap'):
        click.echo("✅ RadioTap headers present - RF metadata available")
    else:
        click.echo("⚠️  No RadioTap headers - limited RF information")
        
    click.echo(f"Validation Time: {result.get('validation_time', 0):.2f}s")


@cli.command()
@click.option('--category', type=click.Choice([
    'capture_quality', 'rf_phy', 'beacons', 'probe_behavior', 'auth_assoc',
    'enterprise_security', 'eapol_handshake', 'data_control_plane', 'qos_wmm',
    'power_save', 'roaming_steering', 'multicast_broadcast', 'ip_onboarding',
    'coexistence_dfs', 'security_threats', 'band_6ghz', 'mlo_be',
    'client_profiling', 'ap_behavior', 'app_performance', 'hotspot_passpoint',
    'metrics_computation', 'anomaly_detection'
]), help='Show filters for specific category only')
@click.pass_context
def show_filters(ctx, category: Optional[str]):
    """Show Wireshark display filters for analyzers."""
    analyzer = WirelessPCAPAnalyzer(config=ctx.obj['config'])
    analyzers = analyzer.list_analyzers()
    
    click.echo("Wireshark Display Filters:")
    click.echo("=========================")
    
    for analyzer_info in analyzers:
        if category and analyzer_info['category'] != category:
            continue
            
        if analyzer_info.get('wireshark_filters'):
            click.echo(f"\n{analyzer_info['name']}:")
            for filter_str in analyzer_info['wireshark_filters']:
                click.echo(f"  {filter_str}")
        elif not category:
            click.echo(f"\n{analyzer_info['name']}: (no specific filters)")


@cli.command()
@click.argument('pcap_file', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), 
              help='Output file path (default: auto-generated)')
@click.option('--output-dir', type=click.Path(),
              help='Output directory (default: ./results)')
@click.option('--format', '-f', default='json',
              type=click.Choice(['json', 'html', 'markdown', 'md', 'text', 'txt']),
              help='Output format')
@click.option('--max-packets', type=int,
              help='Maximum packets to analyze')
@click.option('--analyzers', multiple=True,
              help='Specific analyzers to run (default: all enabled)')
@click.option('--categories', multiple=True,
              help='Specific analyzer categories to run')
@click.option('--sequential', is_flag=True,
              help='Run pipelines sequentially instead of parallel')
@click.option('--debug', is_flag=True,
              help='Enable debug mode')
@click.option('--no-expert', is_flag=True,
              help='Disable expert analysis')
@click.option('--quiet', '-q', is_flag=True,
              help='Suppress progress output')
@click.option('--skip-validation', is_flag=True,
              help='Skip pre-analysis PCAP validation')
@click.pass_context
def compare(ctx, pcap_file: str, output: Optional[str], output_dir: Optional[str], 
           format: str, max_packets: Optional[int], analyzers: tuple, categories: tuple,
           sequential: bool, debug: bool, no_expert: bool, quiet: bool, skip_validation: bool):
    """Analyze a wireless PCAP file using both Scapy and PyShark for comparison."""
    
    if not quiet:
        click.echo(f"Comparing PCAP file: {pcap_file}")
        click.echo("Running dual pipeline analysis (Scapy + PyShark)...")
        
    try:
        # Initialize analyzer
        analyzer = WirelessPCAPAnalyzer(config=ctx.obj['config'])
        
        if not quiet and not analyzers:
            enabled_analyzers = [a for a in analyzer.list_analyzers() if a['enabled']]
            click.echo(f"Running {len(enabled_analyzers)} analyzers on both pipelines...")
        elif not quiet:
            click.echo(f"Running {len(analyzers)} specific analyzers on both pipelines...")
            
        # Run dual pipeline analysis
        results = analyzer.analyze_pcap_dual_comparison(
            pcap_file=pcap_file,
            max_packets=max_packets,
            analyzer_categories=list(categories) if categories else None,
            specific_analyzers=list(analyzers) if analyzers else None,
            parallel_execution=not sequential,
            debug_mode=debug,
            skip_validation=skip_validation
        )
        
        # Generate report - handle case where results might be None
        if results:
            report = analyzer.generate_report(
                results, 
                output_format=format,
                include_expert_analysis=not no_expert
            )
        else:
            report = '{"error": "Dual pipeline analysis returned no results"}'
        
        # Determine output file
        if not output:
            pcap_path = Path(pcap_file)
            
            # Get timestamp from results or use current time
            import time
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            
            # Create shorter, more meaningful filename
            pcap_stem = pcap_path.stem
            if len(pcap_stem) > 20:
                # For very long names (like hashes), use first 8 chars + last 4 chars
                short_name = f"{pcap_stem[:8]}...{pcap_stem[-4:]}"
            else:
                short_name = pcap_stem
                
            # Set up output directory
            if output_dir:
                output_path = Path(output_dir)
            else:
                output_path = Path("results")
                
            # Create output directory if it doesn't exist
            output_path.mkdir(parents=True, exist_ok=True)
            
            # Generate final output path
            filename = f"comparison_{short_name}_{timestamp}.{format}"
            output = str(output_path / filename)
            
        # Write output
        with open(output, 'w') as f:
            f.write(report)
            
        if not quiet:
            click.echo(f"\n✅ Dual pipeline analysis complete!")
            click.echo(f"📊 Report saved to: {output}")
            
            # Show basic comparison summary
            if results and results.get('comparison') and results['comparison'].get('comparison_available'):
                comparison = results['comparison']
                click.echo(f"\n📈 Quick Comparison:")
                click.echo(f"   Scapy findings: {comparison['findings_comparison']['scapy_total']}")
                click.echo(f"   PyShark findings: {comparison['findings_comparison']['pyshark_total']}")
                click.echo(f"   Performance winner: {comparison['performance_winner']}")
                click.echo(f"   Detection winner: {comparison['detection_winner']}")
                
    except AnalysisError as e:
        click.echo(f"Analysis error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Unexpected error: {e}", err=True)
        if ctx.obj['log_level'] == 'DEBUG':
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.command()
@click.pass_context
def version(ctx):
    """Show version information."""
    click.echo("Wireless PCAP Analysis Framework")
    click.echo("Version: 0.1.0")
    click.echo("Author: Your Name")
    click.echo("\nDependencies:")
    
    try:
        import scapy
        click.echo(f"  Scapy: {scapy.__version__}")
    except:
        click.echo("  Scapy: Not available")
        
    try:
        import click as click_module
        click.echo(f"  Click: {click_module.__version__}")
    except:
        click.echo("  Click: Version unknown")


def main():
    """Main CLI entry point."""
    try:
        cli()
    except KeyboardInterrupt:
        click.echo("\nOperation cancelled by user", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Unexpected error: {e}", err=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
