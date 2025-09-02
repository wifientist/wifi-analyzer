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
from typing import Optional, List

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
            
    ctx.ensure_object(dict)
    ctx.obj['config'] = config
    ctx.obj['log_level'] = log_level


@cli.command()
@click.argument('pcap_file', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), 
              help='Output file path (default: auto-generated)')
@click.option('--format', '-f', default='json',
              type=click.Choice(['json', 'html', 'text']),
              help='Output format')
@click.option('--max-packets', type=int,
              help='Maximum packets to analyze')
@click.option('--analyzers', multiple=True,
              help='Specific analyzers to run (default: all enabled)')
@click.option('--no-expert', is_flag=True,
              help='Disable expert analysis')
@click.option('--quiet', '-q', is_flag=True,
              help='Suppress progress output')
@click.pass_context
def analyze(ctx, pcap_file: str, output: Optional[str], format: str,
           max_packets: Optional[int], analyzers: tuple, 
           no_expert: bool, quiet: bool):
    """Analyze a wireless PCAP file."""
    
    if not quiet:
        click.echo(f"Analyzing PCAP file: {pcap_file}")
        
    try:
        # Initialize analyzer
        analyzer = WirelessPCAPAnalyzer(config=ctx.obj['config'])
        
        if not quiet and not analyzers:
            click.echo(f"Running {len(analyzer.registry.get_enabled_analyzers())} analyzers...")
        elif not quiet:
            click.echo(f"Running {len(analyzers)} specific analyzers...")
            
        # Run analysis
        results = analyzer.analyze_pcap(
            pcap_file=pcap_file,
            max_packets=max_packets,
            analyzers=list(analyzers) if analyzers else None
        )
        
        # Generate report
        report = analyzer.generate_report(
            results, 
            output_format=format,
            include_expert_analysis=not no_expert
        )
        
        # Determine output file
        if not output:
            pcap_path = Path(pcap_file)
            timestamp = results.analysis_timestamp.strftime("%Y%m%d_%H%M%S")
            output = f"{pcap_path.stem}_analysis_{timestamp}.{format}"
            
        # Write output
        with open(output, 'w') as f:
            f.write(report)
            
        if not quiet:
            summary = results.get_summary_stats()
            click.echo(f"\nAnalysis Complete!")
            click.echo(f"Total Findings: {summary['total_findings']}")
            click.echo(f"Critical: {summary['findings_by_severity']['critical']}")
            click.echo(f"Warning: {summary['findings_by_severity']['warning']}")
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
        click.echo(f"  {status} {analyzer_info['name']} (v{analyzer_info['version']})")
        if analyzer_info['description']:
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
@click.pass_context
def validate(ctx, pcap_file: str, quick: bool):
    """Validate a PCAP file for wireless analysis."""
    
    try:
        from scapy.all import rdpcap
        from scapy.layers.dot11 import Dot11
        
        click.echo(f"Validating PCAP file: {pcap_file}")
        
        # Load packets
        if quick:
            click.echo("Quick validation mode - analyzing first 1000 packets")
            packets = rdpcap(pcap_file, count=1000)
        else:
            packets = rdpcap(pcap_file)
            
        total_packets = len(packets)
        dot11_packets = sum(1 for p in packets if p.haslayer(Dot11))
        
        click.echo(f"\nValidation Results:")
        click.echo(f"==================")
        click.echo(f"Total Packets: {total_packets:,}")
        click.echo(f"802.11 Packets: {dot11_packets:,}")
        click.echo(f"802.11 Percentage: {(dot11_packets/max(total_packets,1)*100):.1f}%")
        
        if dot11_packets == 0:
            click.echo("❌ No 802.11 packets found - this may not be a wireless capture", err=True)
            sys.exit(1)
        elif dot11_packets < total_packets * 0.5:
            click.echo("⚠️  Less than 50% 802.11 packets - mixed capture detected")
        else:
            click.echo("✅ Good wireless capture detected")
            
        # Check for monitor mode indicators
        management_frames = sum(1 for p in packets if p.haslayer(Dot11) and p[Dot11].type == 0)
        if management_frames > 0:
            click.echo("✅ Management frames present - likely monitor mode capture")
        else:
            click.echo("⚠️  No management frames - may not be monitor mode")
            
        # Check for timestamps
        timestamped_packets = sum(1 for p in packets if hasattr(p, 'time'))
        if timestamped_packets > 0:
            click.echo(f"✅ {timestamped_packets:,} packets have timestamps")
        else:
            click.echo("⚠️  No timestamp information found")
            
    except Exception as e:
        click.echo(f"Validation failed: {e}", err=True)
        sys.exit(1)


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
            
        if analyzer_info['wireshark_filters']:
            click.echo(f"\n{analyzer_info['name']}:")
            for filter_str in analyzer_info['wireshark_filters']:
                click.echo(f"  {filter_str}")
        elif not category:
            click.echo(f"\n{analyzer_info['name']}: (no specific filters)")


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
