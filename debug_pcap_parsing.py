#!/usr/bin/env python3
"""
PCAP Parsing Diagnostic Tool

This script helps diagnose why your wireless PCAP analyzers aren't getting 
enough packet detail. It tests different parsing approaches and provides
detailed diagnostics.
"""

import sys
import os
import logging
import time
from pathlib import Path

# Add src to path so we can import our modules
sys.path.insert(0, 'src')

try:
    from wireless_analyzer.utils.enhanced_packet_parser import EnhancedPacketParser
    ENHANCED_PARSER_AVAILABLE = True
except ImportError as e:
    print(f"Enhanced parser not available: {e}")
    ENHANCED_PARSER_AVAILABLE = False

# Try to import and test basic Scapy functionality
try:
    from scapy.all import rdpcap, Packet
    from scapy.layers.dot11 import Dot11
    SCAPY_AVAILABLE = True
except ImportError as e:
    print(f"Scapy not available: {e}")
    SCAPY_AVAILABLE = False

def setup_logging():
    """Setup detailed logging for diagnostics."""
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('pcap_parsing_debug.log')
        ]
    )
    return logging.getLogger(__name__)

def basic_scapy_test(pcap_file: str, max_packets: int = 50):
    """Basic Scapy parsing test with detailed diagnostics."""
    logger = logging.getLogger(__name__)
    
    print(f"\n=== Basic Scapy Test: {pcap_file} ===")
    
    if not SCAPY_AVAILABLE:
        print("❌ Scapy not available")
        return None
        
    try:
        start_time = time.time()
        packets = rdpcap(pcap_file)
        load_time = time.time() - start_time
        
        if max_packets:
            packets = packets[:max_packets]
            
        print(f"✅ Loaded {len(packets)} packets in {load_time:.2f}s")
        
        # Analyze packet composition
        layer_stats = {}
        dot11_packets = 0
        radiotap_packets = 0
        timestamp_packets = 0
        
        sample_details = []
        
        for i, packet in enumerate(packets[:10]):  # Analyze first 10 in detail
            # Count layers
            layers = []
            layer = packet
            while layer:
                layer_name = layer.__class__.__name__
                layers.append(layer_name)
                layer_stats[layer_name] = layer_stats.get(layer_name, 0) + 1
                layer = layer.payload if hasattr(layer, 'payload') else None
                
            # Check for 802.11
            has_dot11 = packet.haslayer(Dot11)
            if has_dot11:
                dot11_packets += 1
                
            # Check for RadioTap
            has_radiotap = 'RadioTap' in layers
            if has_radiotap:
                radiotap_packets += 1
                
            # Check timestamp
            has_timestamp = hasattr(packet, 'time')
            if has_timestamp:
                timestamp_packets += 1
                
            # Detailed analysis of first few packets
            if i < 5:
                details = {
                    'packet_index': i,
                    'layers': ' -> '.join(layers),
                    'has_dot11': has_dot11,
                    'has_radiotap': has_radiotap,
                    'has_timestamp': has_timestamp
                }
                
                # Try to extract basic 802.11 info
                if has_dot11:
                    try:
                        dot11 = packet[Dot11]
                        details['addresses'] = {
                            'addr1': str(dot11.addr1) if hasattr(dot11, 'addr1') and dot11.addr1 else None,
                            'addr2': str(dot11.addr2) if hasattr(dot11, 'addr2') and dot11.addr2 else None,
                            'addr3': str(dot11.addr3) if hasattr(dot11, 'addr3') and dot11.addr3 else None
                        }
                        details['frame_type'] = getattr(dot11, 'type', None)
                        details['frame_subtype'] = getattr(dot11, 'subtype', None)
                    except Exception as e:
                        details['dot11_error'] = str(e)
                        
                # Try to extract RadioTap info
                if has_radiotap:
                    try:
                        from scapy.layers.dot11 import RadioTap
                        if packet.haslayer(RadioTap):
                            radiotap = packet[RadioTap]
                            details['radiotap_fields'] = {}
                            
                            # Common fields
                            if hasattr(radiotap, 'dBm_AntSignal'):
                                details['radiotap_fields']['rssi'] = radiotap.dBm_AntSignal
                            if hasattr(radiotap, 'Channel'):
                                details['radiotap_fields']['channel'] = radiotap.Channel
                            if hasattr(radiotap, 'ChannelFrequency'):
                                details['radiotap_fields']['frequency'] = radiotap.ChannelFrequency
                                
                            # List all available fields
                            fields = [f for f in dir(radiotap) if not f.startswith('_')]
                            details['radiotap_available_fields'] = fields[:10]  # First 10
                            
                    except Exception as e:
                        details['radiotap_error'] = str(e)
                        
                sample_details.append(details)
        
        # Print summary
        print(f"\nPacket Composition:")
        for layer, count in sorted(layer_stats.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / len(packets)) * 100
            print(f"  {layer}: {count} ({percentage:.1f}%)")
            
        print(f"\n802.11 Analysis:")
        print(f"  Packets with Dot11 layer: {dot11_packets}/{len(packets)} ({100*dot11_packets/len(packets):.1f}%)")
        print(f"  Packets with RadioTap: {radiotap_packets}/{len(packets)} ({100*radiotap_packets/len(packets):.1f}%)")
        print(f"  Packets with timestamps: {timestamp_packets}/{len(packets)} ({100*timestamp_packets/len(packets):.1f}%)")
        
        print(f"\nSample Packet Details:")
        for detail in sample_details:
            print(f"  Packet {detail['packet_index']}:")
            print(f"    Layers: {detail['layers']}")
            print(f"    802.11: {detail['has_dot11']}, RadioTap: {detail['has_radiotap']}, Timestamp: {detail['has_timestamp']}")
            
            if 'addresses' in detail:
                addrs = detail['addresses']
                print(f"    Addresses: addr1={addrs['addr1']}, addr2={addrs['addr2']}, addr3={addrs['addr3']}")
                
            if 'radiotap_fields' in detail:
                rt_fields = detail['radiotap_fields']
                print(f"    RadioTap: {rt_fields}")
                
            if 'dot11_error' in detail:
                print(f"    Dot11 Error: {detail['dot11_error']}")
            if 'radiotap_error' in detail:
                print(f"    RadioTap Error: {detail['radiotap_error']}")
                
        return {
            'total_packets': len(packets),
            'dot11_packets': dot11_packets,
            'radiotap_packets': radiotap_packets,
            'timestamp_packets': timestamp_packets,
            'layer_stats': layer_stats,
            'load_time': load_time
        }
        
    except Exception as e:
        print(f"❌ Scapy test failed: {e}")
        logger.exception("Scapy test exception")
        return None

def enhanced_parser_test(pcap_file: str, max_packets: int = 50):
    """Test enhanced parser with multiple libraries."""
    print(f"\n=== Enhanced Parser Test: {pcap_file} ===")
    
    if not ENHANCED_PARSER_AVAILABLE:
        print("❌ Enhanced parser not available")
        return None
        
    try:
        parser = EnhancedPacketParser(prefer_library="auto")
        
        # Run diagnosis
        diagnosis = parser.diagnose_pcap(pcap_file, max_packets)
        
        print("Library Test Results:")
        for library, result in diagnosis['library_results'].items():
            if result['success']:
                stats = result['statistics']
                print(f"  ✅ {library}: {result['packets_parsed']}/{result['total_packets']} packets")
                print(f"    Frame types: {stats.get('frame_types', {})}")
                print(f"    Channels: {len(stats.get('channels', []))} unique")
                print(f"    SSIDs: {len(stats.get('ssids', []))} unique")
                print(f"    RSSI available: {stats.get('rssi_available', 0)} packets")
            else:
                print(f"  ❌ {library}: {result['error']}")
                
        print(f"\nRecommendations:")
        for rec in diagnosis['recommendations']:
            print(f"  • {rec}")
            
        return diagnosis
        
    except Exception as e:
        print(f"❌ Enhanced parser test failed: {e}")
        return None

def analyze_pcap_files(pcap_dir: str = "pcaps"):
    """Analyze all PCAP files in directory."""
    logger = setup_logging()
    
    print("🔍 PCAP Parsing Diagnostic Tool")
    print("=" * 50)
    
    # Find PCAP files
    pcap_path = Path(pcap_dir)
    if not pcap_path.exists():
        print(f"❌ Directory {pcap_dir} not found")
        return
        
    pcap_files = list(pcap_path.glob("*.pcap*"))
    if not pcap_files:
        print(f"❌ No PCAP files found in {pcap_dir}")
        return
        
    print(f"Found {len(pcap_files)} PCAP files:")
    for f in pcap_files:
        size_mb = f.stat().st_size / (1024 * 1024)
        print(f"  • {f.name} ({size_mb:.1f} MB)")
        
    # Analyze each file
    results = {}
    for pcap_file in pcap_files:
        print(f"\n" + "="*60)
        print(f"Analyzing: {pcap_file.name}")
        print("="*60)
        
        file_results = {}
        
        # Basic Scapy test
        scapy_result = basic_scapy_test(str(pcap_file), max_packets=100)
        file_results['scapy'] = scapy_result
        
        # Enhanced parser test
        enhanced_result = enhanced_parser_test(str(pcap_file), max_packets=100)
        file_results['enhanced'] = enhanced_result
        
        results[pcap_file.name] = file_results
        
    # Summary
    print(f"\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    
    for filename, file_results in results.items():
        print(f"\n{filename}:")
        
        scapy_result = file_results.get('scapy')
        if scapy_result:
            dot11_rate = (scapy_result['dot11_packets'] / scapy_result['total_packets']) * 100
            radiotap_rate = (scapy_result['radiotap_packets'] / scapy_result['total_packets']) * 100
            print(f"  Scapy: {dot11_rate:.1f}% 802.11, {radiotap_rate:.1f}% RadioTap")
        else:
            print(f"  Scapy: Failed")
            
        enhanced_result = file_results.get('enhanced')
        if enhanced_result and enhanced_result['library_results']:
            best_lib = None
            best_count = 0
            for lib, result in enhanced_result['library_results'].items():
                if result['success'] and result['packets_parsed'] > best_count:
                    best_lib = lib
                    best_count = result['packets_parsed']
            
            if best_lib:
                print(f"  Best parser: {best_lib} ({best_count} packets)")
            else:
                print(f"  Enhanced: All parsers failed")
        else:
            print(f"  Enhanced: Not tested")
            
    # Recommendations
    print(f"\nRECOMMENDATIONS:")
    
    # Check if any files had low 802.11 detection rates
    low_dot11_files = []
    for filename, file_results in results.items():
        scapy_result = file_results.get('scapy')
        if scapy_result and scapy_result['dot11_packets'] / scapy_result['total_packets'] < 0.5:
            low_dot11_files.append(filename)
            
    if low_dot11_files:
        print(f"  ⚠️  Low 802.11 detection rate in: {', '.join(low_dot11_files)}")
        print(f"      These files may not be wireless captures or may need different parsing")
        
    # Check for missing RadioTap
    no_radiotap_files = []
    for filename, file_results in results.items():
        scapy_result = file_results.get('scapy')
        if scapy_result and scapy_result['radiotap_packets'] == 0:
            no_radiotap_files.append(filename)
            
    if no_radiotap_files:
        print(f"  📡 No RadioTap headers in: {', '.join(no_radiotap_files)}")
        print(f"      RSSI, channel, and PHY info will be unavailable")
        
    print(f"\n✅ Diagnostic complete. Check 'pcap_parsing_debug.log' for detailed logs.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        pcap_dir = sys.argv[1]
    else:
        pcap_dir = "pcaps"
        
    analyze_pcap_files(pcap_dir)