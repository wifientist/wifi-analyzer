#!/usr/bin/env python3
"""
Diagnostic script to analyze BSSID extraction issues in PCAP files.
This helps identify monitor mode, frame structure, and extraction problems.
"""

import sys
from pathlib import Path
from scapy.all import rdpcap, Packet
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp
from scapy.layers.dot11 import RadioTap
import argparse


def analyze_capture_mode(packets):
    """Analyze capture characteristics to determine mode."""
    print("=== CAPTURE MODE ANALYSIS ===")
    
    total_packets = len(packets)
    print(f"Total packets: {total_packets}")
    
    if total_packets == 0:
        print("❌ No packets found!")
        return
    
    # Check for RadioTap headers (monitor mode indicator)
    radiotap_count = sum(1 for p in packets if p.haslayer(RadioTap))
    print(f"RadioTap headers: {radiotap_count}/{total_packets} ({radiotap_count/total_packets*100:.1f}%)")
    
    if radiotap_count == 0:
        print("❌ NO RADIOTAP HEADERS - This is NOT monitor mode capture!")
        print("   Likely captured in managed mode or wrong interface type")
        return False
    
    # Check for 802.11 frames
    dot11_count = sum(1 for p in packets if p.haslayer(Dot11))
    print(f"802.11 frames: {dot11_count}/{total_packets} ({dot11_count/total_packets*100:.1f}%)")
    
    if dot11_count == 0:
        print("❌ NO 802.11 FRAMES - Not a wireless capture!")
        return False
    
    # Check frame types
    beacon_count = sum(1 for p in packets if p.haslayer(Dot11Beacon))
    probe_req_count = sum(1 for p in packets if p.haslayer(Dot11ProbeReq))
    probe_resp_count = sum(1 for p in packets if p.haslayer(Dot11ProbeResp))
    
    print(f"Beacon frames: {beacon_count}")
    print(f"Probe requests: {probe_req_count}")
    print(f"Probe responses: {probe_resp_count}")
    
    if beacon_count == 0:
        print("⚠️  NO BEACON FRAMES - May indicate filtering or very short capture")
    
    print("✅ Monitor mode indicators present" if radiotap_count > 0 and dot11_count > 0 else "❌ Monitor mode issues detected")
    return radiotap_count > 0 and dot11_count > 0


def analyze_bssid_extraction(packets, max_packets=1000):
    """Analyze BSSID extraction from sample packets."""
    print(f"\n=== BSSID EXTRACTION ANALYSIS (first {max_packets} beacon frames) ===")
    
    beacon_packets = [p for p in packets if p.haslayer(Dot11Beacon)]
    
    if not beacon_packets:
        print("❌ No beacon frames found for BSSID analysis")
        return
    
    print(f"Found {len(beacon_packets)} beacon frames total")
    
    for i, packet in enumerate(beacon_packets[:max_packets]):
        print(f"\n--- Beacon Frame {i+1} ---")
        
        # Check frame structure
        if packet.haslayer(RadioTap):
            print("✅ RadioTap header present")
        else:
            print("❌ No RadioTap header")
        
        if packet.haslayer(Dot11):
            dot11 = packet[Dot11]
            print(f"802.11 frame type/subtype: {dot11.type}/{dot11.subtype}")
            
            # Extract addresses
            print(f"addr1 (DA): {dot11.addr1}")
            print(f"addr2 (SA): {dot11.addr2}")  
            print(f"addr3 (BSSID): {dot11.addr3}")
            
            # BSSID should be in addr3 for beacon frames
            bssid = dot11.addr3
            if bssid and bssid != "00:00:00:00:00:00":
                print(f"✅ BSSID extracted: {bssid}")
            else:
                print(f"❌ BSSID is null/invalid: {bssid}")
                
                # Debug the raw frame
                print("Raw 802.11 header (first 24 bytes):")
                raw_data = bytes(dot11)[:24]
                print(" ".join(f"{b:02x}" for b in raw_data))
                
        else:
            print("❌ No 802.11 header found")
        
        # Check beacon-specific fields
        if packet.haslayer(Dot11Beacon):
            beacon = packet[Dot11Beacon]
            print(f"Beacon interval: {beacon.beacon_interval}")
            print(f"Capabilities: 0x{beacon.cap:04x}")
        
        print("-" * 40)


def analyze_frame_distribution(packets):
    """Analyze the distribution of frame types."""
    print("\n=== FRAME TYPE DISTRIBUTION ===")
    
    frame_types = {
        'management': 0,
        'control': 0, 
        'data': 0,
        'unknown': 0
    }
    
    subtype_counts = {}
    
    for packet in packets:
        if packet.haslayer(Dot11):
            dot11 = packet[Dot11]
            frame_type = dot11.type
            subtype = dot11.subtype
            
            if frame_type == 0:  # Management
                frame_types['management'] += 1
            elif frame_type == 1:  # Control
                frame_types['control'] += 1
            elif frame_type == 2:  # Data
                frame_types['data'] += 1
            else:
                frame_types['unknown'] += 1
                
            # Track subtypes
            type_subtype = f"{frame_type}.{subtype}"
            subtype_counts[type_subtype] = subtype_counts.get(type_subtype, 0) + 1
    
    total = sum(frame_types.values())
    
    for frame_type, count in frame_types.items():
        percentage = count/total*100 if total > 0 else 0
        print(f"{frame_type.capitalize()}: {count} ({percentage:.1f}%)")
    
    print(f"\nMost common frame subtypes:")
    sorted_subtypes = sorted(subtype_counts.items(), key=lambda x: x[1], reverse=True)
    
    # Map common subtypes to names
    subtype_names = {
        '0.8': 'Beacon',
        '0.4': 'Probe Request',
        '0.5': 'Probe Response', 
        '0.0': 'Association Request',
        '0.1': 'Association Response',
        '0.11': 'Authentication',
        '0.12': 'Deauthentication',
        '2.0': 'Data',
        '2.8': 'QoS Data'
    }
    
    for type_subtype, count in sorted_subtypes[:10]:
        name = subtype_names.get(type_subtype, f'Type {type_subtype}')
        percentage = count/total*100 if total > 0 else 0
        print(f"  {name}: {count} ({percentage:.1f}%)")


def check_scapy_version():
    """Check Scapy version and capabilities."""
    print("=== SCAPY ENVIRONMENT ===")
    try:
        import scapy
        print(f"Scapy version: {scapy.__version__}")
        
        # Test basic 802.11 parsing
        from scapy.layers.dot11 import Dot11, Dot11Beacon
        print("✅ 802.11 layer support available")
        
    except Exception as e:
        print(f"❌ Scapy issue: {e}")


def main():
    parser = argparse.ArgumentParser(description="Diagnose BSSID extraction issues in PCAP files")
    parser.add_argument("pcap_file", help="Path to PCAP file")
    parser.add_argument("--max-packets", type=int, default=10000, help="Max packets to analyze in detail")
    parser.add_argument("--sample-size", type=int, default=10000, help="Sample size for analysis")
    
    args = parser.parse_args()
    
    pcap_path = Path(args.pcap_file)
    if not pcap_path.exists():
        print(f"❌ PCAP file not found: {args.pcap_file}")
        sys.exit(1)
    
    print(f"Analyzing PCAP file: {pcap_path}")
    print(f"File size: {pcap_path.stat().st_size:,} bytes")
    
    try:
        # Load packets
        print(f"\nLoading packets (sample: {args.sample_size})...")
        packets = rdpcap(str(pcap_path), count=args.sample_size)
        
        # Run diagnostics
        check_scapy_version()
        monitor_mode_ok = analyze_capture_mode(packets)
        
        if monitor_mode_ok:
            analyze_bssid_extraction(packets, args.max_packets)
        
        analyze_frame_distribution(packets)
        
        # Recommendations
        print(f"\n=== RECOMMENDATIONS ===")
        if not monitor_mode_ok:
            print("❌ CRITICAL: Capture was not done in monitor mode!")
            print("   Solutions:")
            print("   1. Recapture using: sudo iwconfig <interface> mode monitor")
            print("   2. Use airmon-ng to enable monitor mode")
            print("   3. Use tcpdump/wireshark with proper monitor mode setup")
            print("   4. Ensure wireless adapter supports monitor mode")
        else:
            print("✅ Capture appears to be in monitor mode")
            print("   If BSSIDs are still null, check:")
            print("   1. Frame filtering during capture")
            print("   2. Encrypted/corrupted frames")
            print("   3. Scapy parsing issues with specific frame formats")
        
    except Exception as e:
        print(f"❌ Error analyzing PCAP: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()