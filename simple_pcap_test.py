#!/usr/bin/env python3
"""
Simple PCAP diagnostic tool to identify parsing issues.
This works without requiring the full wireless analyzer environment.
"""

import sys
import os
from pathlib import Path
import time

def test_file_access():
    """Test basic file access and library availability."""
    print("🔍 Testing environment and file access...")
    
    # Test PCAP directory
    pcap_dir = Path("pcaps")
    if not pcap_dir.exists():
        print("❌ pcaps/ directory not found")
        return False
        
    pcap_files = list(pcap_dir.glob("*.pcap*"))
    print(f"✅ Found {len(pcap_files)} PCAP files:")
    
    for f in pcap_files:
        size_mb = f.stat().st_size / (1024 * 1024)
        print(f"   • {f.name} ({size_mb:.1f} MB)")
        
    return len(pcap_files) > 0

def test_library_imports():
    """Test which packet parsing libraries are available."""
    print("\n📚 Testing library availability...")
    
    libraries = {}
    
    # Test Scapy
    try:
        from scapy.all import rdpcap, Packet
        from scapy.layers.dot11 import Dot11, RadioTap
        libraries['scapy'] = True
        print("✅ Scapy: Available")
    except ImportError as e:
        libraries['scapy'] = False
        print(f"❌ Scapy: Not available ({e})")
        
    # Test PyShark
    try:
        import pyshark
        libraries['pyshark'] = True
        print("✅ PyShark: Available")
    except ImportError as e:
        libraries['pyshark'] = False
        print(f"❌ PyShark: Not available ({e})")
        
    # Test dpkt
    try:
        import dpkt
        libraries['dpkt'] = True
        print("✅ dpkt: Available")
    except ImportError as e:
        libraries['dpkt'] = False
        print(f"❌ dpkt: Not available ({e})")
        
    if not any(libraries.values()):
        print("\n⚠️  No packet parsing libraries available!")
        print("Install with:")
        print("  pip install scapy")
        print("  pip install pyshark") 
        print("  pip install dpkt")
        return False
        
    return libraries

def basic_file_inspection():
    """Basic file inspection without parsing libraries."""
    print("\n🔍 Basic PCAP file inspection...")
    
    pcap_files = list(Path("pcaps").glob("*.pcap*"))
    
    for pcap_file in pcap_files[:3]:  # Test first 3 files
        print(f"\n--- {pcap_file.name} ---")
        
        # Read first few bytes to identify format
        with open(pcap_file, 'rb') as f:
            header = f.read(24)  # PCAP global header is 24 bytes
            
        if len(header) < 24:
            print(f"❌ File too small ({len(header)} bytes)")
            continue
            
        # Check magic numbers
        magic = header[:4]
        
        if magic == b'\xd4\xc3\xb2\xa1':  # Original pcap format (little endian)
            print("✅ Format: PCAP (little endian)")
            link_type = int.from_bytes(header[20:24], 'little')
        elif magic == b'\xa1\xb2\xc3\xd4':  # Original pcap format (big endian)
            print("✅ Format: PCAP (big endian)")
            link_type = int.from_bytes(header[20:24], 'big')
        elif magic == b'\x0a\x0d\x0d\x0a':  # PCAPNG format
            print("✅ Format: PCAPNG")
            link_type = None  # PCAPNG link type is more complex
        else:
            print(f"❓ Unknown format, magic: {magic.hex()}")
            continue
            
        # Interpret link type
        if link_type is not None:
            if link_type == 1:
                print("📡 Link Type: Ethernet (1) - Not wireless")
            elif link_type == 105:
                print("📡 Link Type: IEEE 802.11 (105) - Wireless without RadioTap")
            elif link_type == 127:
                print("📡 Link Type: IEEE 802.11 RadioTap (127) - Wireless with RadioTap")
            elif link_type == 163:
                print("📡 Link Type: IEEE 802.11 AVS (163) - Wireless with AVS headers")
            else:
                print(f"📡 Link Type: {link_type} (unknown)")
                
def test_scapy_parsing():
    """Test Scapy parsing if available."""
    try:
        from scapy.all import rdpcap
        from scapy.layers.dot11 import Dot11, RadioTap
    except ImportError:
        print("\n❌ Scapy not available for testing")
        return
        
    print("\n🧪 Testing Scapy parsing...")
    
    pcap_files = list(Path("pcaps").glob("*.pcap*"))
    
    for pcap_file in pcap_files[:5]:  # Test first 5 files
        print(f"\n--- Testing {pcap_file.name} with Scapy ---")
        
        try:
            start_time = time.time()
            packets = rdpcap(str(pcap_file))
            load_time = time.time() - start_time
            
            print(f"✅ Loaded {len(packets)} packets in {load_time:.2f}s")
            
            # Analyze first 10 packets
            dot11_count = 0
            radiotap_count = 0
            timestamp_count = 0
            
            layer_types = set()
            
            for i, packet in enumerate(packets[:10]):
                # Collect layer types
                layer = packet
                packet_layers = []
                while layer:
                    layer_name = layer.__class__.__name__
                    packet_layers.append(layer_name)
                    layer_types.add(layer_name)
                    layer = layer.payload if hasattr(layer, 'payload') else None
                    
                print(f"  Packet {i}: {' -> '.join(packet_layers)}")
                
                # Check for wireless indicators
                if packet.haslayer(Dot11):
                    dot11_count += 1
                    
                if packet.haslayer(RadioTap):
                    radiotap_count += 1
                    
                if hasattr(packet, 'time'):
                    timestamp_count += 1
                    
            print(f"\nFirst 10 packets analysis:")
            print(f"  802.11 packets: {dot11_count}/10")
            print(f"  RadioTap packets: {radiotap_count}/10") 
            print(f"  Timestamped packets: {timestamp_count}/10")
            print(f"  Unique layer types: {', '.join(sorted(layer_types))}")
            
            # Test problematic scenarios
            if dot11_count == 0:
                print("⚠️  No 802.11 packets detected - this may explain analyzer issues")
            if radiotap_count == 0:
                print("⚠️  No RadioTap headers - RSSI/channel info unavailable")
            if timestamp_count < 10:
                print("⚠️  Missing timestamps - timing analysis will be limited")
                
        except Exception as e:
            print(f"❌ Scapy parsing failed: {e}")
            
def test_pyshark_parsing():
    """Test PyShark parsing if available."""
    try:
        import pyshark
    except ImportError:
        print("\n❌ PyShark not available for testing")
        return
        
    print("\n🧪 Testing PyShark parsing...")
    
    pcap_files = list(Path("pcaps").glob("*.pcap*"))
    
    for pcap_file in pcap_files[:1]:  # Test first file only (PyShark can be slow)
        print(f"\n--- Testing {pcap_file.name} with PyShark ---")
        
        try:
            # Try opening with WLAN filter
            cap = pyshark.FileCapture(str(pcap_file), display_filter='wlan')
            
            packet_count = 0
            wlan_packets = 0
            
            for packet in cap:
                packet_count += 1
                if packet_count > 10:  # Limit to first 10 packets
                    break
                    
                print(f"  Packet {packet_count}:")
                
                # Check for WLAN layer
                if hasattr(packet, 'wlan'):
                    wlan_packets += 1
                    wlan = packet.wlan
                    
                    # Extract some basic info
                    info = {}
                    if hasattr(wlan, 'sa'):
                        info['src'] = wlan.sa
                    if hasattr(wlan, 'da'):
                        info['dst'] = wlan.da
                    if hasattr(wlan, 'ssid'):
                        info['ssid'] = wlan.ssid
                    if hasattr(wlan, 'channel'):
                        info['channel'] = wlan.channel
                        
                    print(f"    WLAN: {info}")
                    
                # Check for RadioTap
                if hasattr(packet, 'radiotap'):
                    rt_info = {}
                    radiotap = packet.radiotap
                    if hasattr(radiotap, 'dbm_antsignal'):
                        rt_info['rssi'] = radiotap.dbm_antsignal
                    if hasattr(radiotap, 'channel_freq'):
                        rt_info['freq'] = radiotap.channel_freq
                        
                    print(f"    RadioTap: {rt_info}")
                    
            cap.close()
            
            print(f"\nPyShark results:")
            print(f"  WLAN packets: {wlan_packets}/{packet_count}")
            
        except Exception as e:
            print(f"❌ PyShark parsing failed: {e}")

def main():
    """Run all diagnostic tests."""
    print("🚀 PCAP Parsing Diagnostic Tool")
    print("=" * 50)
    
    # Test 1: File access
    if not test_file_access():
        print("\n❌ Cannot proceed - no PCAP files found")
        return
        
    # Test 2: Library availability  
    libraries = test_library_imports()
    if not libraries:
        return
        
    # Test 3: Basic file inspection
    basic_file_inspection()
    
    # Test 4: Library-specific parsing
    if libraries.get('scapy'):
        test_scapy_parsing()
        
    if libraries.get('pyshark'):
        test_pyshark_parsing()
        
    print("\n" + "=" * 50)
    print("DIAGNOSTIC COMPLETE")
    print("=" * 50)
    
    print("\nNext steps:")
    print("1. If no 802.11 packets detected, check capture method")
    print("2. If no RadioTap headers, PHY analysis will be limited")
    print("3. Install missing libraries for better parsing options")
    print("4. Check wireless_analyzer logs with enhanced logging")

if __name__ == "__main__":
    main()