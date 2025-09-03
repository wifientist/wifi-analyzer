#!/usr/bin/env python3
"""
Test script to verify the unified packet parsing integration works correctly.
"""

import sys
import logging
from pathlib import Path

# Add src to path
sys.path.insert(0, 'src')

def test_unified_analyzer():
    """Test the unified analyzer with enhanced packet loading."""
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    try:
        from wireless_analyzer.main import WirelessPCAPAnalyzer
        from wireless_analyzer.core.packet_loader import UnifiedPacketLoader
        
        print("✅ Successfully imported unified analyzer components")
        
        # Test packet loader directly
        print("\n🔧 Testing UnifiedPacketLoader...")
        loader = UnifiedPacketLoader(prefer_library="auto")
        print(f"Available parsers: {loader.available_parsers}")
        
        # Test main analyzer
        print("\n🔧 Testing WirelessPCAPAnalyzer integration...")
        analyzer = WirelessPCAPAnalyzer()
        
        # Find a test PCAP file
        pcap_files = list(Path("pcaps").glob("*.pcap*"))
        if not pcap_files:
            print("❌ No PCAP files found in pcaps/ directory")
            return False
            
        test_file = pcap_files[0]
        print(f"Testing with: {test_file.name}")
        
        # Run analysis with limited packets
        print("\n🚀 Running analysis...")
        results = analyzer.analyze_pcap(str(test_file), max_packets=20)
        
        print(f"\n📊 Analysis Results:")
        print(f"  Library used: {results.metadata.get('packet_loading', {}).get('library_used', 'unknown')}")
        print(f"  Total packets: {results.metrics.total_packets}")
        print(f"  Management frames: {results.metrics.management_frames}")
        print(f"  Beacon frames: {results.metrics.beacon_frames}")
        print(f"  Unique APs: {results.metrics.unique_aps}")
        print(f"  Unique stations: {results.metrics.unique_stations}")
        print(f"  Channels observed: {list(results.metrics.channels_observed)}")
        print(f"  Findings generated: {len(results.findings)}")
        print(f"  Analyzers run: {len(results.analyzers_run)}")
        
        # Show sample findings
        if results.findings:
            print(f"\n🔍 Sample Findings:")
            for i, finding in enumerate(results.findings[:3]):
                print(f"  {i+1}. {finding.title} ({finding.severity.value})")
                
        print(f"\n✅ Test completed successfully!")
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Make sure all dependencies are installed:")
        print("  pip install scapy pyshark dpkt")
        return False
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_unified_analyzer()
    sys.exit(0 if success else 1)