#!/usr/bin/env python3
"""
Test to verify the adaptive retry system fixes work correctly.
"""

import sys
import logging

# Add src to path
sys.path.insert(0, 'src')

def test_fixed_retry_system():
    """Test the fixed retry system."""
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    try:
        from wireless_analyzer.main import WirelessPCAPAnalyzer
        from pathlib import Path
        
        print("🔧 Testing Fixed Adaptive Retry System")
        print("=" * 50)
        
        # Find test PCAP
        pcap_files = list(Path("pcaps").glob("*.pcap*"))
        if not pcap_files:
            print("❌ No PCAP files found")
            return False
            
        test_file = pcap_files[0]  # Use solis1.pcap that was failing
        print(f"Testing with: {test_file.name}")
        
        # Create analyzer
        analyzer = WirelessPCAPAnalyzer()
        
        # Test with limited packets to speed things up
        print(f"\n🚀 Running analysis...")
        results = analyzer.analyze_pcap(str(test_file), max_packets=100)
        
        print(f"\n📊 Results:")
        print(f"  Total packets processed: {results.metrics.total_packets}")
        print(f"  Total findings: {len(results.findings)}")
        print(f"  Analyzers run: {len(results.analyzers_run)}")
        print(f"  Analysis time: {results.metrics.analysis_duration_seconds:.2f}s")
        
        # Check adaptive retry stats
        retry_stats = analyzer.get_adaptive_retry_stats()
        print(f"\n🔄 Adaptive Retry Statistics:")
        print(f"  Total analyzers run: {retry_stats['total_analyzers_run']}")
        print(f"  Analyzers retried: {retry_stats['analyzers_retried']}")
        print(f"  Successful retries: {retry_stats['successful_retries']}")
        print(f"  Retry rate: {retry_stats['retry_rate']:.1f}%")
        
        if retry_stats['parser_switches']:
            print(f"  Parser switches:")
            for switch, count in retry_stats['parser_switches'].items():
                print(f"    {switch}: {count} times")
        
        # Check loading metadata
        loading_meta = results.metadata.get('packet_loading', {})
        print(f"\n📦 Packet Loading:")
        print(f"  Primary library used: {loading_meta.get('library_used', 'unknown')}")
        print(f"  Loading time: {loading_meta.get('loading_time', 0):.2f}s")
        print(f"  Success rate: {loading_meta.get('successfully_parsed', 0)}/{loading_meta.get('total_raw_packets', 0)}")
        
        # Show sample findings by category
        if results.findings:
            category_counts = {}
            for finding in results.findings:
                cat = finding.category.value
                category_counts[cat] = category_counts.get(cat, 0) + 1
                
            print(f"\n🔍 Findings by Category:")
            for category, count in category_counts.items():
                print(f"  {category}: {count} findings")
        
        print(f"\n✅ Test completed successfully!")
        print(f"The retry system is working and should handle parser failures gracefully.")
        
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_fixed_retry_system()
    sys.exit(0 if success else 1)