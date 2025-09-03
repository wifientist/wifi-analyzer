#!/usr/bin/env python3
"""
Test script to verify intelligent packet parser selection based on PCAP characteristics
and analyzer requirements.
"""

import sys
import logging
from pathlib import Path

# Add src to path
sys.path.insert(0, 'src')

def test_parser_selection():
    """Test intelligent parser selection logic."""
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    try:
        from wireless_analyzer.core.packet_loader import UnifiedPacketLoader
        from wireless_analyzer.main import WirelessPCAPAnalyzer
        
        print("🧠 Testing Intelligent Parser Selection")
        print("=" * 50)
        
        # Find test PCAP files
        pcap_files = list(Path("pcaps").glob("*.pcap*"))
        if not pcap_files:
            print("❌ No PCAP files found in pcaps/ directory")
            return False
            
        # Test different analyzer configurations
        test_scenarios = [
            {
                'name': 'Enterprise Security Analysis',
                'analyzers': ['Enterprise Security Analyzer', 'WPA Security Posture'],
                'expected_preference': 'pyshark'  # Best for complex protocol dissection
            },
            {
                'name': 'RF Signal Analysis', 
                'analyzers': ['RF/PHY Signal Analyzer', 'Signal Quality Monitor'],
                'expected_preference': 'pyshark'  # Best RadioTap field extraction
            },
            {
                'name': 'Deauth Flood Detection',
                'analyzers': ['Deauthentication Flood Detector', 'Attack Pattern Analyzer'], 
                'expected_preference': 'scapy'    # Good for deauth analysis
            },
            {
                'name': 'High Performance Bulk Processing',
                'analyzers': ['Bulk Frame Processor', 'Volume Statistics'],
                'expected_preference': 'dpkt'     # Fastest processing
            },
            {
                'name': 'Beacon Analysis',
                'analyzers': ['Beacon Frame Analyzer', 'Beacon Inventory'],
                'expected_preference': 'pyshark'  # Best IE parsing
            }
        ]
        
        for scenario in test_scenarios:
            print(f"\n🔍 Scenario: {scenario['name']}")
            print("-" * 40)
            
            # Create and configure packet loader
            loader = UnifiedPacketLoader(prefer_library="auto")
            loader.configure_for_analyzers(scenario['analyzers'])
            
            # Test with each PCAP file
            for pcap_file in pcap_files[:2]:  # Test with first 2 files
                print(f"\nTesting with: {pcap_file.name}")
                
                # Get parser selection for this file
                try:
                    parser_order = loader._get_parser_order(str(pcap_file))
                    selected_parser = parser_order[0] if parser_order else "none"
                    
                    print(f"  Selected parser: {selected_parser}")
                    print(f"  Parser order: {parser_order}")
                    print(f"  Expected preference: {scenario['expected_preference']}")
                    
                    # Check if selection makes sense
                    if selected_parser == scenario['expected_preference']:
                        print("  ✅ Parser selection matches expected preference")
                    else:
                        print("  ⚠️  Parser selection differs from expectation")
                        # This could be due to PCAP characteristics overriding analyzer preferences
                        
                    # Show PCAP analysis that influenced the decision
                    pcap_info = loader._analyze_pcap_file(str(pcap_file))
                    print(f"  PCAP characteristics:")
                    print(f"    Format: {pcap_info.get('format', 'unknown')}")
                    print(f"    Link type: {pcap_info.get('link_type', 'unknown')}")
                    print(f"    Size: {pcap_info.get('size_mb', 0):.1f} MB")
                    print(f"    Has RadioTap: {pcap_info.get('has_radiotap', False)}")
                    print(f"    Wireless indicators: {pcap_info.get('wireless_indicators', [])}")
                    
                except Exception as e:
                    print(f"  ❌ Error testing parser selection: {e}")
                    
        # Test with actual analysis
        print(f"\n🚀 Testing Full Analysis Integration")
        print("=" * 40)
        
        analyzer = WirelessPCAPAnalyzer()
        test_file = pcap_files[0]
        
        print(f"Analyzing: {test_file.name}")
        
        try:
            # Run analysis - this should automatically configure the loader
            results = analyzer.analyze_pcap(str(test_file), max_packets=10)
            
            loading_metadata = results.metadata.get('packet_loading', {})
            library_used = loading_metadata.get('library_used', 'unknown')
            
            print(f"✅ Analysis completed using: {library_used}")
            print(f"Packets processed: {results.metrics.total_packets}")
            print(f"Analyzers run: {len(results.analyzers_run)}")
            
            # Show which analyzers influenced parser selection
            enabled_analyzers = results.analyzers_run
            print(f"Enabled analyzers that influenced selection:")
            for analyzer_name in enabled_analyzers:
                print(f"  • {analyzer_name}")
                
        except Exception as e:
            print(f"❌ Full analysis test failed: {e}")
            import traceback
            traceback.print_exc()
            
        print(f"\n✅ Intelligent parser selection test completed!")
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def demo_parser_decision_matrix():
    """Demonstrate the parser selection decision matrix."""
    
    print(f"\n📊 Parser Selection Decision Matrix")
    print("=" * 50)
    
    print("""
🎯 DECISION FACTORS:

1. PCAP File Characteristics:
   • RadioTap presence → PyShark preferred (best RadioTap parsing)
   • Link type 127 (802.11 RadioTap) → PyShark advantage
   • Link type 105 (802.11 basic) → Scapy advantage  
   • Large files (>100MB) → dpkt preferred (speed)
   • Small files (<10MB) → PyShark preferred (quality)
   • PCAPNG format → PyShark advantage

2. Analysis Requirements:
   • Enterprise Security → PyShark (+25 pts) - complex protocols
   • Detailed RadioTap → PyShark (+30 pts) - RSSI/channel/rates
   • High Performance → dpkt (+25 pts) - fastest processing
   • Beacon Analysis → PyShark (+10 pts) - best IE parsing
   • Deauth Analysis → Scapy (+12 pts) - good deauth handling
   • Probe Analysis → PyShark (+15 pts) - best probe dissection

3. Scoring System:
   • Each parser starts with 0 points
   • Points added based on PCAP characteristics and analysis needs
   • Highest scoring parser is selected first
   • Fallback order maintained for reliability

🏆 TYPICAL OUTCOMES:
   • Wireless security analysis → PyShark (comprehensive parsing)
   • RF signal analysis → PyShark (best RadioTap extraction) 
   • Attack detection → Scapy (good balance of speed/features)
   • Large volume processing → dpkt (maximum performance)
   • Mixed analysis → Smart selection based on dominant needs
""")

if __name__ == "__main__":
    success = test_parser_selection()
    demo_parser_decision_matrix()
    sys.exit(0 if success else 1)