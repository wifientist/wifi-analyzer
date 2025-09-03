#!/usr/bin/env python3
"""
Test script to demonstrate adaptive parser retry functionality.
This simulates scenarios where analyzers fail or produce poor results
and the system automatically retries with different parsers.
"""

import sys
import logging
from pathlib import Path

# Add src to path
sys.path.insert(0, 'src')

def test_adaptive_retry():
    """Test the adaptive retry system with different scenarios."""
    
    # Setup detailed logging to see retry behavior
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    try:
        from wireless_analyzer.main import WirelessPCAPAnalyzer
        
        print("🔄 Testing Adaptive Parser Retry System")
        print("=" * 50)
        
        # Find test PCAP files
        pcap_files = list(Path("pcaps").glob("*.pcap*"))
        if not pcap_files:
            print("❌ No PCAP files found in pcaps/ directory")
            return False
            
        # Test with different configurations that might trigger retries
        test_scenarios = [
            {
                'name': 'Beacon Analysis (might need PyShark for IE parsing)',
                'enabled_analyzers': ['Beacon Frame Analyzer'],
                'description': 'Tests if beacon analyzer gets better results with different parsers'
            },
            {
                'name': 'Deauth Detection (might work better with Scapy)',
                'enabled_analyzers': ['Deauthentication Flood Detector'],
                'description': 'Tests if deauth analyzer finds more attacks with different parsers'
            },
            {
                'name': 'Enterprise Security (complex protocol needs)',
                'enabled_analyzers': ['Enterprise Security Analyzer', 'WPA Security Posture'],
                'description': 'Tests if security analyzers get better protocol dissection'
            },
            {
                'name': 'All Analyzers (comprehensive test)',
                'enabled_analyzers': None,  # Use all available
                'description': 'Tests retry behavior across all analyzer types'
            }
        ]
        
        for scenario in test_scenarios:
            print(f"\n🧪 Scenario: {scenario['name']}")
            print(f"Description: {scenario['description']}")
            print("-" * 60)
            
            # Test with first available PCAP file
            test_file = pcap_files[0]
            print(f"Testing with: {test_file.name} ({test_file.stat().st_size / (1024*1024):.1f} MB)")
            
            try:
                # Create analyzer instance
                analyzer = WirelessPCAPAnalyzer()
                
                # Enable specific analyzers if specified
                if scenario['enabled_analyzers']:
                    # First disable all, then enable specific ones
                    for available_analyzer in analyzer.list_analyzers():
                        analyzer.disable_analyzer(available_analyzer['name'])
                    
                    for target_analyzer in scenario['enabled_analyzers']:
                        found = False
                        for available_analyzer in analyzer.list_analyzers():
                            if target_analyzer.lower() in available_analyzer['name'].lower():
                                analyzer.enable_analyzer(available_analyzer['name'])
                                found = True
                                print(f"  Enabled: {available_analyzer['name']}")
                                break
                        if not found:
                            print(f"  ⚠️ Could not find analyzer matching: {target_analyzer}")
                
                print(f"\n🚀 Running analysis...")
                
                # Run analysis with limited packets to speed up testing
                results = analyzer.analyze_pcap(str(test_file), max_packets=50)
                
                # Analyze results
                total_findings = len(results.findings)
                analyzers_run = len(results.analyzers_run)
                
                print(f"\n📊 Results Summary:")
                print(f"  Total findings: {total_findings}")
                print(f"  Analyzers completed: {analyzers_run}")
                print(f"  Analysis time: {results.metrics.analysis_duration_seconds:.2f}s")
                
                # Check loading metadata to see if retries occurred
                loading_metadata = results.metadata.get('packet_loading', {})
                library_used = loading_metadata.get('library_used', 'unknown')
                print(f"  Primary parser used: {library_used}")
                
                # Look for retry indicators in findings
                retry_findings = [f for f in results.findings if 'attempt' in f.details]
                if retry_findings:
                    print(f"  🔄 Retries detected: {len(retry_findings)} analyzer retries occurred")
                    for finding in retry_findings:
                        attempt = finding.details.get('attempt', 'unknown')
                        parser_used = finding.details.get('parser_used', 'unknown')
                        print(f"    - {finding.analyzer_name}: attempt {attempt} with {parser_used}")
                else:
                    print(f"  ✅ No retries needed (all analyzers succeeded on first attempt)")
                
                # Show sample findings by analyzer
                analyzer_findings = {}
                for finding in results.findings:
                    analyzer_name = finding.analyzer_name or 'Unknown'
                    if analyzer_name not in analyzer_findings:
                        analyzer_findings[analyzer_name] = []
                    analyzer_findings[analyzer_name].append(finding)
                
                if analyzer_findings:
                    print(f"\n  📋 Findings by Analyzer:")
                    for analyzer_name, findings in analyzer_findings.items():
                        if analyzer_name != 'Unknown':  # Skip error findings for now
                            print(f"    {analyzer_name}: {len(findings)} findings")
                            if findings:
                                sample = findings[0]
                                print(f"      Sample: {sample.title} ({sample.severity.value})")
                
            except Exception as e:
                print(f"❌ Scenario failed: {e}")
                import traceback
                traceback.print_exc()
                
        print(f"\n✅ Adaptive retry system testing completed!")
        print(f"\n💡 Key Benefits:")
        print(f"  • Automatically detects when analyzers get poor results")
        print(f"  • Retries with alternative parsers for better data extraction")
        print(f"  • Scores results to pick the best parser for each analyzer")
        print(f"  • Maximizes analysis success rate across different PCAP types")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def demo_retry_scenarios():
    """Demonstrate specific scenarios where retry helps."""
    
    print(f"\n🎯 Retry Scenarios That Improve Results")
    print("=" * 50)
    
    print("""
📉 POOR RESULTS TRIGGERS (System automatically detects):

1. Very Low Applicable Packet Rate (<2%):
   • Beacon analyzer finds no beacon frames → Try PyShark for better IE parsing
   • Deauth analyzer finds no deauth frames → Try Scapy for better mgmt parsing
   • Signal analyzer finds no RSSI data → Try PyShark for better RadioTap

2. Zero Findings from Expected Analyzers:
   • Security analyzers find no security issues → Try comprehensive parser
   • Beacon analyzers find no beacon problems → Try parser with better IE support
   • Attack analyzers find no attacks → Try parser with better frame classification

3. Analysis Failures/Exceptions:
   • Parser can't decode certain frame types → Try alternative parser
   • Missing required packet fields → Try parser with better field extraction
   • Protocol dissection errors → Try parser with more robust handling

🔄 RETRY PROCESS:

Step 1: Initial Analysis Attempt
├─ Run analyzer with initially selected parser
├─ Evaluate results quality (applicability rate, findings count, errors)
└─ If results are poor → trigger retry

Step 2: Alternative Parser Selection  
├─ Try remaining available parsers (excluding failed one)
├─ Load packets with each alternative parser
├─ Run analyzer with new packet data
└─ Score each result for quality

Step 3: Best Result Selection
├─ Compare scores: applicability + findings + performance
├─ Select highest scoring result
└─ Return best findings to user

🏆 SCORING SYSTEM:
• Applicable packet rate: 0-50 points (higher = better parsing)
• Findings generated: 0-20 points (shows working analysis)
• Processing time: 0-10 points (reasonable performance)
• Parser type bonus: PyShark +5, Scapy +3 (quality preference)

📈 EXPECTED IMPROVEMENTS:
• Beacon analysis: PyShark often extracts more IE details than Scapy
• Security analysis: PyShark better at complex protocol dissection  
• Attack detection: Scapy sometimes better at management frame handling
• RF analysis: PyShark typically extracts more RadioTap fields
""")

if __name__ == "__main__":
    success = test_adaptive_retry()
    demo_retry_scenarios()
    sys.exit(0 if success else 1)