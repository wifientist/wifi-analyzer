# Intelligent Packet Parser Selection Guide

## Overview

Your wireless analyzer now uses intelligent packet parser selection to ensure optimal 802.11 data extraction based on:

1. **PCAP file characteristics** (format, link type, size, content)
2. **Analysis requirements** (which analyzers are enabled)
3. **Performance vs. quality trade-offs**

## How Parser Selection Works

### Automatic Selection Process

1. **File Analysis**: The system examines your PCAP file:
   - File format (PCAP vs PCAPNG)
   - Link layer type (Ethernet vs 802.11 vs 802.11+RadioTap)
   - File size (affects performance considerations)
   - Quick packet sampling (detects RadioTap headers, wireless frames)

2. **Analyzer Requirements**: Based on enabled analyzers:
   - Enterprise security analyzers → Need comprehensive protocol parsing
   - RF/Signal analyzers → Need detailed RadioTap field extraction
   - Flood detection analyzers → May prioritize performance
   - Frame-specific analyzers → Need optimal parsing for specific frame types

3. **Scoring System**: Each parser gets scored based on suitability:
   - **PyShark**: Best for complex protocol dissection, RadioTap parsing
   - **Scapy**: Good balance of features and performance  
   - **dpkt**: Fastest for bulk processing

4. **Selection**: Highest-scoring parser is used first, with fallbacks

## Parser Characteristics

### PyShark (Wireshark-based)
**Best for:**
- Enterprise security analysis (EAP, WPA2/3 handshakes)
- Detailed RadioTap parsing (RSSI, channel, data rates)
- Information Element (IE) dissection in beacons
- Complex 802.11 protocol analysis
- Small to medium PCAP files where quality matters

**Use when:**
- You need maximum 802.11 protocol detail
- Analyzing security implementations
- Working with enterprise wireless captures
- PCAPNG files with complex structure

### Scapy (Python-native)
**Best for:**
- General wireless frame analysis
- Deauthentication/disassociation detection
- Balanced speed and feature set
- Integration with existing Scapy-based tools
- Medium-sized captures

**Use when:**
- You need good 802.11 support with reasonable speed
- Working with standard wireless attacks
- Need packet crafting/injection capabilities
- Moderate performance requirements

### dpkt (High-performance)
**Best for:**
- Large PCAP file processing
- Bulk frame counting and statistics
- Performance-critical analysis
- Simple frame type classification
- Minimal resource usage

**Use when:**
- Processing very large captures (>100MB)
- Need maximum speed over detailed parsing
- Doing bulk statistical analysis
- Resource-constrained environments

## Configuration Options

### 1. Automatic (Recommended)
```python
analyzer = WirelessPCAPAnalyzer()  # Uses intelligent selection
```

### 2. Manual Override
```python
config = {'preferred_packet_parser': 'pyshark'}  # Force PyShark
analyzer = WirelessPCAPAnalyzer(config=config)
```

### 3. Analysis-Specific Configuration
The system automatically configures based on enabled analyzers:

```python
# This configuration will prefer PyShark for comprehensive parsing
analyzer.enable_analyzer('Enterprise Security Analyzer')
analyzer.enable_analyzer('RF/PHY Signal Analyzer')

# This configuration will prefer dpkt for speed
analyzer.enable_analyzer('Bulk Statistics Analyzer')
analyzer.enable_analyzer('High Volume Processor')
```

## Decision Matrix Examples

### Example 1: Security Analysis
**File**: `enterprise_capture.pcap` (15MB, 802.11 RadioTap)
**Analyzers**: Enterprise Security, WPA Security Posture, Beacon Analyzer

**Selection Logic**:
- RadioTap present → PyShark +30 pts
- Link type 127 → PyShark +25 pts  
- Small file → PyShark +15 pts
- Enterprise security → PyShark +25 pts
- Beacon analysis → PyShark +10 pts

**Result**: PyShark selected (105 pts vs Scapy 65 pts vs dpkt 35 pts)

### Example 2: Attack Detection  
**File**: `deauth_attack.pcap` (5MB, 802.11 basic)
**Analyzers**: Deauth Flood Detector, Attack Pattern Analyzer

**Selection Logic**:
- Link type 105 → Scapy +20 pts
- Small file → PyShark +15 pts
- Deauth analysis → Scapy +12 pts

**Result**: Scapy selected (32 pts vs PyShark 25 pts vs dpkt 10 pts)

### Example 3: Large Volume Processing
**File**: `bulk_capture.pcap` (500MB, 802.11 RadioTap)
**Analyzers**: Volume Statistics, Bulk Frame Counter

**Selection Logic**:
- RadioTap present → PyShark +30 pts
- Large file → dpkt +20 pts, PyShark -10 pts
- High performance → dpkt +25 pts

**Result**: dpkt selected (45 pts vs PyShark 20 pts vs Scapy 25 pts)

## Monitoring Parser Selection

The system logs its selection decisions:

```
INFO - Parser selection scores: {'pyshark': 85, 'scapy': 45, 'dpkt': 20}
INFO - Selected parser order: ['pyshark', 'scapy', 'dpkt']
INFO - Loading packets from capture.pcap using pyshark
```

## Override Guidelines

**Force PyShark when**:
- Maximum 802.11 protocol detail required
- Enterprise security analysis is critical
- Working with complex wireless implementations
- Quality is more important than speed

**Force Scapy when**:
- Your existing analysis depends on Scapy-specific features
- Need packet crafting/modification capabilities
- Balanced performance requirements
- Integration with Scapy-based tools

**Force dpkt when**:
- Processing very large files (>100MB)
- Performance is critical
- Simple frame classification is sufficient
- Working in resource-constrained environments

## Troubleshooting

### Parser Selection Issues
1. **Wrong parser selected**: Check file characteristics and enabled analyzers
2. **Performance issues**: Consider manual override to dpkt for large files
3. **Missing data**: Try PyShark for maximum field extraction
4. **Parsing failures**: System automatically falls back to next parser

### Getting Better Results
1. **Enable specific analyzers** to guide selection
2. **Check PCAP file format** - ensure it's truly wireless
3. **Verify RadioTap presence** for best field extraction
4. **Consider file size** vs analysis depth trade-offs

The intelligent selection system ensures you get the best 802.11 data extraction for your specific analysis needs while maintaining reliability through automatic fallbacks.