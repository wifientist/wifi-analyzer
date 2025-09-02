# Wireless PCAP Analysis Framework

A comprehensive, modular framework for analyzing 802.11 wireless packet captures with expert-level insights and recommendations.

## 🎯 Project Overview

This framework implements a complete wireless security and performance analysis system based on an exhaustive 802.11 analysis checklist. It provides:

- **23 Analysis Categories** covering every aspect of wireless networking
- **Modular Architecture** for easy extension and customization
- **Expert AI Agent** that interprets findings and provides actionable recommendations
- **Professional CLI** for command-line analysis
- **Comprehensive Reporting** in multiple formats (JSON, HTML, text)
- **Real-world Detection** of attacks, performance issues, and misconfigurations

## 🏗️ Architecture

```
wireless_pcap_analyzer/
├── src/wireless_analyzer/
│   ├── core/                    # Core framework components
│   ├── analyzers/              # Modular analyzer implementations  
│   ├── expert/                 # AI expert agent system
│   ├── utils/                  # Utilities and helpers
│   ├── cli/                    # Command-line interface
│   └── main.py                 # Main orchestrator
├── tests/                      # Comprehensive test suite
├── docs/                       # Documentation
├── examples/                   # Usage examples
└── config/                     # Configuration files
```

## 📋 Analysis Categories

The framework implements analyzers across these comprehensive categories:

### Core Network Analysis
- **Capture Quality** - Validates monitor mode, timing, FCS inclusion
- **RF/PHY Analysis** - Signal strength, MCS rates, channel utilization
- **Beacon Analysis** - Interval consistency, IE validation, capability analysis
- **Probe Behavior** - Active/passive scanning, MAC randomization detection
- **Auth/Association** - Connection timing, capability negotiation, failure analysis

### Security Analysis  
- **Enterprise Security** - 802.1X/EAP/TLS analysis, certificate validation
- **EAPOL Analysis** - 4-way handshake validation, KRACK detection, timing analysis
- **Security Threats** - Deauth attacks, evil twins, rogue AP detection
- **6 GHz Security** - WPA3/OWE enforcement, PMF validation

### Performance & QoS
- **Data/Control Plane** - AMPDU/AMSDU analysis, block ACK efficiency, retry analysis
- **QoS/WMM** - EDCA parameter validation, voice/video QoS analysis
- **Power Save** - TIM/DTIM analysis, TWT behavior (802.11ax)
- **Application Performance** - TCP analysis, VoIP quality, latency measurement

### Advanced Features
- **Roaming & Steering** - 802.11k/v/r analysis, BSS transition, FT validation
- **MLO (802.11be)** - Multi-link operation analysis, EMLSR behavior
- **Coexistence/DFS** - Channel protection, RADAR detection, CSA analysis
- **Hotspot/Passpoint** - 802.11u/ANQP analysis, venue validation

### Network Intelligence
- **Client Profiling** - Device capability detection, behavior analysis
- **AP Behavior** - Load balancing, band steering, policy enforcement
- **Multicast/Broadcast** - DTIM efficiency, mDNS analysis, group-to-unicast conversion
- **IP Onboarding** - DHCP analysis, DNS resolution, connectivity validation

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd wireless_pcap_analyzer

# Install in development mode
pip install -e .

# Or install from requirements
pip install -r requirements.txt
```

### Basic Usage

```bash
# Analyze a PCAP file
wireless-analyzer analyze capture.pcap

# Quick validation of capture
wireless-analyzer validate capture.pcap --quick

# List available analyzers
wireless-analyzer list-analyzers

# Run specific analyzers only
wireless-analyzer analyze capture.pcap --analyzers deauth_detector beacon_analyzer

# Generate HTML report
wireless-analyzer analyze capture.pcap --format html --output report.html
```

### Python API Usage

```python
from wireless_analyzer.main import WirelessPCAPAnalyzer

# Initialize analyzer
analyzer = WirelessPCAPAnalyzer()

# Run analysis
results = analyzer.analyze_pcap("capture.pcap")

# Generate report
report = analyzer.generate_report(results, output_format='json')

# Access findings
critical_findings = results.get_findings_by_severity(Severity.CRITICAL)
security_findings = results.get_findings_by_category(AnalysisCategory.SECURITY_THREATS)

print(f"Found {len(critical_findings)} critical issues")
```

## 🔍 Example Analysis Output

```json
{
  "pcap_file": "enterprise_capture.pcap",
  "analysis_timestamp": "2025-01-15T10:30:00",
  "findings": [
    {
      "category": "security_threats",
      "severity": "critical", 
      "title": "Deauthentication Flood Attack Detected",
      "description": "High deauth rate detected: 45.3 frames/sec",
      "recommendations": [
        "Enable 802.11w (Management Frame Protection)",
        "Investigate source MAC addresses for rogue devices",
        "Consider emergency network isolation"
      ],
      "confidence": 0.95
    }
  ],
  "expert_summary": {
    "overall_assessment": "POOR - Multiple critical security issues detected",
    "risk_score": 85,
    "priority_recommendations": [...]
  }
}
```

## 📊 Key Features

### Expert AI Agent
The framework includes an AI expert agent that:
- Interprets raw findings into business impact
- Provides prioritized, actionable recommendations  
- Calculates risk scores and compliance assessments
- Identifies common wireless pathologies and root causes

### Comprehensive Detection
Real-world detection capabilities include:
- **Attack Detection**: Deauth floods, evil twins, KARMA attacks, WEP cracking attempts
- **Performance Issues**: Sticky clients, hidden nodes, channel contention, QoS violations
- **Configuration Problems**: Security misconfigurations, capability mismatches, band steering issues
- **Compliance Violations**: 802.11w enforcement, WPA3 requirements, enterprise policy violations

### Modular & Extensible
- Clean plugin architecture for adding new analyzers
- Category-based organization following wireless best practices
- Configurable thresholds and detection parameters
- Support for custom OUI databases and known device lists

## 🛠️ Development

### Adding a New Analyzer

1. Create analyzer in appropriate category directory:
```python
# src/wireless_analyzer/analyzers/security/my_detector.py
class MyThreatDetector(SecurityThreatAnalyzer):
    def __init__(self):
        super().__init__("My Threat Detector", "1.0")
        self.description = "Detects specific wireless threats"
        
    def analyze(self, packets, context):
        findings = []
        # Your detection logic here
        return findings
```

2. Register in main analyzer:
```python
# src/wireless_analyzer/main.py  
from .analyzers.security.my_detector import MyThreatDetector

def _register_default_analyzers(self):
    self.registry.register(MyThreatDetector())
```

3. Add tests:
```python
# tests/unit/analyzers/test_my_detector.py
def test_my_detector():
    # Test your analyzer
    pass
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src/wireless_analyzer

# Run specific category
pytest tests/unit/analyzers/security/
```

## 📈 Performance

The framework is designed for efficiency:
- **Streaming Analysis**: Processes packets incrementally 
- **Selective Processing**: Only applicable packets sent to each analyzer
- **Parallel Execution**: Analyzers can run concurrently (future enhancement)
- **Memory Efficient**: Minimal packet storage, metadata extraction only

Typical performance on modern hardware:
- **Small captures** (<10K packets): Sub-second analysis
- **Medium captures** (100K packets): 5-15 seconds  
- **Large captures** (1M+ packets): 1-5 minutes depending on complexity

## 🔒 Security Focus

This framework implements detection for:

### Common Attack Patterns
- Deauthentication/disassociation floods
- Evil twin and rogue access points
- KARMA and known-SSID attacks  
- WEP/WPS attacks and downgrade attempts
- Management frame injection attacks

### Enterprise Security Validation
- 802.1X/EAP implementation validation
- Certificate chain analysis and validation
- RADIUS authentication flow analysis
- PMF (802.11w) enforcement validation
- WPA3 transition mode security analysis

### Compliance Checking
- Industry standard compliance (802.11w, WPA3)
- Enterprise policy enforcement validation
- Regulatory compliance (DFS, power limits)
- Security framework alignment (NIST, ISO 27001)

## 📚 Documentation

- [Installation Guide](docs/installation.md)
- [User Guide](docs/usage.md) 
- [Analyzer Reference](docs/analyzer_reference.md)
- [Expert Agent Guide](docs/expert_agent.md)
- [API Documentation](docs/api/)
- [Contributing Guide](docs/extending.md)

## 🤝 Contributing

Contributions welcome! Areas of particular interest:

1. **New Analyzers** - Implement analyzers from the comprehensive checklist
2. **Expert Knowledge** - Enhance the AI agent's wireless expertise
3. **Performance Optimization** - Improve analysis speed and memory usage
4. **Additional Output Formats** - HTML, PDF, dashboard integration
5. **Enterprise Features** - SIEM integration, alerting, automation

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built on the comprehensive wireless analysis checklist
- Uses Scapy for packet parsing and analysis
- Inspired by professional wireless security assessment methodologies
- Community contributions and feedback

---

**Ready to analyze your wireless networks with professional-grade insights!** 🚀
