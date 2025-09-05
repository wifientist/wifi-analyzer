"""
PyShark-specific WPA Security Posture Analyzer

Analyzes WPA2/WPA3/OWE security posture including cipher suites, authentication methods,
and advanced security features using PyShark's native packet parsing capabilities.
"""

import struct
import hashlib
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Set, Optional

try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False

from ....core.base_analyzer import BasePySharkAnalyzer
from ....core.models import Finding, Severity, AnalysisCategory


class SecurityProtocol(Enum):
    """Security protocol enumeration."""
    OPEN = "open"
    WEP = "wep"
    WPA = "wpa"
    WPA2 = "wpa2"
    WPA3 = "wpa3"
    OWE = "owe"
    SAE = "sae"
    WPA2_WPA3_MIXED = "wpa2_wpa3_transition"


class SecurityRisk(Enum):
    """Security risk levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class NetworkSecurity:
    """Security posture for a wireless network."""
    bssid: str
    ssid: str
    security_protocol: SecurityProtocol = SecurityProtocol.OPEN
    cipher_suites: List[str] = field(default_factory=list)
    auth_suites: List[str] = field(default_factory=list)
    pmf_capable: bool = False
    pmf_required: bool = False
    wpa3_enabled: bool = False
    sae_enabled: bool = False
    owe_enabled: bool = False
    tkip_present: bool = False
    security_risks: List[str] = field(default_factory=list)
    risk_level: SecurityRisk = SecurityRisk.INFO


class PySharkWPASecurityPostureAnalyzer(BasePySharkAnalyzer):
    """
    PyShark-based WPA security posture analyzer.
    
    Analyzes wireless network security including:
    - WPA2/WPA3 protocol detection
    - Cipher suite analysis
    - Authentication method assessment
    - PMF (Protected Management Frames) support
    - Security risk assessment
    """
    
    def __init__(self):
        super().__init__()
        self.name = "PyShark WPA Security Posture Analyzer"
        self.description = "Analyzes WPA security posture using PyShark parsing"
        self.version = "1.0.0"
        
        if not PYSHARK_AVAILABLE:
            self.logger.warning("PyShark not available - analyzer will not function")
        
        # Network security tracking
        self.networks: Dict[str, NetworkSecurity] = {}  # Key: bssid
        
        # Security suite mappings (simplified)
        self.cipher_suites = {
            "1": "WEP-40",
            "2": "TKIP", 
            "4": "CCMP-128",
            "5": "WEP-104",
            "8": "GCMP-128",
            "9": "GCMP-256",
            "10": "CCMP-256"
        }
        
        self.auth_suites = {
            "1": "IEEE 802.1X",
            "2": "PSK",
            "3": "FT over IEEE 802.1X",
            "4": "FT using PSK",
            "5": "IEEE 802.1X/SHA-256",
            "6": "PSK/SHA-256",
            "8": "SAE",
            "9": "FT over SAE",
            "11": "Suite B 192-bit",
            "18": "OWE"
        }
        
        # Risk mappings
        self.cipher_risks = {
            "WEP-40": SecurityRisk.CRITICAL,
            "WEP-104": SecurityRisk.CRITICAL,
            "TKIP": SecurityRisk.HIGH,
            "CCMP-128": SecurityRisk.LOW,
            "CCMP-256": SecurityRisk.LOW,
            "GCMP-128": SecurityRisk.LOW,
            "GCMP-256": SecurityRisk.LOW
        }

    def analyze_packet(self, packet, metadata: Dict[str, Any] = None) -> List[Finding]:
        """Analyze a single packet for WPA security information."""
        if not PYSHARK_AVAILABLE:
            return []
        
        findings = []
        
        try:
            if self._is_beacon_or_assoc_resp(packet):
                security_info = self._extract_security_info(packet)
                if security_info:
                    findings.extend(self._analyze_security_posture(security_info))
            
            elif hasattr(packet, 'eap'):
                findings.extend(self._analyze_eap_methods(packet))
        
        except Exception as e:
            self.logger.error(f"Error analyzing WPA security: {e}")
        
        return findings
    
    def _is_beacon_or_assoc_resp(self, packet) -> bool:
        """Check if packet is a beacon or association response."""
        try:
            if not hasattr(packet, 'wlan'):
                return False
            
            if hasattr(packet.wlan, 'fc_type') and hasattr(packet.wlan, 'fc_subtype'):
                frame_type = int(packet.wlan.fc_type)
                subtype = int(packet.wlan.fc_subtype)
                # Management frame (type 0) with beacon (8) or assoc resp (1) subtype
                return frame_type == 0 and (subtype == 8 or subtype == 1)
            
            return False
            
        except (AttributeError, ValueError):
            return False
    
    def _extract_security_info(self, packet) -> Optional[NetworkSecurity]:
        """Extract security information from beacon or association response."""
        try:
            if not hasattr(packet, 'wlan'):
                return None
            
            bssid = packet.wlan.sa if hasattr(packet.wlan, 'sa') else None
            if not bssid:
                return None
            
            # Extract SSID
            ssid = ""
            if hasattr(packet, 'wlan_mgt') and hasattr(packet.wlan_mgt, 'ssid'):
                ssid = packet.wlan_mgt.ssid
            
            # Initialize or get existing network security
            if bssid not in self.networks:
                self.networks[bssid] = NetworkSecurity(bssid=bssid, ssid=ssid)
            
            network = self.networks[bssid]
            
            # Analyze RSN (WPA2/WPA3) Information
            self._parse_rsn_info(packet, network)
            
            # Analyze WPA Information
            self._parse_wpa_info(packet, network)
            
            # Determine overall security protocol
            self._determine_security_protocol(network)
            
            # Assess security risks
            self._assess_security_risks(network)
            
            return network
            
        except Exception as e:
            self.logger.debug(f"Error extracting security info: {e}")
            return None
    
    def _parse_rsn_info(self, packet, network: NetworkSecurity):
        """Parse RSN Information (WPA2/WPA3) from PyShark packet."""
        try:
            # Check for RSN information in management frame
            if hasattr(packet, 'wlan_mgt'):
                wlan_mgt = packet.wlan_mgt
                
                # Group cipher
                if hasattr(wlan_mgt, 'rsn_group_cipher_type'):
                    cipher_type = str(wlan_mgt.rsn_group_cipher_type)
                    if cipher_type in self.cipher_suites:
                        cipher_name = self.cipher_suites[cipher_type]
                        network.cipher_suites.append(f"Group: {cipher_name}")
                        if cipher_name == "TKIP":
                            network.tkip_present = True
                
                # Pairwise ciphers
                if hasattr(wlan_mgt, 'rsn_pairwise_cipher_type'):
                    cipher_type = str(wlan_mgt.rsn_pairwise_cipher_type)
                    if cipher_type in self.cipher_suites:
                        cipher_name = self.cipher_suites[cipher_type]
                        network.cipher_suites.append(f"Pairwise: {cipher_name}")
                        if cipher_name == "TKIP":
                            network.tkip_present = True
                
                # Authentication suites
                if hasattr(wlan_mgt, 'rsn_akm_type'):
                    auth_type = str(wlan_mgt.rsn_akm_type)
                    if auth_type in self.auth_suites:
                        auth_name = self.auth_suites[auth_type]
                        network.auth_suites.append(auth_name)
                        
                        # Check for WPA3/SAE
                        if auth_type == "8":  # SAE
                            network.sae_enabled = True
                            network.wpa3_enabled = True
                        
                        # Check for OWE
                        if auth_type == "18":  # OWE
                            network.owe_enabled = True
                
                # PMF capabilities
                if hasattr(wlan_mgt, 'rsn_pmf_capable'):
                    network.pmf_capable = True
                
                if hasattr(wlan_mgt, 'rsn_pmf_required'):
                    network.pmf_required = True
                    
        except Exception as e:
            self.logger.debug(f"Error parsing RSN info: {e}")
    
    def _parse_wpa_info(self, packet, network: NetworkSecurity):
        """Parse WPA Information (WPA1) from PyShark packet."""
        try:
            if hasattr(packet, 'wlan_mgt'):
                wlan_mgt = packet.wlan_mgt
                
                # Check for WPA information element
                if hasattr(wlan_mgt, 'wpa_version'):
                    network.cipher_suites.append("WPA1 detected")
                    # WPA1 typically uses TKIP by default
                    network.tkip_present = True
                
                # WPA cipher suites
                if hasattr(wlan_mgt, 'wpa_group_cipher_type'):
                    cipher_type = str(wlan_mgt.wpa_group_cipher_type)
                    if cipher_type in self.cipher_suites:
                        cipher_name = self.cipher_suites[cipher_type]
                        network.cipher_suites.append(f"WPA Group: {cipher_name}")
                        
        except Exception as e:
            self.logger.debug(f"Error parsing WPA info: {e}")
    
    def _determine_security_protocol(self, network: NetworkSecurity):
        """Determine the primary security protocol."""
        if network.sae_enabled:
            if any("PSK" in auth for auth in network.auth_suites):
                network.security_protocol = SecurityProtocol.WPA2_WPA3_MIXED
            else:
                network.security_protocol = SecurityProtocol.WPA3
        elif network.owe_enabled:
            network.security_protocol = SecurityProtocol.OWE
        elif network.cipher_suites:
            if any("WPA1" in cipher for cipher in network.cipher_suites):
                network.security_protocol = SecurityProtocol.WPA
            elif any("WEP" in cipher for cipher in network.cipher_suites):
                network.security_protocol = SecurityProtocol.WEP
            else:
                network.security_protocol = SecurityProtocol.WPA2
        else:
            network.security_protocol = SecurityProtocol.OPEN
    
    def _assess_security_risks(self, network: NetworkSecurity):
        """Assess security risks for the network."""
        risks = []
        max_risk = SecurityRisk.INFO
        
        # Check cipher risks
        for cipher in network.cipher_suites:
            for cipher_name, risk in self.cipher_risks.items():
                if cipher_name in cipher:
                    if risk == SecurityRisk.CRITICAL:
                        risks.append(f"Critical: {cipher_name} encryption is broken")
                        max_risk = SecurityRisk.CRITICAL
                    elif risk == SecurityRisk.HIGH:
                        risks.append(f"High: {cipher_name} has known vulnerabilities")
                        if max_risk not in [SecurityRisk.CRITICAL]:
                            max_risk = SecurityRisk.HIGH
        
        # TKIP specific risks
        if network.tkip_present:
            risks.append("TKIP is vulnerable to chopchop and other attacks")
        
        # PMF risks
        if not network.pmf_capable:
            risks.append("Management frame protection not supported")
            if max_risk == SecurityRisk.INFO:
                max_risk = SecurityRisk.MEDIUM
        
        # Protocol risks
        if network.security_protocol == SecurityProtocol.OPEN:
            risks.append("Open network - no encryption")
            max_risk = SecurityRisk.CRITICAL
        elif network.security_protocol == SecurityProtocol.WEP:
            risks.append("WEP encryption is completely broken")
            max_risk = SecurityRisk.CRITICAL
        elif network.security_protocol == SecurityProtocol.WPA:
            risks.append("WPA1 has known vulnerabilities")
            if max_risk not in [SecurityRisk.CRITICAL]:
                max_risk = SecurityRisk.HIGH
        
        network.security_risks = risks
        network.risk_level = max_risk
    
    def _analyze_security_posture(self, network: NetworkSecurity) -> List[Finding]:
        """Generate findings based on security posture analysis."""
        findings = []
        
        # Critical security issues
        if network.risk_level == SecurityRisk.CRITICAL:
            findings.append(Finding(
                analyzer_name=self.name,
                category=AnalysisCategory.SECURITY_THREATS,
                severity=Severity.CRITICAL,
                title="Critical Security Vulnerability Detected",
                description=f"Network {network.ssid} ({network.bssid}) has critical security issues",
                details={
                    "bssid": network.bssid,
                    "ssid": network.ssid,
                    "security_protocol": network.security_protocol.value,
                    "security_risks": network.security_risks,
                    "cipher_suites": network.cipher_suites,
                    "parser": "pyshark"
                },
                recommendations=[
                    "Immediately upgrade to WPA3 or WPA2 with strong encryption",
                    "Disable WEP and TKIP if still enabled",
                    "Enable PMF (Protected Management Frames)",
                    "Use strong passphrases for PSK networks"
                ]
            ))
        
        # High security risks
        elif network.risk_level == SecurityRisk.HIGH:
            findings.append(Finding(
                analyzer_name=self.name,
                category=AnalysisCategory.SECURITY_THREATS,
                severity=Severity.WARNING,
                title="High Security Risk Detected",
                description=f"Network {network.ssid} has significant security weaknesses",
                details={
                    "bssid": network.bssid,
                    "ssid": network.ssid,
                    "security_protocol": network.security_protocol.value,
                    "security_risks": network.security_risks,
                    "tkip_present": network.tkip_present,
                    "pmf_capable": network.pmf_capable,
                    "parser": "pyshark"
                },
                recommendations=[
                    "Upgrade to WPA3 for enhanced security",
                    "Disable TKIP cipher suite",
                    "Enable PMF if not already active",
                    "Consider enterprise authentication for sensitive environments"
                ]
            ))
        
        # WPA3 transition mode detection
        if network.security_protocol == SecurityProtocol.WPA2_WPA3_MIXED:
            findings.append(Finding(
                analyzer_name=self.name,
                category=AnalysisCategory.SECURITY_THREATS,
                severity=Severity.INFO,
                title="WPA2/WPA3 Transition Mode Detected",
                description=f"Network {network.ssid} is in WPA2/WPA3 transition mode",
                details={
                    "bssid": network.bssid,
                    "ssid": network.ssid,
                    "sae_enabled": network.sae_enabled,
                    "wpa3_enabled": network.wpa3_enabled,
                    "pmf_capable": network.pmf_capable,
                    "parser": "pyshark"
                },
                recommendations=[
                    "Plan migration to WPA3-only mode when all clients support it",
                    "Monitor for potential downgrade attacks",
                    "Ensure PMF is enforced consistently"
                ]
            ))
        
        # OWE detection
        if network.owe_enabled:
            findings.append(Finding(
                analyzer_name=self.name,
                category=AnalysisCategory.SECURITY_THREATS,
                severity=Severity.INFO,
                title="OWE (Enhanced Open) Network Detected",
                description=f"Network {network.ssid} supports Opportunistic Wireless Encryption",
                details={
                    "bssid": network.bssid,
                    "ssid": network.ssid,
                    "owe_enabled": network.owe_enabled,
                    "parser": "pyshark"
                },
                recommendations=[
                    "OWE provides encryption for open networks",
                    "Ensure client devices support OWE for full benefit",
                    "Monitor for proper OWE implementation"
                ]
            ))
        
        return findings
    
    def _analyze_eap_methods(self, packet) -> List[Finding]:
        """Analyze EAP methods for enterprise security assessment."""
        findings = []
        
        try:
            if hasattr(packet, 'eap') and hasattr(packet.eap, 'type'):
                eap_type = int(packet.eap.type)
                
                # Check for weak EAP methods
                weak_eap_methods = {
                    4: "MD5-Challenge",
                    6: "GTC", 
                    17: "LEAP"
                }
                
                if eap_type in weak_eap_methods:
                    findings.append(Finding(
                        analyzer_name=self.name,
                        category=AnalysisCategory.ENTERPRISE_SECURITY,
                        severity=Severity.WARNING,
                        title="Weak EAP Method Detected",
                        description=f"EAP method {weak_eap_methods[eap_type]} has known vulnerabilities",
                        details={
                            "eap_type": eap_type,
                            "eap_method": weak_eap_methods[eap_type],
                            "timestamp": float(packet.sniff_timestamp),
                            "parser": "pyshark"
                        },
                        recommendations=[
                            "Use stronger EAP methods like EAP-TLS or EAP-TTLS",
                            "Avoid EAP-MD5 and LEAP in production environments",
                            "Implement certificate-based authentication"
                        ]
                    ))
        
        except Exception as e:
            self.logger.error(f"Error analyzing EAP methods: {e}")
        
        return findings
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get comprehensive analysis summary."""
        if not PYSHARK_AVAILABLE:
            return {"error": "PyShark not available"}
        
        protocol_distribution = Counter()
        risk_distribution = Counter()
        
        for network in self.networks.values():
            protocol_distribution[network.security_protocol.value] += 1
            risk_distribution[network.risk_level.value] += 1
        
        return {
            "analyzer": self.name,
            "parser": "pyshark",
            "networks_analyzed": len(self.networks),
            "protocol_distribution": dict(protocol_distribution),
            "risk_distribution": dict(risk_distribution),
            "wpa3_networks": sum(1 for n in self.networks.values() if n.wpa3_enabled),
            "owe_networks": sum(1 for n in self.networks.values() if n.owe_enabled),
            "pmf_capable_networks": sum(1 for n in self.networks.values() if n.pmf_capable),
            "tkip_networks": sum(1 for n in self.networks.values() if n.tkip_present),
            "critical_risk_networks": risk_distribution.get("critical", 0),
            "high_risk_networks": risk_distribution.get("high", 0)
        }