"""
Scapy-specific Enterprise Security Analyzer

Analyzes 802.1X/EAP/TLS enterprise authentication security using Scapy's
native packet parsing capabilities.
"""

import hashlib
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Any, Set, Optional

from scapy.all import Packet, Raw
from scapy.layers.dot11 import Dot11, Dot11Auth, Dot11AssoReq, Dot11AssoResp
from scapy.layers.eap import EAPOL, EAP
from scapy.layers.inet import IP, UDP

# TLS imports with graceful fallback
try:
    from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello, TLSCertificate
    TLS_AVAILABLE = True
except ImportError:
    TLS = TLSClientHello = TLSServerHello = TLSCertificate = None
    TLS_AVAILABLE = False

from ....core.base_analyzer import BaseScapyAnalyzer
from ....core.models import Finding


class EAPMethodType(Enum):
    """EAP method types with security classifications."""
    IDENTITY = (1, "Identity", "INFO")
    MD5_CHALLENGE = (4, "MD5-Challenge", "WEAK")
    TLS = (13, "EAP-TLS", "STRONG")
    LEAP = (17, "LEAP", "WEAK")
    TTLS = (21, "EAP-TTLS", "STRONG")
    PEAP = (25, "PEAP", "STRONG")
    MSCHAPV2 = (26, "MS-CHAPv2", "WEAK")
    FAST = (43, "EAP-FAST", "STRONG")
    
    def __init__(self, method_id: int, name: str, security_level: str):
        self.method_id = method_id
        self.method_name = name
        self.security_level = security_level


@dataclass
class AuthenticationAttempt:
    """802.1X authentication attempt tracking."""
    client_mac: str
    ap_bssid: str
    timestamp: float
    eap_methods: List[str] = field(default_factory=list)
    success: Optional[bool] = None
    failure_reason: Optional[str] = None
    certificates: List[str] = field(default_factory=list)


@dataclass
class EnterpriseNetwork:
    """Enterprise network security profile."""
    bssid: str
    ssid: str
    eap_methods_seen: Set[str] = field(default_factory=set)
    weak_methods_detected: List[str] = field(default_factory=list)
    certificate_issues: List[str] = field(default_factory=list)
    authentication_attempts: int = 0
    successful_auths: int = 0
    failed_auths: int = 0


class ScapyEnterpriseSecurityAnalyzer(BaseScapyAnalyzer):
    """
    Scapy-based enterprise security analyzer.
    
    Analyzes:
    - 802.1X authentication flows
    - EAP method security assessment
    - TLS certificate validation
    - Enterprise security posture
    """
    
    def __init__(self):
        super().__init__()
        self.name = "Scapy Enterprise Security Analyzer"
        self.description = "Analyzes enterprise security using Scapy parsing"
        self.version = "1.0.0"
        
        # Enterprise network tracking
        self.enterprise_networks: Dict[str, EnterpriseNetwork] = {}
        self.auth_attempts: List[AuthenticationAttempt] = []
        
        # EAP method mapping
        self.eap_methods = {}
        for method in EAPMethodType:
            self.eap_methods[method.method_id] = method
        
        # Weak EAP methods
        self.weak_eap_methods = {
            4: "MD5-Challenge - easily broken",
            17: "LEAP - vulnerable to dictionary attacks", 
            26: "MS-CHAPv2 - vulnerable without proper tunneling"
        }
        
        # Certificate tracking
        self.certificates_seen: Dict[str, Dict[str, Any]] = {}

    def analyze_packet(self, packet, metadata: Dict[str, Any] = None) -> List[Finding]:
        """Analyze a single packet for enterprise security information."""
        findings = []
        
        try:
            if packet.haslayer(EAPOL):
                findings.extend(self._analyze_eapol_packet(packet))
            
            elif packet.haslayer(EAP):
                findings.extend(self._analyze_eap_packet(packet))
            
            elif TLS_AVAILABLE and packet.haslayer(TLS):
                findings.extend(self._analyze_tls_packet(packet))
        
        except Exception as e:
            self.logger.error(f"Error analyzing enterprise security: {e}")
        
        return findings
    
    def _analyze_eapol_packet(self, packet) -> List[Finding]:
        """Analyze EAPOL packets for 802.1X authentication."""
        findings = []
        
        try:
            if not packet.haslayer(Dot11) or not packet.haslayer(EAPOL):
                return findings
            
            dot11 = packet[Dot11]
            eapol = packet[EAPOL]
            
            # Extract basic info
            client_mac = str(dot11.addr2) if hasattr(dot11, 'addr2') else None
            ap_bssid = str(dot11.addr1) if hasattr(dot11, 'addr1') else None
            
            if not client_mac or not ap_bssid:
                return findings
            
            # Track enterprise network
            if ap_bssid not in self.enterprise_networks:
                self.enterprise_networks[ap_bssid] = EnterpriseNetwork(
                    bssid=ap_bssid,
                    ssid=""  # Will be filled from beacon analysis
                )
            
            network = self.enterprise_networks[ap_bssid]
            network.authentication_attempts += 1
            
            # EAPOL packet type analysis
            if hasattr(eapol, 'type'):
                eapol_type = eapol.type
                
                if eapol_type == 1:  # EAP-Packet
                    # EAP packet contained in EAPOL
                    if packet.haslayer(EAP):
                        eap_findings = self._analyze_eap_packet(packet, network)
                        findings.extend(eap_findings)
                
                elif eapol_type == 3:  # EAPOL-Key
                    # 4-way handshake analysis
                    findings.extend(self._analyze_eapol_key(packet, network))
        
        except Exception as e:
            self.logger.debug(f"Error analyzing EAPOL packet: {e}")
        
        return findings
    
    def _analyze_eap_packet(self, packet, network: EnterpriseNetwork = None) -> List[Finding]:
        """Analyze EAP packets for method security assessment."""
        findings = []
        
        try:
            if not packet.haslayer(EAP):
                return findings
            
            eap = packet[EAP]
            
            # Extract EAP method type
            if hasattr(eap, 'type'):
                eap_type = eap.type
                
                # Look up EAP method
                method_info = self.eap_methods.get(eap_type)
                if method_info:
                    method_name = method_info.method_name
                    security_level = method_info.security_level
                    
                    # Track method in network
                    if network:
                        network.eap_methods_seen.add(method_name)
                    
                    # Check for weak EAP methods
                    if eap_type in self.weak_eap_methods:
                        if network:
                            network.weak_methods_detected.append(method_name)
                        
                        findings.append(self.create_finding(
                            finding_type="weak_eap_method",
                            severity="warning",
                            title="Weak EAP Method Detected",
                            description=f"EAP method {method_name} has known security vulnerabilities",
                            evidence={
                                "eap_type": eap_type,
                                "eap_method": method_name,
                                "security_level": security_level,
                                "vulnerability": self.weak_eap_methods[eap_type],
                                "network_bssid": network.bssid if network else None,
                                "timestamp": float(packet.time) if hasattr(packet, 'time') else 0,
                                "parser": "scapy"
                            },
                            recommendations=[
                                "Upgrade to stronger EAP methods like EAP-TLS or PEAP",
                                f"Disable {method_name} if not required",
                                "Use certificate-based authentication when possible",
                                "Ensure proper TLS tunneling for inner methods"
                            ]
                        ))
                
                # EAP Success/Failure analysis
                if hasattr(eap, 'code'):
                    if eap.code == 3:  # EAP-Success
                        if network:
                            network.successful_auths += 1
                    elif eap.code == 4:  # EAP-Failure
                        if network:
                            network.failed_auths += 1
                        
                        findings.append(self.create_finding(
                            finding_type="eap_authentication_failure",
                            severity="info",
                            title="EAP Authentication Failure",
                            description="EAP authentication failed",
                            evidence={
                                "client_mac": str(packet[Dot11].addr2) if packet.haslayer(Dot11) else None,
                                "ap_bssid": network.bssid if network else None,
                                "timestamp": float(packet.time) if hasattr(packet, 'time') else 0,
                                "parser": "scapy"
                            },
                            recommendations=[
                                "Check client certificate validity",
                                "Verify user credentials",
                                "Review RADIUS server logs",
                                "Check network connectivity to authentication server"
                            ]
                        ))
        
        except Exception as e:
            self.logger.debug(f"Error analyzing EAP packet: {e}")
        
        return findings
    
    def _analyze_eapol_key(self, packet, network: EnterpriseNetwork) -> List[Finding]:
        """Analyze EAPOL-Key packets for 4-way handshake security."""
        findings = []
        
        try:
            # Basic 4-way handshake analysis
            # This is simplified - could be expanded for detailed handshake analysis
            
            if packet.haslayer(EAPOL):
                eapol = packet[EAPOL]
                
                # Check for potential replay attacks or anomalies
                if hasattr(eapol, 'replay_counter'):
                    # Could track replay counters for anomaly detection
                    pass
        
        except Exception as e:
            self.logger.debug(f"Error analyzing EAPOL-Key: {e}")
        
        return findings
    
    def _analyze_tls_packet(self, packet) -> List[Finding]:
        """Analyze TLS packets for certificate security assessment."""
        findings = []
        
        if not TLS_AVAILABLE:
            return findings
        
        try:
            if packet.haslayer(TLSCertificate):
                findings.extend(self._analyze_tls_certificate(packet))
            
            elif packet.haslayer(TLSClientHello):
                findings.extend(self._analyze_tls_client_hello(packet))
            
            elif packet.haslayer(TLSServerHello):
                findings.extend(self._analyze_tls_server_hello(packet))
        
        except Exception as e:
            self.logger.debug(f"Error analyzing TLS packet: {e}")
        
        return findings
    
    def _analyze_tls_certificate(self, packet) -> List[Finding]:
        """Analyze TLS certificates for security issues."""
        findings = []
        
        try:
            cert = packet[TLSCertificate]
            
            # Basic certificate analysis
            # This is simplified - real certificate parsing would be more complex
            
            if hasattr(cert, 'certs') and cert.certs:
                for cert_data in cert.certs:
                    cert_hash = hashlib.sha256(bytes(cert_data)).hexdigest()
                    
                    if cert_hash not in self.certificates_seen:
                        self.certificates_seen[cert_hash] = {
                            "first_seen": float(packet.time) if hasattr(packet, 'time') else 0,
                            "usage_count": 1
                        }
                        
                        # Certificate security check placeholder
                        findings.append(self.create_finding(
                            finding_type="tls_certificate_detected",
                            severity="info",
                            title="TLS Certificate Observed",
                            description="TLS certificate detected in enterprise authentication",
                            evidence={
                                "certificate_hash": cert_hash,
                                "timestamp": float(packet.time) if hasattr(packet, 'time') else 0,
                                "parser": "scapy"
                            },
                            recommendations=[
                                "Verify certificate is from trusted CA",
                                "Check certificate expiration date",
                                "Ensure certificate chain is valid",
                                "Validate certificate usage and key extensions"
                            ]
                        ))
                    else:
                        self.certificates_seen[cert_hash]["usage_count"] += 1
        
        except Exception as e:
            self.logger.debug(f"Error analyzing TLS certificate: {e}")
        
        return findings
    
    def _analyze_tls_client_hello(self, packet) -> List[Finding]:
        """Analyze TLS Client Hello for security configuration."""
        findings = []
        
        try:
            client_hello = packet[TLSClientHello]
            
            # Analyze TLS version
            if hasattr(client_hello, 'version'):
                version = client_hello.version
                if version < 0x0303:  # TLS 1.2
                    findings.append(self.create_finding(
                        finding_type="weak_tls_version",
                        severity="warning",
                        title="Weak TLS Version Detected",
                        description=f"Client using TLS version {version:#04x}, which may be vulnerable",
                        evidence={
                            "tls_version": version,
                            "timestamp": float(packet.time) if hasattr(packet, 'time') else 0,
                            "parser": "scapy"
                        },
                        recommendations=[
                            "Upgrade to TLS 1.2 or higher",
                            "Disable support for older TLS versions",
                            "Check client certificate requirements"
                        ]
                    ))
            
            # Analyze cipher suites (if available)
            if hasattr(client_hello, 'cipher_suites'):
                # Could analyze for weak cipher suites
                pass
        
        except Exception as e:
            self.logger.debug(f"Error analyzing TLS Client Hello: {e}")
        
        return findings
    
    def _analyze_tls_server_hello(self, packet) -> List[Finding]:
        """Analyze TLS Server Hello for security configuration."""
        findings = []
        
        try:
            server_hello = packet[TLSServerHello]
            
            # Similar analysis as Client Hello but from server perspective
            if hasattr(server_hello, 'version'):
                version = server_hello.version
                if version < 0x0303:  # TLS 1.2
                    findings.append(self.create_finding(
                        finding_type="weak_tls_version",
                        severity="warning",
                        title="Server Using Weak TLS Version",
                        description=f"Server selected TLS version {version:#04x}, which may be vulnerable",
                        evidence={
                            "tls_version": version,
                            "timestamp": float(packet.time) if hasattr(packet, 'time') else 0,
                            "parser": "scapy"
                        },
                        recommendations=[
                            "Configure server to require TLS 1.2 or higher",
                            "Update server TLS configuration",
                            "Review cipher suite preferences"
                        ]
                    ))
        
        except Exception as e:
            self.logger.debug(f"Error analyzing TLS Server Hello: {e}")
        
        return findings
    
    def analyze_enterprise_posture(self) -> List[Finding]:
        """Analyze overall enterprise security posture."""
        findings = []
        
        for network in self.enterprise_networks.values():
            # Check for weak EAP methods
            if network.weak_methods_detected:
                findings.append(self.create_finding(
                    finding_type="enterprise_security_weakness",
                    severity="warning",
                    title="Weak EAP Methods in Enterprise Network",
                    description=f"Network {network.bssid} allows weak EAP authentication methods",
                    evidence={
                        "bssid": network.bssid,
                        "ssid": network.ssid,
                        "weak_methods": network.weak_methods_detected,
                        "all_methods": list(network.eap_methods_seen),
                        "auth_attempts": network.authentication_attempts,
                        "success_rate": network.successful_auths / max(network.authentication_attempts, 1),
                        "parser": "scapy"
                    },
                    recommendations=[
                        "Disable weak EAP methods in network policy",
                        "Migrate to stronger authentication methods",
                        "Implement certificate-based authentication",
                        "Review enterprise authentication policy"
                    ]
                ))
            
            # Check authentication success rate
            if network.authentication_attempts > 10:
                success_rate = network.successful_auths / network.authentication_attempts
                if success_rate < 0.7:  # Less than 70% success rate
                    findings.append(self.create_finding(
                        finding_type="low_auth_success_rate",
                        severity="info",
                        title="Low Authentication Success Rate",
                        description=f"Network {network.bssid} has low authentication success rate ({success_rate:.1%})",
                        evidence={
                            "bssid": network.bssid,
                            "success_rate": success_rate,
                            "total_attempts": network.authentication_attempts,
                            "successful_auths": network.successful_auths,
                            "failed_auths": network.failed_auths,
                            "parser": "scapy"
                        },
                        recommendations=[
                            "Investigate authentication failures",
                            "Check RADIUS server connectivity",
                            "Review certificate validity and trust chains",
                            "Verify client configuration"
                        ]
                    ))
        
        return findings
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get comprehensive enterprise security analysis summary."""
        total_attempts = sum(net.authentication_attempts for net in self.enterprise_networks.values())
        total_successes = sum(net.successful_auths for net in self.enterprise_networks.values())
        
        all_methods = set()
        weak_methods = set()
        for network in self.enterprise_networks.values():
            all_methods.update(network.eap_methods_seen)
            weak_methods.update(network.weak_methods_detected)
        
        return {
            "analyzer": self.name,
            "parser": "scapy",
            "enterprise_networks": len(self.enterprise_networks),
            "total_auth_attempts": total_attempts,
            "total_successful_auths": total_successes,
            "overall_success_rate": total_successes / max(total_attempts, 1),
            "eap_methods_observed": list(all_methods),
            "weak_eap_methods_detected": list(weak_methods),
            "certificates_observed": len(self.certificates_seen),
            "tls_available": TLS_AVAILABLE,
            "networks_with_weak_methods": sum(1 for net in self.enterprise_networks.values() if net.weak_methods_detected)
        }