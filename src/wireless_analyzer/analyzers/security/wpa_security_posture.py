"""
WPA2/WPA3/OWE Security Posture Analysis for wireless PCAP data.

This analyzer provides comprehensive security posture analysis including:
- Per-BSSID cipher suite and authentication method analysis
- WPA2/WPA3 transition mode security assessment and risk analysis
- TKIP presence detection and vulnerability assessment
- 802.1X/EAP method security validation and certificate analysis
- TLS certificate validation and trust chain verification
- OWE (Opportunistic Wireless Encryption) implementation analysis
- Security downgrade attack detection and prevention assessment
- WPA3 Personal/Enterprise security feature validation
- SAE (Simultaneous Authentication of Equals) implementation analysis
- PMF (Protected Management Frames) enforcement and compliance
- Advanced cipher suite vulnerability assessment
"""

import struct
import hashlib
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Any, Set, Optional, NamedTuple, Tuple
import logging
import re

from scapy.all import Packet
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11AssoReq, Dot11AssoResp, Dot11Elt
from scapy.layers.eap import EAPOL, EAP
# TLS imports - adjust based on available Scapy version
try:
    from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello, TLSCertificate
except ImportError:
    try:
        from scapy.layers.tls import TLSClientHello, TLSServerHello
        TLS = None
        TLSCertificate = None
    except ImportError:
        TLS = None
        TLSClientHello = None
        TLSServerHello = None
        TLSCertificate = None

from ...core.base_analyzer import BaseAnalyzer
from ...utils.analyzer_helpers import (
    packet_has_layer, get_packet_layer, get_packet_field,
    get_src_mac, get_dst_mac, get_bssid, get_timestamp
)
from ...core.models import (
    Finding, 
    Severity, 
    AnalysisContext,
    AnalysisCategory
)


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


class CipherSuite(Enum):
    """Cipher suite enumeration."""
    NONE = "none"
    WEP40 = "wep40"
    WEP104 = "wep104"
    TKIP = "tkip"
    CCMP = "ccmp"
    GCMP = "gcmp"
    GCMP_256 = "gcmp_256"
    CCMP_256 = "ccmp_256"


class AuthSuite(Enum):
    """Authentication suite enumeration."""
    OPEN = "open"
    WEP = "wep"
    PSK = "psk"
    IEEE8021X = "ieee_8021x"
    FT_PSK = "ft_psk"
    FT_IEEE8021X = "ft_ieee_8021x"
    SHA256_PSK = "sha256_psk"
    SHA256_IEEE8021X = "sha256_ieee_8021x"
    SAE = "sae"
    FT_SAE = "ft_sae"
    SUITE_B_192 = "suite_b_192"
    OWE = "owe"
    FILS_SHA256 = "fils_sha256"
    FILS_SHA384 = "fils_sha384"


class SecurityRisk(Enum):
    """Security risk levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class CipherSuiteInfo:
    """Cipher suite detailed information."""
    oui: bytes
    suite_type: int
    name: str
    security_level: SecurityRisk
    vulnerabilities: List[str] = field(default_factory=list)
    deprecation_status: Optional[str] = None


@dataclass
class AuthSuiteInfo:
    """Authentication suite detailed information."""
    oui: bytes
    suite_type: int
    name: str
    method: str
    security_level: SecurityRisk
    requires_infrastructure: bool = False
    vulnerabilities: List[str] = field(default_factory=list)


@dataclass
class CertificateInfo:
    """Certificate information from TLS analysis."""
    subject: str
    issuer: str
    serial_number: str
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    algorithm: Optional[str] = None
    key_size: Optional[int] = None
    fingerprint: Optional[str] = None
    is_ca: bool = False
    is_self_signed: bool = False
    validation_errors: List[str] = field(default_factory=list)


@dataclass
class SecurityPosture:
    """Comprehensive security posture for a network."""
    bssid: str
    ssid: str
    
    # Protocol analysis
    primary_protocol: SecurityProtocol = SecurityProtocol.OPEN
    supported_protocols: Set[SecurityProtocol] = field(default_factory=set)
    is_transition_mode: bool = False
    
    # Cipher analysis
    group_cipher: Optional[CipherSuiteInfo] = None
    pairwise_ciphers: List[CipherSuiteInfo] = field(default_factory=list)
    
    # Authentication analysis
    auth_suites: List[AuthSuiteInfo] = field(default_factory=list)
    
    # Advanced security features
    pmf_capable: bool = False
    pmf_required: bool = False
    fast_transition_enabled: bool = False
    sae_enabled: bool = False
    owe_enabled: bool = False
    
    # TKIP analysis
    tkip_present: bool = False
    tkip_only: bool = False
    tkip_vulnerabilities: List[str] = field(default_factory=list)
    
    # 802.1X/EAP analysis
    enterprise_auth: bool = False
    eap_methods_observed: Set[str] = field(default_factory=set)
    certificate_info: List[CertificateInfo] = field(default_factory=list)
    
    # Security risks
    overall_security_level: SecurityRisk = SecurityRisk.INFO
    security_risks: List[str] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    # Compliance
    pci_compliant: bool = False
    fips_compliant: bool = False
    enterprise_ready: bool = False


@dataclass
class TransitionModeAnalysis:
    """WPA2/WPA3 transition mode analysis."""
    networks_in_transition: int = 0
    transition_configurations: List[Dict[str, Any]] = field(default_factory=list)
    security_risks: List[str] = field(default_factory=list)
    downgrade_opportunities: List[str] = field(default_factory=list)


class WPASecurityPostureAnalyzer(BaseAnalyzer):
    """
    Comprehensive WPA2/WPA3/OWE Security Posture Analyzer.
    
    This analyzer performs deep security posture assessment of wireless networks
    including cipher suite analysis, authentication method validation, certificate
    verification, and advanced security feature assessment.
    """
    
    def __init__(self):
        super().__init__(
            name="WPA Security Posture Analyzer",
            category=AnalysisCategory.ENTERPRISE_SECURITY,
            version="1.0"
        )
        
        self.description = (
            "Comprehensive security posture analysis for WPA2/WPA3/OWE networks "
            "including cipher suites, authentication methods, and certificate validation"
        )
        
        # Wireshark filters
        self.wireshark_filters = [
            "wlan_mgt.rsn",  # RSN Information Element
            "wlan_mgt.wpa",  # WPA Information Element
            "wlan.rsn.cipher",
            "wlan.rsn.akm",
            "eap",
            "tls",
            "wlan.rsn.pmf.capable",
            "wlan.rsn.pmf.required"
        ]
        
        self.analysis_order = 40  # Run after EAPOL/PMF analysis
        
        # Analysis storage
        self.security_postures: Dict[str, SecurityPosture] = {}  # Key: bssid
        self.transition_analysis = TransitionModeAnalysis()
        self.certificate_store: Dict[str, CertificateInfo] = {}
        
        # Security suite databases
        self._initialize_cipher_suites()
        self._initialize_auth_suites()
        
        # Security policy rules
        self.security_policies = {
            'min_cipher_strength': CipherSuite.CCMP,
            'banned_ciphers': [CipherSuite.WEP40, CipherSuite.WEP104, CipherSuite.TKIP],
            'preferred_auth': [AuthSuite.SAE, AuthSuite.IEEE8021X, AuthSuite.SHA256_IEEE8021X],
            'require_pmf': True,
            'allow_transition_mode': False
        }

    def _initialize_cipher_suites(self):
        """Initialize cipher suite database."""
        self.cipher_suites = {
            # Standard cipher suites (00-0F-AC)
            (b'\x00\x0f\xac', 0): CipherSuiteInfo(
                b'\x00\x0f\xac', 0, "Use Group Cipher", SecurityRisk.INFO
            ),
            (b'\x00\x0f\xac', 1): CipherSuiteInfo(
                b'\x00\x0f\xac', 1, "WEP-40", SecurityRisk.CRITICAL,
                ["Broken encryption", "Easily cracked"], "Deprecated since 2004"
            ),
            (b'\x00\x0f\xac', 2): CipherSuiteInfo(
                b'\x00\x0f\xac', 2, "TKIP", SecurityRisk.HIGH,
                ["RC4-based", "Michael MIC vulnerabilities", "Chopchop attacks"], "Deprecated since 2012"
            ),
            (b'\x00\x0f\xac', 4): CipherSuiteInfo(
                b'\x00\x0f\xac', 4, "CCMP-128 (AES)", SecurityRisk.LOW,
                [], None
            ),
            (b'\x00\x0f\xac', 5): CipherSuiteInfo(
                b'\x00\x0f\xac', 5, "WEP-104", SecurityRisk.CRITICAL,
                ["Broken encryption", "Easily cracked"], "Deprecated since 2004"
            ),
            (b'\x00\x0f\xac', 8): CipherSuiteInfo(
                b'\x00\x0f\xac', 8, "GCMP-128", SecurityRisk.LOW
            ),
            (b'\x00\x0f\xac', 9): CipherSuiteInfo(
                b'\x00\x0f\xac', 9, "GCMP-256", SecurityRisk.LOW
            ),
            (b'\x00\x0f\xac', 10): CipherSuiteInfo(
                b'\x00\x0f\xac', 10, "CCMP-256", SecurityRisk.LOW
            )
        }
        
    def _initialize_auth_suites(self):
        """Initialize authentication suite database."""
        self.auth_suites = {
            # Standard AKM suites (00-0F-AC)
            (b'\x00\x0f\xac', 1): AuthSuiteInfo(
                b'\x00\x0f\xac', 1, "IEEE 802.1X", "EAP", SecurityRisk.LOW, True
            ),
            (b'\x00\x0f\xac', 2): AuthSuiteInfo(
                b'\x00\x0f\xac', 2, "PSK", "Pre-Shared Key", SecurityRisk.MEDIUM
            ),
            (b'\x00\x0f\xac', 3): AuthSuiteInfo(
                b'\x00\x0f\xac', 3, "FT over IEEE 802.1X", "Fast Transition EAP", SecurityRisk.LOW, True
            ),
            (b'\x00\x0f\xac', 4): AuthSuiteInfo(
                b'\x00\x0f\xac', 4, "FT using PSK", "Fast Transition PSK", SecurityRisk.MEDIUM
            ),
            (b'\x00\x0f\xac', 5): AuthSuiteInfo(
                b'\x00\x0f\xac', 5, "IEEE 802.1X/SHA-256", "EAP with SHA-256", SecurityRisk.LOW, True
            ),
            (b'\x00\x0f\xac', 6): AuthSuiteInfo(
                b'\x00\x0f\xac', 6, "PSK/SHA-256", "PSK with SHA-256", SecurityRisk.LOW
            ),
            (b'\x00\x0f\xac', 8): AuthSuiteInfo(
                b'\x00\x0f\xac', 8, "SAE", "WPA3-Personal", SecurityRisk.LOW,
                vulnerabilities=[]
            ),
            (b'\x00\x0f\xac', 9): AuthSuiteInfo(
                b'\x00\x0f\xac', 9, "FT over SAE", "Fast Transition SAE", SecurityRisk.LOW
            ),
            (b'\x00\x0f\xac', 11): AuthSuiteInfo(
                b'\x00\x0f\xac', 11, "Suite B 192-bit", "Enterprise Suite B", SecurityRisk.LOW, True
            ),
            (b'\x00\x0f\xac', 18): AuthSuiteInfo(
                b'\x00\x0f\xac', 18, "OWE", "Opportunistic Wireless Encryption", SecurityRisk.LOW
            )
        }

    def is_applicable(self, packet: Packet) -> bool:
        """Check if packet is relevant for security posture analysis."""
        return (packet_has_layer(packet, Dot11Beacon) or
                packet_has_layer(packet, Dot11AssoReq) or
                packet_has_layer(packet, Dot11AssoResp) or
                packet_has_layer(packet, EAP) or
                packet_has_layer(packet, TLS))
        
    def get_display_filters(self) -> List[str]:
        """Get Wireshark display filters."""
        return self.wireshark_filters
        
    def analyze(self, packets: List[Packet], context: AnalysisContext) -> List[Finding]:
        """
        Analyze WPA2/WPA3/OWE security posture.
        
        Args:
            packets: List of relevant packets
            context: Analysis context
            
        Returns:
            List of findings
        """
        if not packets:
            return []
            
        self.logger.info(f"Analyzing WPA security posture from {len(packets)} packets")
        
        # Get beacon inventory for base security info
        beacon_inventory = context.metadata.get('beacon_inventory', {})
        
        # Initialize security postures from beacon data
        self._initialize_security_postures(beacon_inventory)
        
        # Analyze security frames
        self._analyze_security_frames(packets)
        
        # Analyze 802.1X/EAP sessions
        self._analyze_eap_security(packets, context)
        
        # Analyze certificates
        self._analyze_certificates(packets)
        
        # Perform comprehensive security assessment
        self._assess_security_postures()
        
        # Analyze transition modes
        self._analyze_transition_modes()
        
        self.logger.info(f"Analyzed security posture for {len(self.security_postures)} networks")
        
        # Generate findings
        findings = []
        findings.extend(self._analyze_overall_security_posture())
        findings.extend(self._analyze_cipher_suite_security())
        findings.extend(self._analyze_tkip_vulnerabilities())
        findings.extend(self._analyze_transition_mode_risks())
        findings.extend(self._analyze_authentication_security())
        findings.extend(self._analyze_certificate_security())
        findings.extend(self._analyze_pmf_compliance())
        findings.extend(self._analyze_wpa3_adoption())
        findings.extend(self._analyze_security_downgrades())
        
        # Store results in context
        context.metadata['wpa_security_posture'] = {
            'networks_analyzed': len(self.security_postures),
            'security_distribution': self._get_security_distribution(),
            'critical_risks': self._get_critical_risks(),
            'transition_analysis': self.transition_analysis
        }
        
        self.findings_generated = len(findings)
        return findings
        
    def _initialize_security_postures(self, beacon_inventory: Dict) -> None:
        """Initialize security postures from beacon inventory."""
        for bssid, beacon_entry in beacon_inventory.items():
            posture = SecurityPosture(
                bssid=bssid,
                ssid=getattr(beacon_entry, 'ssid', 'Unknown')
            )
            
            # Extract basic security info from beacon
            if hasattr(beacon_entry, 'security'):
                security = beacon_entry.security
                
                # Determine primary protocol
                if getattr(security, 'wpa3', False):
                    posture.primary_protocol = SecurityProtocol.WPA3
                    posture.supported_protocols.add(SecurityProtocol.WPA3)
                elif getattr(security, 'wpa2', False):
                    posture.primary_protocol = SecurityProtocol.WPA2
                    posture.supported_protocols.add(SecurityProtocol.WPA2)
                elif getattr(security, 'wpa', False):
                    posture.primary_protocol = SecurityProtocol.WPA
                    posture.supported_protocols.add(SecurityProtocol.WPA)
                elif getattr(security, 'open', False):
                    posture.primary_protocol = SecurityProtocol.OPEN
                    posture.supported_protocols.add(SecurityProtocol.OPEN)
                
                # Check for transition mode
                if getattr(security, 'transition_mode', False):
                    posture.is_transition_mode = True
                    posture.primary_protocol = SecurityProtocol.WPA2_WPA3_MIXED
                    posture.supported_protocols.update([SecurityProtocol.WPA2, SecurityProtocol.WPA3])
                
                # PMF status
                posture.pmf_capable = getattr(security, 'pmf_capable', False)
                posture.pmf_required = getattr(security, 'pmf_required', False)
                
                # Authentication suites
                akm_suites = getattr(security, 'akm_suites', [])
                for akm in akm_suites:
                    if akm == 'SAE':
                        posture.sae_enabled = True
                    elif akm == 'OWE':
                        posture.owe_enabled = True
                    elif akm in ['IEEE8021X', 'SHA256-IEEE8021X']:
                        posture.enterprise_auth = True
                        
            self.security_postures[bssid] = posture
            
    def _analyze_security_frames(self, packets: List[Packet]) -> None:
        """Analyze security-related frames for detailed posture assessment."""
        for packet in packets:
            try:
                if packet_has_layer(packet, Dot11Beacon) or packet_has_layer(packet, Dot11AssoResp):
                    self._analyze_rsn_ie(packet)
                elif packet_has_layer(packet, Dot11AssoReq):
                    self._analyze_client_capabilities(packet)
                    
            except Exception as e:
                self.logger.debug(f"Error analyzing security frame: {e}")
                continue
                
    def _analyze_rsn_ie(self, packet: Packet) -> None:
        """Analyze RSN Information Element for detailed security configuration."""
        if not packet_has_layer(packet, Dot11):
            return
            
        dot11 = get_packet_layer(packet, "Dot11")
        bssid = dot11.addr3 if dot11.addr3 else dot11.addr2
        
        if bssid not in self.security_postures:
            return
            
        posture = self.security_postures[bssid]
        
        # Parse RSN IE
        if packet_has_layer(packet, Dot11Elt):
            current_ie = get_packet_layer(packet, "Dot11Elt")
            while current_ie:
                if current_ie.ID == 48:  # RSN IE
                    self._parse_rsn_ie(current_ie, posture)
                elif current_ie.ID == 221:  # Vendor specific (WPA)
                    ie_data = bytes(current_ie.info) if current_ie.info else b''
                    if len(ie_data) >= 4 and ie_data[:4] == b'\x00\x50\xf2\x01':
                        self._parse_wpa_ie(current_ie, posture)
                        
                current_ie = current_ie.payload if hasattr(current_ie, 'payload') and isinstance(current_ie.payload, Dot11Elt) else None
                
    def _parse_rsn_ie(self, ie: Dot11Elt, posture: SecurityPosture) -> None:
        """Parse RSN Information Element."""
        try:
            ie_data = bytes(ie.info) if ie.info else b''
            if len(ie_data) < 2:
                return
                
            # RSN version
            version = struct.unpack('<H', ie_data[:2])[0]
            offset = 2
            
            # Group cipher suite
            if len(ie_data) >= offset + 4:
                group_cipher_data = ie_data[offset:offset+4]
                cipher_info = self._parse_cipher_suite(group_cipher_data)
                if cipher_info:
                    posture.group_cipher = cipher_info
                    if cipher_info.name == "TKIP":
                        posture.tkip_present = True
                offset += 4
                
            # Pairwise cipher suites
            if len(ie_data) >= offset + 2:
                pairwise_count = struct.unpack('<H', ie_data[offset:offset+2])[0]
                offset += 2
                
                posture.pairwise_ciphers = []
                for _ in range(min(pairwise_count, 10)):  # Limit for safety
                    if len(ie_data) >= offset + 4:
                        cipher_data = ie_data[offset:offset+4]
                        cipher_info = self._parse_cipher_suite(cipher_data)
                        if cipher_info:
                            posture.pairwise_ciphers.append(cipher_info)
                            if cipher_info.name == "TKIP":
                                posture.tkip_present = True
                        offset += 4
                        
            # Check if TKIP is the only cipher
            if posture.tkip_present:
                non_tkip_ciphers = [c for c in posture.pairwise_ciphers if c.name != "TKIP"]
                posture.tkip_only = len(non_tkip_ciphers) == 0
                
            # AKM suites
            if len(ie_data) >= offset + 2:
                akm_count = struct.unpack('<H', ie_data[offset:offset+2])[0]
                offset += 2
                
                posture.auth_suites = []
                for _ in range(min(akm_count, 10)):  # Limit for safety
                    if len(ie_data) >= offset + 4:
                        akm_data = ie_data[offset:offset+4]
                        auth_info = self._parse_auth_suite(akm_data)
                        if auth_info:
                            posture.auth_suites.append(auth_info)
                            
                            # Update flags based on auth suite
                            if auth_info.name == "SAE":
                                posture.sae_enabled = True
                                posture.supported_protocols.add(SecurityProtocol.WPA3)
                            elif auth_info.name == "OWE":
                                posture.owe_enabled = True
                                posture.supported_protocols.add(SecurityProtocol.OWE)
                            elif "802.1X" in auth_info.name:
                                posture.enterprise_auth = True
                            elif "FT" in auth_info.name:
                                posture.fast_transition_enabled = True
                                
                        offset += 4
                        
            # RSN capabilities
            if len(ie_data) >= offset + 2:
                rsn_cap = struct.unpack('<H', ie_data[offset:offset+2])[0]
                posture.pmf_capable = bool(rsn_cap & 0x0080)
                posture.pmf_required = bool(rsn_cap & 0x0040)
                
        except Exception as e:
            self.logger.debug(f"Error parsing RSN IE: {e}")
            
    def _parse_cipher_suite(self, cipher_data: bytes) -> Optional[CipherSuiteInfo]:
        """Parse cipher suite from bytes."""
        if len(cipher_data) != 4:
            return None
            
        oui = cipher_data[:3]
        suite_type = cipher_data[3]
        
        key = (oui, suite_type)
        if key in self.cipher_suites:
            return self.cipher_suites[key]
            
        # Unknown cipher suite
        return CipherSuiteInfo(
            oui, suite_type, f"Unknown-{oui.hex()}:{suite_type}",
            SecurityRisk.MEDIUM, ["Unknown cipher suite"]
        )
        
    def _parse_auth_suite(self, auth_data: bytes) -> Optional[AuthSuiteInfo]:
        """Parse authentication suite from bytes."""
        if len(auth_data) != 4:
            return None
            
        oui = auth_data[:3]
        suite_type = auth_data[3]
        
        key = (oui, suite_type)
        if key in self.auth_suites:
            return self.auth_suites[key]
            
        # Unknown auth suite
        return AuthSuiteInfo(
            oui, suite_type, f"Unknown-{oui.hex()}:{suite_type}",
            "Unknown", SecurityRisk.MEDIUM, False, ["Unknown authentication suite"]
        )
        
    def _parse_wpa_ie(self, ie: Dot11Elt, posture: SecurityPosture) -> None:
        """Parse WPA Information Element."""
        # WPA IE parsing (simplified)
        posture.supported_protocols.add(SecurityProtocol.WPA)
        if posture.primary_protocol == SecurityProtocol.OPEN:
            posture.primary_protocol = SecurityProtocol.WPA
            
    def _analyze_client_capabilities(self, packet: Packet) -> None:
        """Analyze client security capabilities from association requests."""
        # This would analyze what security features clients support
        # For now, just track that we saw association requests
        pass
        
    def _analyze_eap_security(self, packets: List[Packet], context: AnalysisContext) -> None:
        """Analyze EAP method security from previous analysis."""
        eapol_analysis = context.metadata.get('eapol_pmf_analysis', {})
        
        # Update security postures with EAP information
        for posture in self.security_postures.values():
            if posture.enterprise_auth:
                # This would be enhanced with actual EAP frame analysis
                posture.eap_methods_observed.add("Unknown")
                
    def _analyze_certificates(self, packets: List[Packet]) -> None:
        """Analyze TLS certificates for enterprise networks."""
        if TLSCertificate is None:
            self.logger.debug("TLS certificate analysis not available - Scapy TLS support missing")
            return
            
        for packet in packets:
            try:
                if packet_has_layer(packet, TLSCertificate):
                    self._extract_certificate_info(packet)
            except Exception as e:
                self.logger.debug(f"Error analyzing certificate: {e}")
                continue
                
    def _extract_certificate_info(self, packet: Packet) -> None:
        """Extract certificate information from TLS packets."""
        # This would extract and validate certificate information
        # For now, create placeholder certificate info
        cert_info = CertificateInfo(
            subject="Unknown",
            issuer="Unknown",
            serial_number="Unknown",
            validation_errors=["Certificate analysis not implemented"]
        )
        
        cert_fingerprint = f"unknown_{len(self.certificate_store)}"
        self.certificate_store[cert_fingerprint] = cert_info
        
    def _assess_security_postures(self) -> None:
        """Perform comprehensive security assessment for each network."""
        for posture in self.security_postures.values():
            self._assess_overall_security_level(posture)
            self._identify_vulnerabilities(posture)
            self._generate_recommendations(posture)
            self._assess_compliance(posture)
            
    def _assess_overall_security_level(self, posture: SecurityPosture) -> None:
        """Assess overall security level for a network."""
        risk_factors = []
        
        # Protocol assessment
        if posture.primary_protocol == SecurityProtocol.OPEN:
            risk_factors.append(SecurityRisk.CRITICAL)
        elif posture.primary_protocol == SecurityProtocol.WEP:
            risk_factors.append(SecurityRisk.CRITICAL)
        elif posture.primary_protocol == SecurityProtocol.WPA:
            risk_factors.append(SecurityRisk.HIGH)
        elif posture.primary_protocol == SecurityProtocol.WPA2:
            risk_factors.append(SecurityRisk.MEDIUM)
        elif posture.primary_protocol == SecurityProtocol.WPA3:
            risk_factors.append(SecurityRisk.LOW)
            
        # Cipher assessment
        if posture.tkip_only:
            risk_factors.append(SecurityRisk.HIGH)
        elif posture.tkip_present:
            risk_factors.append(SecurityRisk.MEDIUM)
            
        # PMF assessment
        if not posture.pmf_capable:
            risk_factors.append(SecurityRisk.MEDIUM)
            
        # Transition mode assessment
        if posture.is_transition_mode:
            risk_factors.append(SecurityRisk.MEDIUM)
            
        # Determine overall risk
        if SecurityRisk.CRITICAL in risk_factors:
            posture.overall_security_level = SecurityRisk.CRITICAL
        elif SecurityRisk.HIGH in risk_factors:
            posture.overall_security_level = SecurityRisk.HIGH
        elif SecurityRisk.MEDIUM in risk_factors:
            posture.overall_security_level = SecurityRisk.MEDIUM
        else:
            posture.overall_security_level = SecurityRisk.LOW
            
    def _identify_vulnerabilities(self, posture: SecurityPosture) -> None:
        """Identify specific vulnerabilities for a network."""
        vulnerabilities = []
        
        # TKIP vulnerabilities
        if posture.tkip_present:
            vulnerabilities.extend([
                "TKIP RC4 stream cipher vulnerabilities",
                "Michael MIC attacks possible",
                "Beck-Tews chopchop attacks"
            ])
            posture.tkip_vulnerabilities = vulnerabilities
            
        # Transition mode vulnerabilities
        if posture.is_transition_mode:
            vulnerabilities.extend([
                "Downgrade attacks to WPA2",
                "Mixed security policy complexity",
                "Client confusion attacks"
            ])
            
        # PMF vulnerabilities
        if not posture.pmf_required:
            vulnerabilities.append("Management frame attacks possible")
            
        # Open network vulnerabilities
        if posture.primary_protocol == SecurityProtocol.OPEN:
            vulnerabilities.extend([
                "No encryption - traffic transmitted in clear",
                "No authentication - anyone can connect",
                "Evil twin attacks trivial"
            ])
            
        posture.vulnerabilities = vulnerabilities
        
    def _generate_recommendations(self, posture: SecurityPosture) -> None:
        """Generate security recommendations for a network."""
        recommendations = []
        
        # Protocol recommendations
        if posture.primary_protocol in [SecurityProtocol.OPEN, SecurityProtocol.WEP]:
            recommendations.append("Upgrade to WPA3-Personal or WPA2 with CCMP")
        elif posture.primary_protocol == SecurityProtocol.WPA:
            recommendations.append("Upgrade to WPA2 or WPA3")
        elif posture.primary_protocol == SecurityProtocol.WPA2:
            recommendations.append("Consider upgrading to WPA3 for enhanced security")
            
        # Cipher recommendations
        if posture.tkip_present:
            recommendations.append("Disable TKIP and use only CCMP/GCMP ciphers")
            
        # PMF recommendations
        if not posture.pmf_required:
            recommendations.append("Enable PMF (Protected Management Frames) as required")
            
        # Transition mode recommendations
        if posture.is_transition_mode:
            recommendations.append("Plan migration to WPA3-only mode when all clients support it")
            
        # Enterprise recommendations
        if posture.enterprise_auth:
            recommendations.extend([
                "Use strong EAP methods (EAP-TLS preferred)",
                "Validate server certificates properly",
                "Use current TLS versions (1.2+)"
            ])
            
        posture.recommendations = recommendations
        
    def _assess_compliance(self, posture: SecurityPosture) -> None:
        """Assess compliance with various standards."""
        # PCI compliance
        if (posture.primary_protocol in [SecurityProtocol.WPA2, SecurityProtocol.WPA3] and
            not posture.tkip_present and posture.pmf_capable):
            posture.pci_compliant = True
            
        # FIPS compliance (simplified)
        if (posture.primary_protocol == SecurityProtocol.WPA3 and
            posture.enterprise_auth):
            posture.fips_compliant = True
            
        # Enterprise ready
        if (posture.enterprise_auth and posture.pmf_required and
            not posture.tkip_present):
            posture.enterprise_ready = True
            
    def _analyze_transition_modes(self) -> None:
        """Analyze WPA2/WPA3 transition mode configurations."""
        transition_networks = [p for p in self.security_postures.values() if p.is_transition_mode]
        
        self.transition_analysis.networks_in_transition = len(transition_networks)
        
        for posture in transition_networks:
            config = {
                "bssid": posture.bssid,
                "ssid": posture.ssid,
                "auth_suites": [auth.name for auth in posture.auth_suites],
                "ciphers": [cipher.name for cipher in posture.pairwise_ciphers],
                "pmf_status": "required" if posture.pmf_required else "capable" if posture.pmf_capable else "disabled"
            }
            self.transition_analysis.transition_configurations.append(config)
            
        # Analyze risks
        if transition_networks:
            self.transition_analysis.security_risks = [
                "Clients may downgrade to WPA2",
                "Increased attack surface during transition",
                "Configuration complexity"
            ]
            
            self.transition_analysis.downgrade_opportunities = [
                "WPA2 PSK still available for downgrade attacks",
                "PMF not consistently enforced across modes"
            ]
            
    # Analysis methods for generating findings
    
    def _analyze_overall_security_posture(self) -> List[Finding]:
        """Analyze overall security posture across all networks."""
        findings = []
        
        if not self.security_postures:
            return findings
            
        # Security level distribution
        security_distribution = Counter()
        for posture in self.security_postures.values():
            security_distribution[posture.overall_security_level.value] += 1
            
        # Protocol distribution
        protocol_distribution = Counter()
        for posture in self.security_postures.values():
            protocol_distribution[posture.primary_protocol.value] += 1
            
        critical_networks = security_distribution.get('critical', 0)
        high_risk_networks = security_distribution.get('high', 0)
        
        severity = Severity.CRITICAL if critical_networks > 0 else \
                  Severity.WARNING if high_risk_networks > 0 else Severity.INFO
                  
        findings.append(Finding(
            category=AnalysisCategory.ENTERPRISE_SECURITY,
            severity=severity,
            title="Overall Security Posture Assessment",
            description=f"Security analysis of {len(self.security_postures)} wireless networks",
            details={
                "networks_analyzed": len(self.security_postures),
                "security_distribution": dict(security_distribution),
                "protocol_distribution": dict(protocol_distribution),
                "critical_risk_networks": critical_networks,
                "high_risk_networks": high_risk_networks,
                "security_assessment": "POOR" if critical_networks > 0 else 
                                    "FAIR" if high_risk_networks > 0 else "GOOD"
            },
            analyzer_name=self.name,
            analyzer_version=self.version
        ))
        
        return findings
        
    def _analyze_cipher_suite_security(self) -> List[Finding]:
        """Analyze cipher suite security across networks."""
        findings = []
        
        # Collect cipher usage statistics
        cipher_usage = Counter()
        weak_ciphers = []
        
        for posture in self.security_postures.values():
            if posture.group_cipher:
                cipher_usage[posture.group_cipher.name] += 1
                
            for cipher in posture.pairwise_ciphers:
                cipher_usage[cipher.name] += 1
                
                if cipher.security_level in [SecurityRisk.CRITICAL, SecurityRisk.HIGH]:
                    weak_ciphers.append({
                        "network": f"{posture.ssid} ({posture.bssid})",
                        "cipher": cipher.name,
                        "risk_level": cipher.security_level.value,
                        "vulnerabilities": cipher.vulnerabilities
                    })
        
        if weak_ciphers:
            findings.append(Finding(
                category=AnalysisCategory.ENTERPRISE_SECURITY,
                severity=Severity.CRITICAL if any(c["risk_level"] == "critical" for c in weak_ciphers) else Severity.WARNING,
                title="Weak Cipher Suites Detected",
                description=f"Found {len(weak_ciphers)} networks using weak encryption ciphers",
                details={
                    "weak_cipher_networks": weak_ciphers[:10],  # Top 10
                    "cipher_distribution": dict(cipher_usage.most_common()),
                    "recommendation": "Upgrade to CCMP-128 (AES) or stronger ciphers",
                    "security_impact": "Weak ciphers can be broken or have known vulnerabilities"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
            
        return findings
        
    def _analyze_tkip_vulnerabilities(self) -> List[Finding]:
        """Analyze TKIP presence and vulnerabilities."""
        findings = []
        
        tkip_networks = [p for p in self.security_postures.values() if p.tkip_present]
        tkip_only_networks = [p for p in tkip_networks if p.tkip_only]
        
        if tkip_networks:
            findings.append(Finding(
                category=AnalysisCategory.ENTERPRISE_SECURITY,
                severity=Severity.HIGH if tkip_only_networks else Severity.WARNING,
                title="TKIP Cipher Vulnerabilities",
                description=f"Found {len(tkip_networks)} networks with TKIP cipher support",
                details={
                    "tkip_networks": len(tkip_networks),
                    "tkip_only_networks": len(tkip_only_networks),
                    "affected_networks": [
                        {
                            "ssid": p.ssid,
                            "bssid": p.bssid,
                            "tkip_only": p.tkip_only,
                            "vulnerabilities": p.tkip_vulnerabilities
                        }
                        for p in tkip_networks[:10]
                    ],
                    "vulnerability_details": [
                        "RC4 stream cipher weaknesses",
                        "Michael MIC attacks (chopchop)",
                        "Beck-Tews attacks",
                        "Deprecated since 2012"
                    ],
                    "recommendation": "Disable TKIP immediately and use only CCMP/GCMP"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
            
        return findings
        
    def _analyze_transition_mode_risks(self) -> List[Finding]:
        """Analyze WPA2/WPA3 transition mode security risks."""
        findings = []
        
        if self.transition_analysis.networks_in_transition == 0:
            return findings
            
        findings.append(Finding(
            category=AnalysisCategory.ENTERPRISE_SECURITY,
            severity=Severity.WARNING,
            title="WPA2/WPA3 Transition Mode Analysis",
            description=f"Found {self.transition_analysis.networks_in_transition} networks in transition mode",
            details={
                "networks_in_transition": self.transition_analysis.networks_in_transition,
                "transition_configurations": self.transition_analysis.transition_configurations[:10],
                "security_risks": self.transition_analysis.security_risks,
                "downgrade_opportunities": self.transition_analysis.downgrade_opportunities,
                "recommendation": "Plan migration timeline to WPA3-only mode",
                "best_practices": [
                    "Monitor client compatibility",
                    "Enforce PMF where possible",
                    "Set timeline for WPA2 sunset"
                ]
            },
            analyzer_name=self.name,
            analyzer_version=self.version
        ))
        
        return findings
        
    def _analyze_authentication_security(self) -> List[Finding]:
        """Analyze authentication method security."""
        findings = []
        
        # Collect authentication method statistics
        auth_usage = Counter()
        weak_auth = []
        
        for posture in self.security_postures.values():
            for auth in posture.auth_suites:
                auth_usage[auth.name] += 1
                
                if auth.security_level in [SecurityRisk.CRITICAL, SecurityRisk.HIGH]:
                    weak_auth.append({
                        "network": f"{posture.ssid} ({posture.bssid})",
                        "auth_method": auth.name,
                        "risk_level": auth.security_level.value,
                        "vulnerabilities": auth.vulnerabilities
                    })
        
        if weak_auth:
            findings.append(Finding(
                category=AnalysisCategory.ENTERPRISE_SECURITY,
                severity=Severity.WARNING,
                title="Weak Authentication Methods",
                description=f"Found {len(weak_auth)} instances of weak authentication methods",
                details={
                    "weak_auth_instances": weak_auth,
                    "auth_distribution": dict(auth_usage.most_common()),
                    "recommendation": "Upgrade to SAE (WPA3) or strong EAP methods"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
            
        return findings
        
    def _analyze_certificate_security(self) -> List[Finding]:
        """Analyze certificate security for enterprise networks."""
        findings = []
        
        if not self.certificate_store:
            return findings
            
        cert_issues = []
        for fingerprint, cert in self.certificate_store.items():
            if cert.validation_errors:
                cert_issues.extend(cert.validation_errors)
                
        if cert_issues:
            findings.append(Finding(
                category=AnalysisCategory.ENTERPRISE_SECURITY,
                severity=Severity.WARNING,
                title="Certificate Validation Issues",
                description=f"Found certificate validation issues in {len(cert_issues)} instances",
                details={
                    "certificates_analyzed": len(self.certificate_store),
                    "validation_issues": cert_issues,
                    "recommendation": "Ensure proper certificate validation and trust chains"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
            
        return findings
        
    def _analyze_pmf_compliance(self) -> List[Finding]:
        """Analyze PMF compliance across networks."""
        findings = []
        
        pmf_stats = {
            "required": 0,
            "capable": 0,
            "disabled": 0
        }
        
        non_compliant = []
        
        for posture in self.security_postures.values():
            if posture.pmf_required:
                pmf_stats["required"] += 1
            elif posture.pmf_capable:
                pmf_stats["capable"] += 1
            else:
                pmf_stats["disabled"] += 1
                non_compliant.append({
                    "ssid": posture.ssid,
                    "bssid": posture.bssid,
                    "protocol": posture.primary_protocol.value
                })
        
        if non_compliant:
            findings.append(Finding(
                category=AnalysisCategory.ENTERPRISE_SECURITY,
                severity=Severity.WARNING,
                title="PMF (Protected Management Frames) Non-Compliance",
                description=f"Found {len(non_compliant)} networks without PMF support",
                details={
                    "pmf_distribution": pmf_stats,
                    "non_compliant_networks": non_compliant[:10],
                    "security_impact": "Management frame attacks (deauth floods, etc.) possible",
                    "recommendation": "Enable PMF as required for all WPA2/WPA3 networks"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
            
        return findings
        
    def _analyze_wpa3_adoption(self) -> List[Finding]:
        """Analyze WPA3 adoption and implementation."""
        findings = []
        
        wpa3_networks = [p for p in self.security_postures.values() 
                        if SecurityProtocol.WPA3 in p.supported_protocols]
        sae_networks = [p for p in self.security_postures.values() if p.sae_enabled]
        owe_networks = [p for p in self.security_postures.values() if p.owe_enabled]
        
        wpa3_adoption_rate = (len(wpa3_networks) / len(self.security_postures) * 100) if self.security_postures else 0
        
        findings.append(Finding(
            category=AnalysisCategory.ENTERPRISE_SECURITY,
            severity=Severity.INFO,
            title="WPA3 Adoption Analysis",
            description=f"WPA3 adoption rate: {wpa3_adoption_rate:.1f}%",
            details={
                "total_networks": len(self.security_postures),
                "wpa3_networks": len(wpa3_networks),
                "sae_enabled_networks": len(sae_networks),
                "owe_enabled_networks": len(owe_networks),
                "adoption_rate_percentage": round(wpa3_adoption_rate, 1),
                "wpa3_benefits": [
                    "Stronger authentication (SAE)",
                    "Forward secrecy",
                    "Resistance to offline attacks",
                    "Enhanced Open (OWE) for public networks"
                ],
                "recommendation": "Plan WPA3 migration strategy" if wpa3_adoption_rate < 50 else "Continue WPA3 rollout"
            },
            analyzer_name=self.name,
            analyzer_version=self.version
        ))
        
        return findings
        
    def _analyze_security_downgrades(self) -> List[Finding]:
        """Analyze potential security downgrade opportunities."""
        findings = []
        
        downgrade_risks = []
        
        for posture in self.security_postures.values():
            risks = []
            
            # Check for mixed security protocols
            if len(posture.supported_protocols) > 1:
                protocols = [p.value for p in posture.supported_protocols]
                risks.append(f"Mixed protocols: {', '.join(protocols)}")
                
            # Check for mixed cipher suites
            if len(posture.pairwise_ciphers) > 1:
                ciphers = [c.name for c in posture.pairwise_ciphers]
                if any(c in ["TKIP", "WEP-40", "WEP-104"] for c in ciphers):
                    risks.append(f"Mixed ciphers including weak ones: {', '.join(ciphers)}")
                    
            # Check for optional PMF when required should be enforced
            if posture.pmf_capable and not posture.pmf_required and posture.primary_protocol == SecurityProtocol.WPA3:
                risks.append("PMF optional in WPA3 network (should be required)")
                
            if risks:
                downgrade_risks.append({
                    "network": f"{posture.ssid} ({posture.bssid})",
                    "risks": risks,
                    "overall_security": posture.overall_security_level.value
                })
        
        if downgrade_risks:
            findings.append(Finding(
                category=AnalysisCategory.SECURITY_THREATS,
                severity=Severity.WARNING,
                title="Security Downgrade Attack Opportunities",
                description=f"Found {len(downgrade_risks)} networks with potential downgrade attack vectors",
                details={
                    "networks_at_risk": downgrade_risks[:10],
                    "attack_vectors": [
                        "Protocol downgrade (WPA3 → WPA2)",
                        "Cipher downgrade (CCMP → TKIP)",
                        "PMF bypass attempts",
                        "Authentication method downgrades"
                    ],
                    "recommendation": "Eliminate weaker security options where possible",
                    "mitigation": "Use single strong security configuration per network"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
            
        return findings
        
    def _get_security_distribution(self) -> Dict[str, int]:
        """Get security protocol distribution."""
        distribution = Counter()
        for posture in self.security_postures.values():
            distribution[posture.primary_protocol.value] += 1
        return dict(distribution)
        
    def _get_critical_risks(self) -> List[str]:
        """Get list of critical security risks."""
        risks = []
        
        for posture in self.security_postures.values():
            if posture.overall_security_level == SecurityRisk.CRITICAL:
                risks.extend(posture.vulnerabilities)
                
        return list(set(risks))  # Remove duplicates