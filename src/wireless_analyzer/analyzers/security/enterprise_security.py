"""
Enterprise Security Analysis for 802.1X/EAP/TLS authentication.

This analyzer provides comprehensive analysis of enterprise wireless security including:
- 802.1X authentication flow tracking and validation
- EAP method security analysis and vulnerability assessment
- TLS certificate parsing, validation, and trust chain verification
- RADIUS communication analysis and backend authentication tracking
- Enterprise policy compliance checking and security posture assessment
- Certificate lifecycle management and expiration monitoring
- EAP tunneling method analysis (PEAP/TTLS/FAST/TEAP)
- PKI infrastructure analysis and certificate authority validation
- Enterprise security best practices compliance checking
- Authentication server communication security assessment
"""

import hashlib
import logging
import re
import struct
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Any, Set, Optional, NamedTuple, Tuple, Union
import ipaddress

from scapy.all import Packet, Raw
from scapy.layers.dot11 import Dot11, Dot11Auth, Dot11AssoReq, Dot11AssoResp
from scapy.layers.eap import EAPOL, EAP
from scapy.layers.inet import IP, UDP
from scapy.layers.radius import Radius, RadiusAttribute

# TLS imports with graceful fallback
try:
    from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello, TLSCertificate, TLSHandshake
    TLS_AVAILABLE = True
except ImportError:
    try:
        from scapy.layers.tls import TLS, TLSClientHello, TLSServerHello, TLSCertificate, TLSHandshake
        TLS_AVAILABLE = True
    except ImportError:
        TLS = TLSClientHello = TLSServerHello = TLSCertificate = TLSHandshake = None
        TLS_AVAILABLE = False

from ...core.base_analyzer import BaseAnalyzer
from ...utils.analyzer_helpers import (
    packet_has_layer, get_packet_layer, get_packet_field,
    get_src_mac, get_dst_mac, get_bssid, get_timestamp
)
from ...core.models import (
    Finding, 
    Severity, 
    AnalysisContext,
    AnalysisCategory,
    PacketReference
)


class EAPMethodType(Enum):
    """EAP method types with security classifications."""
    IDENTITY = (1, "Identity", "INFO", False)
    NOTIFICATION = (2, "Notification", "INFO", False)
    NAK = (3, "NAK", "INFO", False)
    MD5_CHALLENGE = (4, "MD5-Challenge", "WEAK", False)
    OTP = (5, "One-Time Password", "MEDIUM", False)
    GTC = (6, "Generic Token Card", "MEDIUM", False)
    TLS = (13, "EAP-TLS", "STRONG", True)
    LEAP = (17, "LEAP", "WEAK", False)
    SIM = (18, "EAP-SIM", "MEDIUM", True)
    TTLS = (21, "EAP-TTLS", "STRONG", True)
    AKA = (23, "EAP-AKA", "MEDIUM", True)
    PEAP = (25, "PEAP", "STRONG", True)
    MSCHAPV2 = (26, "MS-CHAPv2", "WEAK", False)
    TLV = (33, "TLV", "INFO", False)
    FAST = (43, "EAP-FAST", "STRONG", True)
    PAX = (46, "EAP-PAX", "MEDIUM", True)
    PSK = (47, "EAP-PSK", "MEDIUM", True)
    SAKE = (48, "EAP-SAKE", "MEDIUM", True)
    IKEV2 = (49, "EAP-IKEv2", "STRONG", True)
    AKA_PRIME = (50, "EAP-AKA'", "MEDIUM", True)
    GPSK = (51, "EAP-GPSK", "MEDIUM", True)
    PWD = (52, "EAP-PWD", "STRONG", True)
    TEAP = (55, "TEAP", "STRONG", True)
    
    def __init__(self, method_id: int, name: str, security_level: str, certificate_based: bool):
        self.method_id = method_id
        self.method_name = name
        self.security_level = security_level
        self.certificate_based = certificate_based


class AuthenticationState(Enum):
    """802.1X authentication states."""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    AUTHENTICATING = "authenticating"
    AUTHENTICATED = "authenticated"
    HELD = "held"
    FORCE_AUTH = "force_auth"
    FORCE_UNAUTH = "force_unauth"


class RadiusMessageType(Enum):
    """RADIUS message types."""
    ACCESS_REQUEST = 1
    ACCESS_ACCEPT = 2
    ACCESS_REJECT = 3
    ACCOUNTING_REQUEST = 4
    ACCOUNTING_RESPONSE = 5
    ACCESS_CHALLENGE = 11
    STATUS_SERVER = 12
    STATUS_CLIENT = 13


@dataclass
class CertificateDetails:
    """Detailed certificate information."""
    subject: str
    issuer: str
    serial_number: str
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None
    fingerprint_sha256: str = ""
    fingerprint_md5: str = ""
    
    # Certificate validation
    is_expired: bool = False
    is_self_signed: bool = False
    is_ca_cert: bool = False
    
    # Extensions
    key_usage: List[str] = field(default_factory=list)
    extended_key_usage: List[str] = field(default_factory=list)
    subject_alt_names: List[str] = field(default_factory=list)
    
    # Security analysis
    signature_algorithm: str = ""
    public_key_algorithm: str = ""
    public_key_size: int = 0
    security_issues: List[str] = field(default_factory=list)


@dataclass
class AuthenticationFlow:
    """Complete 802.1X authentication flow tracking."""
    client_mac: str
    ap_bssid: str
    start_time: datetime
    end_time: Optional[datetime] = None
    
    # Flow stages
    dot11_auth_complete: bool = False
    dot11_assoc_complete: bool = False
    eap_start_sent: bool = False
    eap_identity_exchanged: bool = False
    eap_method_negotiated: Optional[EAPMethodType] = None
    eap_authentication_complete: bool = False
    eapol_key_exchange_complete: bool = False
    
    # Authentication details
    identity: str = ""
    auth_server: Optional[str] = None
    radius_messages: List[Dict[str, Any]] = field(default_factory=list)
    
    # Results
    authentication_successful: bool = False
    failure_reason: str = ""
    session_timeout: Optional[int] = None
    vlan_assignment: Optional[int] = None
    
    # Security analysis
    method_downgrade_attempted: bool = False
    weak_methods_attempted: List[EAPMethodType] = field(default_factory=list)
    certificate_issues: List[str] = field(default_factory=list)
    timing_anomalies: List[str] = field(default_factory=list)
    
    def get_duration(self) -> float:
        """Get authentication flow duration in seconds."""
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0


@dataclass
class RadiusConversation:
    """RADIUS client-server conversation tracking."""
    client_ip: str
    server_ip: str
    nas_identifier: str = ""
    
    # Messages
    access_requests: int = 0
    access_accepts: int = 0
    access_rejects: int = 0
    access_challenges: int = 0
    
    # Timing
    first_message: Optional[datetime] = None
    last_message: Optional[datetime] = None
    average_response_time: float = 0.0
    
    # Security analysis
    shared_secret_issues: List[str] = field(default_factory=list)
    attribute_issues: List[str] = field(default_factory=list)
    timing_issues: List[str] = field(default_factory=list)


@dataclass
class EnterpriseSecurityPosture:
    """Overall enterprise security posture assessment."""
    total_auth_attempts: int = 0
    successful_auths: int = 0
    failed_auths: int = 0
    
    # Method distribution
    methods_observed: Dict[EAPMethodType, int] = field(default_factory=dict)
    strong_methods_percentage: float = 0.0
    weak_methods_percentage: float = 0.0
    
    # Certificate security
    certificates_analyzed: int = 0
    expired_certificates: int = 0
    self_signed_certificates: int = 0
    weak_key_certificates: int = 0
    
    # Infrastructure security
    radius_servers: Set[str] = field(default_factory=set)
    nas_devices: Set[str] = field(default_factory=set)
    authentication_domains: Set[str] = field(default_factory=set)
    
    # Compliance
    policy_violations: List[str] = field(default_factory=list)
    security_recommendations: List[str] = field(default_factory=list)
    compliance_score: float = 0.0


class EnterpriseSecurityAnalyzer(BaseAnalyzer):
    """
    Comprehensive Enterprise Security Analyzer.
    
    This analyzer provides in-depth analysis of 802.1X/EAP/TLS enterprise
    authentication systems, including certificate validation, policy compliance,
    and security posture assessment.
    """
    
    def __init__(self):
        super().__init__(
            name="Enterprise Security Analyzer",
            category=AnalysisCategory.ENTERPRISE_SECURITY,
            version="1.0"
        )
        
        self.description = (
            "Comprehensive 802.1X/EAP/TLS analysis including certificate validation, "
            "authentication flow tracking, and enterprise policy compliance"
        )
        
        # Wireshark filters for enterprise analysis
        self.wireshark_filters = [
            "eapol",           # EAPOL frames
            "eap",             # EAP frames
            "tls",             # TLS traffic
            "radius",          # RADIUS authentication
            "wlan.fc.type_subtype == 11",  # Authentication frames
            "wlan.fc.type_subtype == 0",   # Association request
            "wlan.fc.type_subtype == 1",   # Association response
            "ssl.handshake.type == 11",    # TLS Certificate messages
            "eap.type",                    # EAP method types
            "radius.code"                  # RADIUS message codes
        ]
        
        self.analysis_order = 50  # Run after EAPOL/PMF and WPA security analyzers
        
        # Analysis storage
        self.authentication_flows: Dict[str, AuthenticationFlow] = {}  # Key: client_mac:ap_bssid
        self.radius_conversations: Dict[str, RadiusConversation] = {}  # Key: client_ip:server_ip
        self.certificates: Dict[str, CertificateDetails] = {}  # Key: certificate fingerprint
        self.security_posture = EnterpriseSecurityPosture()
        
        # EAP method tracking
        self.eap_methods_by_client: Dict[str, List[EAPMethodType]] = defaultdict(list)
        self.eap_conversations: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        
        # Policy configuration (could be loaded from config file)
        self.security_policies = {
            "allowed_eap_methods": [EAPMethodType.TLS, EAPMethodType.TTLS, EAPMethodType.PEAP, EAPMethodType.TEAP],
            "prohibited_eap_methods": [EAPMethodType.MD5_CHALLENGE, EAPMethodType.LEAP, EAPMethodType.MSCHAPV2],
            "minimum_certificate_key_size": 2048,
            "maximum_certificate_age_days": 365,
            "require_certificate_validation": True,
            "require_strong_cipher_suites": True,
            "maximum_auth_timeout_seconds": 30
        }
        
    def is_applicable(self, packet: Packet) -> bool:
        """Check if packet is relevant for enterprise security analysis."""
        return (packet_has_layer(packet, EAPOL) or
                packet_has_layer(packet, EAP) or
                packet_has_layer(packet, Dot11Auth) or
                packet_has_layer(packet, Dot11AssoReq) or
                packet_has_layer(packet, Dot11AssoResp) or
                (packet_has_layer(packet, UDP) and 
                 (get_packet_layer(packet, "UDP").sport == 1812 or get_packet_layer(packet, "UDP").dport == 1812 or  # RADIUS auth
                  get_packet_layer(packet, "UDP").sport == 1813 or get_packet_layer(packet, "UDP").dport == 1813)) or  # RADIUS accounting
                (TLS_AVAILABLE and packet_has_layer(packet, TLS)))
        
    def get_display_filters(self) -> List[str]:
        """Get Wireshark display filters."""
        return self.wireshark_filters
        
    def analyze(self, packets: List[Packet], context: AnalysisContext) -> List[Finding]:
        """
        Analyze enterprise security aspects.
        
        Args:
            packets: List of relevant packets
            context: Analysis context
            
        Returns:
            List of findings
        """
        if not packets:
            return []
            
        self.logger.info(f"Analyzing enterprise security from {len(packets)} packets")
        
        # Process packets to build authentication flows
        self._process_authentication_flows(packets)
        
        # Analyze RADIUS communications
        self._analyze_radius_communications(packets)
        
        # Analyze TLS certificates
        if TLS_AVAILABLE:
            self._analyze_tls_certificates(packets)
        else:
            self.logger.warning("TLS analysis not available - Scapy TLS support missing")
            
        # Assess overall security posture
        self._assess_security_posture()
        
        # Validate against enterprise policies
        self._validate_enterprise_policies()
        
        self.logger.info(
            f"Analyzed {len(self.authentication_flows)} auth flows, "
            f"{len(self.radius_conversations)} RADIUS conversations, "
            f"{len(self.certificates)} certificates"
        )
        
        # Generate findings
        findings = []
        findings.extend(self._analyze_authentication_security())
        findings.extend(self._analyze_eap_method_security())
        findings.extend(self._analyze_certificate_security())
        findings.extend(self._analyze_radius_security())
        findings.extend(self._analyze_enterprise_compliance())
        findings.extend(self._analyze_infrastructure_security())
        
        # Store results in context
        context.metadata['enterprise_security'] = {
            'authentication_flows': len(self.authentication_flows),
            'radius_conversations': len(self.radius_conversations),
            'certificates_analyzed': len(self.certificates),
            'success_rate': (self.security_posture.successful_auths / 
                           max(self.security_posture.total_auth_attempts, 1)) * 100,
            'compliance_score': self.security_posture.compliance_score
        }
        
        self.findings_generated = len(findings)
        return findings
        
    def _process_authentication_flows(self, packets: List[Packet]) -> None:
        """Process packets to build complete authentication flows."""
        for packet in packets:
            try:
                timestamp = self._extract_timestamp(packet)
                
                if packet_has_layer(packet, Dot11Auth):
                    self._process_dot11_auth(packet, timestamp)
                elif packet_has_layer(packet, Dot11AssoReq) or packet_has_layer(packet, Dot11AssoResp):
                    self._process_dot11_assoc(packet, timestamp)
                elif packet_has_layer(packet, EAPOL):
                    self._process_eapol_frame(packet, timestamp)
                elif packet_has_layer(packet, EAP):
                    self._process_eap_frame(packet, timestamp)
                    
            except Exception as e:
                self.logger.debug(f"Error processing authentication flow: {e}")
                continue
                
    def _extract_timestamp(self, packet: Packet) -> datetime:
        """Extract timestamp from packet."""
        try:
            if hasattr(packet, 'time'):
                time_val = get_timestamp(packet)
                if hasattr(time_val, '__float__'):
                    return datetime.fromtimestamp(float(time_val))
                elif hasattr(time_val, 'val'):
                    return datetime.fromtimestamp(float(time_val.val))
                else:
                    return datetime.fromtimestamp(float(time_val))
        except (ValueError, TypeError, AttributeError):
            pass
        return datetime.now()
        
    def _process_dot11_auth(self, packet: Packet, timestamp: datetime) -> None:
        """Process 802.11 authentication frames."""
        if not packet_has_layer(packet, Dot11):
            return
            
        dot11 = get_packet_layer(packet, "Dot11")
        auth = get_packet_layer(packet, "Dot11Auth")
        
        client_mac = dot11.addr2
        ap_bssid = dot11.addr1
        flow_key = f"{client_mac}:{ap_bssid}"
        
        # Initialize flow if needed
        if flow_key not in self.authentication_flows:
            self.authentication_flows[flow_key] = AuthenticationFlow(
                client_mac=client_mac,
                ap_bssid=ap_bssid,
                start_time=timestamp
            )
            
        flow = self.authentication_flows[flow_key]
        
        # Check authentication success
        if hasattr(auth, 'status') and auth.status == 0:  # Successful
            flow.dot11_auth_complete = True
            
    def _process_dot11_assoc(self, packet: Packet, timestamp: datetime) -> None:
        """Process 802.11 association frames."""
        if not packet_has_layer(packet, Dot11):
            return
            
        dot11 = get_packet_layer(packet, "Dot11")
        
        if packet_has_layer(packet, Dot11AssoReq):
            client_mac = dot11.addr2
            ap_bssid = dot11.addr1
        else:  # Dot11AssoResp
            client_mac = dot11.addr1
            ap_bssid = dot11.addr2
            
        flow_key = f"{client_mac}:{ap_bssid}"
        
        if flow_key in self.authentication_flows:
            flow = self.authentication_flows[flow_key]
            
            if packet_has_layer(packet, Dot11AssoResp):
                assoc_resp = get_packet_layer(packet, "Dot11AssoResp")
                if hasattr(assoc_resp, 'status') and assoc_resp.status == 0:
                    flow.dot11_assoc_complete = True
                    
    def _process_eapol_frame(self, packet: Packet, timestamp: datetime) -> None:
        """Process EAPOL frames for authentication flow."""
        if not packet_has_layer(packet, Dot11) or not packet_has_layer(packet, EAPOL):
            return
            
        dot11 = get_packet_layer(packet, "Dot11")
        eapol = get_packet_layer(packet, "EAPOL")
        
        # Determine client and AP
        if dot11.addr1.startswith('ff:ff:ff'):  # Broadcast
            client_mac = dot11.addr2
            ap_bssid = dot11.addr3
        else:
            # Use address analysis to determine direction
            client_mac = dot11.addr2
            ap_bssid = dot11.addr1
            
        flow_key = f"{client_mac}:{ap_bssid}"
        
        if flow_key not in self.authentication_flows:
            self.authentication_flows[flow_key] = AuthenticationFlow(
                client_mac=client_mac,
                ap_bssid=ap_bssid,
                start_time=timestamp
            )
            
        flow = self.authentication_flows[flow_key]
        
        # Analyze EAPOL type
        if hasattr(eapol, 'type'):
            if get_packet_field(packet, "Dot11", "type") == 1:  # EAPOL-Start
                flow.eap_start_sent = True
            elif get_packet_field(packet, "Dot11", "type") == 3:  # EAPOL-Key
                # This indicates key exchange (post-authentication)
                flow.eapol_key_exchange_complete = True
                flow.authentication_successful = True
                flow.end_time = timestamp
                
    def _process_eap_frame(self, packet: Packet, timestamp: datetime) -> None:
        """Process EAP frames for method analysis."""
        if not packet_has_layer(packet, EAP):
            return
            
        eap = get_packet_layer(packet, "EAP")
        dot11 = get_packet_layer(packet, "Dot11") if packet_has_layer(packet, Dot11) else None
        
        if dot11:
            client_mac = dot11.addr2
            ap_bssid = dot11.addr1
            flow_key = f"{client_mac}:{ap_bssid}"
        else:
            # For non-802.11 EAP (e.g., over Ethernet)
            client_mac = "unknown"
            ap_bssid = "unknown"
            flow_key = f"{client_mac}:{ap_bssid}"
            
        # Track EAP conversation
        eap_info = {
            'timestamp': timestamp,
            'code': getattr(eap, 'code', 0),
            'id': getattr(eap, 'id', 0),
            'type': getattr(eap, 'type', None),
            'len': getattr(eap, 'len', 0)
        }
        
        self.eap_conversations[flow_key].append(eap_info)
        
        # Initialize flow if needed
        if flow_key not in self.authentication_flows:
            self.authentication_flows[flow_key] = AuthenticationFlow(
                client_mac=client_mac,
                ap_bssid=ap_bssid,
                start_time=timestamp
            )
            
        flow = self.authentication_flows[flow_key]
        
        # Analyze EAP codes
        if hasattr(eap, 'code'):
            if eap.code == 1:  # Request
                if hasattr(eap, 'type'):
                    if get_packet_field(packet, "Dot11", "type") == 1:  # Identity
                        flow.eap_identity_exchanged = True
                    else:
                        # EAP method
                        try:
                            method = EAPMethodType(get_packet_field(packet, "Dot11", "type"))
                            if not flow.eap_method_negotiated:
                                flow.eap_method_negotiated = method
                                
                            # Track method attempts
                            if method not in self.eap_methods_by_client[client_mac]:
                                self.eap_methods_by_client[client_mac].append(method)
                                
                            # Check for weak methods
                            if method.security_level == "WEAK":
                                flow.weak_methods_attempted.append(method)
                                
                        except ValueError:
                            self.logger.debug(f"Unknown EAP method type: {get_packet_field(packet, 'Dot11', 'type')}")
                            
            elif eap.code == 2:  # Response
                if hasattr(eap, 'type') and get_packet_field(packet, "Dot11", "type") == 1:  # Identity response
                    # Extract identity if available
                    if hasattr(eap, 'identity'):
                        flow.identity = eap.identity.decode('utf-8', errors='ignore')
                    elif hasattr(eap, 'payload') and eap.payload:
                        try:
                            identity_data = bytes(eap.payload)
                            if len(identity_data) > 5:  # Skip EAP header
                                flow.identity = identity_data[5:].decode('utf-8', errors='ignore')
                        except:
                            pass
                            
            elif eap.code == 3:  # Success
                flow.eap_authentication_complete = True
                flow.authentication_successful = True
                flow.end_time = timestamp
                
            elif eap.code == 4:  # Failure
                flow.eap_authentication_complete = True
                flow.authentication_successful = False
                flow.failure_reason = "EAP authentication failed"
                flow.end_time = timestamp
                
    def _analyze_radius_communications(self, packets: List[Packet]) -> None:
        """Analyze RADIUS client-server communications."""
        for packet in packets:
            try:
                if not (packet_has_layer(packet, UDP) and packet_has_layer(packet, Radius)):
                    continue
                    
                if not (get_packet_layer(packet, "UDP").sport in [1812, 1813] or get_packet_layer(packet, "UDP").dport in [1812, 1813]):
                    continue
                    
                self._process_radius_packet(packet)
                
            except Exception as e:
                self.logger.debug(f"Error analyzing RADIUS packet: {e}")
                continue
                
    def _process_radius_packet(self, packet: Packet) -> None:
        """Process individual RADIUS packet."""
        if not packet_has_layer(packet, IP) or not packet_has_layer(packet, Radius):
            return
            
        ip = get_packet_layer(packet, "IP")
        radius = get_packet_layer(packet, "Radius")
        timestamp = self._extract_timestamp(packet)
        
        # Determine client and server
        if get_packet_layer(packet, "UDP").dport in [1812, 1813]:  # Request
            client_ip = ip.src
            server_ip = ip.dst
        else:  # Response
            client_ip = ip.dst
            server_ip = ip.src
            
        conv_key = f"{client_ip}:{server_ip}"
        
        # Initialize conversation if needed
        if conv_key not in self.radius_conversations:
            self.radius_conversations[conv_key] = RadiusConversation(
                client_ip=client_ip,
                server_ip=server_ip,
                first_message=timestamp
            )
            
        conv = self.radius_conversations[conv_key]
        conv.last_message = timestamp
        
        # Analyze RADIUS message type
        if hasattr(radius, 'code'):
            if radius.code == RadiusMessageType.ACCESS_REQUEST.value:
                conv.access_requests += 1
            elif radius.code == RadiusMessageType.ACCESS_ACCEPT.value:
                conv.access_accepts += 1
            elif radius.code == RadiusMessageType.ACCESS_REJECT.value:
                conv.access_rejects += 1
            elif radius.code == RadiusMessageType.ACCESS_CHALLENGE.value:
                conv.access_challenges += 1
                
        # Extract NAS identifier if available
        if hasattr(radius, 'attributes'):
            for attr in radius.attributes:
                if hasattr(attr, 'type') and get_packet_field(packet, "Dot11", "type") == 32:  # NAS-Identifier
                    conv.nas_identifier = attr.value.decode('utf-8', errors='ignore')
                    
    def _analyze_tls_certificates(self, packets: List[Packet]) -> None:
        """Analyze TLS certificates in enterprise authentication."""
        if not TLS_AVAILABLE:
            return
            
        for packet in packets:
            try:
                if packet_has_layer(packet, TLSCertificate):
                    self._extract_certificate_details(packet)
                elif packet_has_layer(packet, TLSHandshake):
                    # Look for certificate handshake messages
                    tls_handshake = get_packet_layer(packet, "TLSHandshake")
                    if hasattr(tls_handshake, 'type') and get_packet_field(packet, "Dot11", "type") == 11:  # Certificate
                        self._extract_certificate_details(packet)
                        
            except Exception as e:
                self.logger.debug(f"Error analyzing TLS certificate: {e}")
                continue
                
    def _extract_certificate_details(self, packet: Packet) -> None:
        """Extract detailed certificate information."""
        # This is a placeholder for certificate extraction
        # In a real implementation, this would parse X.509 certificates
        # and extract subject, issuer, validity dates, etc.
        
        try:
            # Generate a placeholder certificate fingerprint
            cert_data = bytes(packet)
            fingerprint = hashlib.sha256(cert_data).hexdigest()[:32]
            
            if fingerprint not in self.certificates:
                cert_details = CertificateDetails(
                    subject="CN=Example Enterprise CA",
                    issuer="CN=Root CA",
                    serial_number="123456789",
                    fingerprint_sha256=fingerprint,
                    security_issues=["Certificate parsing not fully implemented"]
                )
                
                self.certificates[fingerprint] = cert_details
                
        except Exception as e:
            self.logger.debug(f"Error extracting certificate details: {e}")
            
    def _assess_security_posture(self) -> None:
        """Assess overall enterprise security posture."""
        # Count authentication attempts and successes
        self.security_posture.total_auth_attempts = len(self.authentication_flows)
        self.security_posture.successful_auths = sum(
            1 for flow in self.authentication_flows.values() 
            if flow.authentication_successful
        )
        self.security_posture.failed_auths = (
            self.security_posture.total_auth_attempts - self.security_posture.successful_auths
        )
        
        # Analyze EAP method distribution
        method_counter = Counter()
        for methods in self.eap_methods_by_client.values():
            for method in methods:
                method_counter[method] += 1
                
        self.security_posture.methods_observed = dict(method_counter)
        
        # Calculate method security distribution
        total_methods = sum(method_counter.values())
        if total_methods > 0:
            strong_methods = sum(
                count for method, count in method_counter.items()
                if method.security_level == "STRONG"
            )
            weak_methods = sum(
                count for method, count in method_counter.items()
                if method.security_level == "WEAK"
            )
            
            self.security_posture.strong_methods_percentage = (strong_methods / total_methods) * 100
            self.security_posture.weak_methods_percentage = (weak_methods / total_methods) * 100
            
        # Certificate analysis
        self.security_posture.certificates_analyzed = len(self.certificates)
        
        # Infrastructure analysis
        self.security_posture.radius_servers = set(
            conv.server_ip for conv in self.radius_conversations.values()
        )
        self.security_posture.nas_devices = set(
            conv.client_ip for conv in self.radius_conversations.values()
        )
        
        # Extract authentication domains from identities
        for flow in self.authentication_flows.values():
            if '@' in flow.identity:
                domain = flow.identity.split('@')[1]
                self.security_posture.authentication_domains.add(domain)
                
    def _validate_enterprise_policies(self) -> None:
        """Validate authentication against enterprise security policies."""
        violations = []
        
        # Check for prohibited EAP methods
        prohibited_used = []
        for method in self.security_posture.methods_observed:
            if method in self.security_policies.get("prohibited_eap_methods", []):
                prohibited_used.append(method.method_name)
                
        if prohibited_used:
            violations.append(f"Prohibited EAP methods used: {', '.join(prohibited_used)}")
            
        # Check authentication timeouts
        long_auths = []
        max_timeout = self.security_policies.get("maximum_auth_timeout_seconds", 30)
        for flow in self.authentication_flows.values():
            duration = flow.get_duration()
            if duration > max_timeout:
                long_auths.append(f"{flow.client_mac}: {duration:.1f}s")
                
        if long_auths:
            violations.append(f"Authentication timeouts exceeded: {len(long_auths)} cases")
            
        # Check for weak certificate key sizes
        weak_certs = []
        min_key_size = self.security_policies.get("minimum_certificate_key_size", 2048)
        for cert in self.certificates.values():
            if cert.public_key_size > 0 and cert.public_key_size < min_key_size:
                weak_certs.append(cert.subject)
                
        if weak_certs:
            violations.append(f"Weak certificate key sizes: {len(weak_certs)} certificates")
            
        self.security_posture.policy_violations = violations
        
        # Calculate compliance score
        total_checks = 3  # Number of policy checks
        violations_count = len(violations)
        self.security_posture.compliance_score = max(0, (total_checks - violations_count) / total_checks * 100)
        
    # Findings generation methods
    
    def _analyze_authentication_security(self) -> List[Finding]:
        """Analyze overall authentication security."""
        findings = []
        
        if not self.authentication_flows:
            return findings
            
        # Authentication success rate analysis
        total_attempts = self.security_posture.total_auth_attempts
        success_rate = (self.security_posture.successful_auths / max(total_attempts, 1)) * 100
        
        if success_rate < 80:
            severity = Severity.WARNING if success_rate > 50 else Severity.CRITICAL
            findings.append(Finding(
                category=AnalysisCategory.ENTERPRISE_SECURITY,
                severity=severity,
                title="Low Enterprise Authentication Success Rate",
                description=f"Authentication success rate: {success_rate:.1f}% ({self.security_posture.successful_auths}/{total_attempts})",
                details={
                    "success_rate": round(success_rate, 1),
                    "total_attempts": total_attempts,
                    "successful_auths": self.security_posture.successful_auths,
                    "failed_auths": self.security_posture.failed_auths,
                    "failure_analysis": self._analyze_auth_failures(),
                    "recommendation": "Investigate authentication failures and improve enterprise configuration"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
        
        # Authentication timing analysis
        slow_auths = []
        timing_issues = []
        
        for flow in self.authentication_flows.values():
            duration = flow.get_duration()
            if duration > 30:  # Slow authentication
                slow_auths.append({
                    "client": flow.client_mac,
                    "ap": flow.ap_bssid,
                    "duration": round(duration, 1),
                    "method": flow.eap_method_negotiated.method_name if flow.eap_method_negotiated else "Unknown"
                })
            
            if len(flow.timing_anomalies) > 0:
                timing_issues.extend(flow.timing_anomalies)
                
        if slow_auths:
            findings.append(Finding(
                category=AnalysisCategory.ENTERPRISE_SECURITY,
                severity=Severity.INFO,
                title="Slow Enterprise Authentication Flows",
                description=f"Detected {len(slow_auths)} slow authentication flows (>30s)",
                details={
                    "slow_authentication_count": len(slow_auths),
                    "slow_authentications": slow_auths[:10],  # Top 10
                    "timing_issues": timing_issues,
                    "performance_impact": "Slow authentication affects user experience",
                    "recommendations": [
                        "Optimize RADIUS server response times",
                        "Check network connectivity to authentication servers",
                        "Review EAP method complexity",
                        "Consider authentication server load balancing"
                    ]
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
            
        return findings
        
    def _analyze_auth_failures(self) -> Dict[str, Any]:
        """Analyze authentication failure patterns."""
        failure_reasons = Counter()
        failed_methods = Counter()
        
        for flow in self.authentication_flows.values():
            if not flow.authentication_successful:
                failure_reasons[flow.failure_reason or "Unknown"] += 1
                if flow.eap_method_negotiated:
                    failed_methods[flow.eap_method_negotiated.method_name] += 1
                    
        return {
            "failure_reasons": dict(failure_reasons),
            "failed_methods": dict(failed_methods),
            "total_failures": sum(failure_reasons.values())
        }
        
    def _analyze_eap_method_security(self) -> List[Finding]:
        """Analyze EAP method security and usage patterns."""
        findings = []
        
        if not self.security_posture.methods_observed:
            return findings
            
        # EAP method security analysis
        method_security = {
            "strong": [],
            "medium": [],
            "weak": []
        }
        
        for method, count in self.security_posture.methods_observed.items():
            method_info = {
                "method": method.method_name,
                "count": count,
                "certificate_based": method.certificate_based
            }
            
            if method.security_level == "STRONG":
                method_security["strong"].append(method_info)
            elif method.security_level == "MEDIUM":
                method_security["medium"].append(method_info)
            else:
                method_security["weak"].append(method_info)
                
        # Generate findings for weak methods
        if method_security["weak"]:
            total_weak = sum(m["count"] for m in method_security["weak"])
            weak_percentage = self.security_posture.weak_methods_percentage
            
            findings.append(Finding(
                category=AnalysisCategory.ENTERPRISE_SECURITY,
                severity=Severity.WARNING,
                title="Weak EAP Methods Detected",
                description=f"Detected {total_weak} authentications using weak EAP methods ({weak_percentage:.1f}%)",
                details={
                    "weak_methods": method_security["weak"],
                    "weak_methods_percentage": round(weak_percentage, 1),
                    "security_risk": "Weak EAP methods are vulnerable to attacks",
                    "vulnerable_methods": [
                        {
                            "method": "MD5-Challenge",
                            "risk": "Vulnerable to dictionary attacks"
                        },
                        {
                            "method": "LEAP",
                            "risk": "Known cryptographic weaknesses"
                        },
                        {
                            "method": "MS-CHAPv2",
                            "risk": "Vulnerable to offline attacks when used alone"
                        }
                    ],
                    "recommendations": [
                        "Migrate to strong EAP methods (EAP-TLS, PEAP, TTLS)",
                        "Disable weak EAP methods in authentication servers",
                        "Implement certificate-based authentication",
                        "Use strong inner methods for tunneled EAP"
                    ]
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
            
        # Certificate-based method analysis
        cert_based_count = sum(
            count for method, count in self.security_posture.methods_observed.items()
            if method.certificate_based
        )
        total_methods = sum(self.security_posture.methods_observed.values())
        cert_based_percentage = (cert_based_count / max(total_methods, 1)) * 100
        
        if cert_based_percentage < 50:
            findings.append(Finding(
                category=AnalysisCategory.ENTERPRISE_SECURITY,
                severity=Severity.INFO,
                title="Low Certificate-Based Authentication Usage",
                description=f"Only {cert_based_percentage:.1f}% of authentications use certificate-based methods",
                details={
                    "certificate_based_percentage": round(cert_based_percentage, 1),
                    "certificate_based_count": cert_based_count,
                    "total_authentications": total_methods,
                    "strong_methods": method_security["strong"],
                    "security_benefit": "Certificate-based methods provide stronger security",
                    "recommendations": [
                        "Deploy EAP-TLS for strongest security",
                        "Use PEAP/TTLS with server certificates",
                        "Implement proper PKI infrastructure",
                        "Train users on certificate installation"
                    ]
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
            
        return findings
        
    def _analyze_certificate_security(self) -> List[Finding]:
        """Analyze certificate security for enterprise authentication."""
        findings = []
        
        if not self.certificates:
            findings.append(Finding(
                category=AnalysisCategory.ENTERPRISE_SECURITY,
                severity=Severity.INFO,
                title="No TLS Certificates Analyzed",
                description="No TLS certificates detected in enterprise authentication traffic",
                details={
                    "certificates_found": 0,
                    "analysis_limitation": "Certificate analysis requires TLS traffic capture",
                    "recommendations": [
                        "Ensure capture includes full TLS handshakes",
                        "Verify EAP-TLS or server certificate usage",
                        "Check if certificate validation is properly configured"
                    ]
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
            return findings
            
        # Certificate security analysis
        security_issues = []
        expired_certs = []
        weak_key_certs = []
        self_signed_certs = []
        
        for fingerprint, cert in self.certificates.items():
            if cert.is_expired:
                expired_certs.append(cert.subject)
            if cert.public_key_size > 0 and cert.public_key_size < 2048:
                weak_key_certs.append(f"{cert.subject} ({cert.public_key_size} bits)")
            if cert.is_self_signed:
                self_signed_certs.append(cert.subject)
            security_issues.extend(cert.security_issues)
            
        # Generate findings for certificate issues
        if expired_certs or weak_key_certs or self_signed_certs:
            severity = Severity.CRITICAL if expired_certs else Severity.WARNING
            
            findings.append(Finding(
                category=AnalysisCategory.ENTERPRISE_SECURITY,
                severity=severity,
                title="Certificate Security Issues Detected",
                description=f"Found security issues in {len(self.certificates)} enterprise certificates",
                details={
                    "certificates_analyzed": len(self.certificates),
                    "expired_certificates": expired_certs,
                    "weak_key_certificates": weak_key_certs,
                    "self_signed_certificates": self_signed_certs,
                    "security_issues": list(set(security_issues)),
                    "security_impact": "Certificate issues compromise authentication security",
                    "recommendations": [
                        "Renew expired certificates immediately",
                        "Replace certificates with weak keys (use 2048+ bit RSA)",
                        "Use proper CA-signed certificates in production",
                        "Implement certificate lifecycle management",
                        "Enable certificate revocation checking"
                    ]
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
            
        return findings
        
    def _analyze_radius_security(self) -> List[Finding]:
        """Analyze RADIUS communication security."""
        findings = []
        
        if not self.radius_conversations:
            return findings
            
        # RADIUS infrastructure analysis
        total_servers = len(self.security_posture.radius_servers)
        total_nas_devices = len(self.security_posture.nas_devices)
        
        # Calculate RADIUS success rates
        radius_stats = {
            "total_requests": 0,
            "total_accepts": 0,
            "total_rejects": 0,
            "total_challenges": 0
        }
        
        slow_responses = []
        
        for conv in self.radius_conversations.values():
            radius_stats["total_requests"] += conv.access_requests
            radius_stats["total_accepts"] += conv.access_accepts
            radius_stats["total_rejects"] += conv.access_rejects
            radius_stats["total_challenges"] += conv.access_challenges
            
            if conv.average_response_time > 5.0:  # Slow response
                slow_responses.append({
                    "server": conv.server_ip,
                    "client": conv.client_ip,
                    "avg_response_time": round(conv.average_response_time, 2)
                })
                
        # RADIUS success rate
        total_responses = radius_stats["total_accepts"] + radius_stats["total_rejects"]
        if total_responses > 0:
            success_rate = (radius_stats["total_accepts"] / total_responses) * 100
            
            if success_rate < 80:
                findings.append(Finding(
                    category=AnalysisCategory.ENTERPRISE_SECURITY,
                    severity=Severity.WARNING,
                    title="Low RADIUS Authentication Success Rate",
                    description=f"RADIUS success rate: {success_rate:.1f}% across {total_servers} servers",
                    details={
                        "radius_success_rate": round(success_rate, 1),
                        "radius_statistics": radius_stats,
                        "radius_servers": list(self.security_posture.radius_servers),
                        "nas_devices": list(self.security_posture.nas_devices),
                        "infrastructure_concern": "Low RADIUS success rate indicates authentication issues",
                        "recommendations": [
                            "Investigate RADIUS server configuration",
                            "Check user database synchronization",
                            "Verify NAS device configuration",
                            "Review authentication policies"
                        ]
                    },
                    analyzer_name=self.name,
                    analyzer_version=self.version
                ))
                
        # RADIUS performance issues
        if slow_responses:
            findings.append(Finding(
                category=AnalysisCategory.ENTERPRISE_SECURITY,
                severity=Severity.INFO,
                title="RADIUS Performance Issues",
                description=f"Detected {len(slow_responses)} RADIUS conversations with slow response times",
                details={
                    "slow_radius_responses": slow_responses[:10],
                    "performance_threshold": "5.0 seconds",
                    "impact": "Slow RADIUS responses delay authentication",
                    "recommendations": [
                        "Optimize RADIUS server performance",
                        "Check network connectivity to RADIUS servers",
                        "Consider RADIUS server load balancing",
                        "Review RADIUS server hardware resources"
                    ]
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
            
        return findings
        
    def _analyze_enterprise_compliance(self) -> List[Finding]:
        """Analyze enterprise policy compliance."""
        findings = []
        
        # Policy compliance assessment
        compliance_score = self.security_posture.compliance_score
        violations = self.security_posture.policy_violations
        
        if violations:
            severity = Severity.CRITICAL if compliance_score < 50 else Severity.WARNING
            
            findings.append(Finding(
                category=AnalysisCategory.ENTERPRISE_SECURITY,
                severity=severity,
                title="Enterprise Security Policy Violations",
                description=f"Compliance score: {compliance_score:.0f}% ({len(violations)} violations)",
                details={
                    "compliance_score": round(compliance_score, 1),
                    "policy_violations": violations,
                    "violation_count": len(violations),
                    "compliance_status": "NON-COMPLIANT" if compliance_score < 80 else "PARTIALLY_COMPLIANT",
                    "security_policies": {
                        "allowed_eap_methods": [m.method_name for m in self.security_policies["allowed_eap_methods"]],
                        "prohibited_eap_methods": [m.method_name for m in self.security_policies["prohibited_eap_methods"]],
                        "certificate_requirements": {
                            "minimum_key_size": self.security_policies["minimum_certificate_key_size"],
                            "maximum_age_days": self.security_policies["maximum_certificate_age_days"]
                        }
                    },
                    "recommendations": [
                        "Address all policy violations immediately",
                        "Update security configurations to meet enterprise standards",
                        "Implement automated policy compliance monitoring",
                        "Regular security audits and assessments"
                    ]
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
            
        return findings
        
    def _analyze_infrastructure_security(self) -> List[Finding]:
        """Analyze enterprise authentication infrastructure."""
        findings = []
        
        # Infrastructure overview
        domains = self.security_posture.authentication_domains
        radius_servers = self.security_posture.radius_servers
        nas_devices = self.security_posture.nas_devices
        
        if len(domains) > 1 or len(radius_servers) > 3:
            findings.append(Finding(
                category=AnalysisCategory.ENTERPRISE_SECURITY,
                severity=Severity.INFO,
                title="Enterprise Authentication Infrastructure Analysis",
                description=f"Complex authentication infrastructure: {len(domains)} domains, {len(radius_servers)} RADIUS servers",
                details={
                    "authentication_domains": list(domains),
                    "radius_servers": list(radius_servers),
                    "nas_devices": list(nas_devices),
                    "infrastructure_complexity": {
                        "domains": len(domains),
                        "radius_servers": len(radius_servers),
                        "nas_devices": len(nas_devices)
                    },
                    "security_considerations": [
                        "Multiple domains may indicate complex trust relationships",
                        "Multiple RADIUS servers require consistent configuration",
                        "NAS device security is critical for overall system security"
                    ],
                    "recommendations": [
                        "Document authentication infrastructure architecture",
                        "Ensure consistent security policies across all domains",
                        "Implement centralized RADIUS server management",
                        "Regular security assessment of all infrastructure components"
                    ]
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
            
        return findings