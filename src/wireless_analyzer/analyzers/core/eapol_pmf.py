"""
EAPOL/PMF Analysis for wireless PCAP data.

This analyzer provides comprehensive EAPOL (Extensible Authentication Protocol over LAN) 
and PMF (Protected Management Frames) analysis including:
- 4-way handshake success/failure analysis
- MIC (Message Integrity Check) error detection and patterns
- PTK (Pairwise Transient Key) and GTK (Group Temporal Key) retry analysis
- PMF required/optional/absent detection and compliance
- EAP method identification and analysis
- Key derivation timing and performance analysis
- EAPOL frame sequencing and state validation
- Security vulnerability detection (KRACK, downgrade attacks)
- PMF bypass attempts and management frame protection analysis
"""

import struct
import hashlib
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Any, Set, Optional, NamedTuple, Tuple
import logging

from scapy.all import Packet
from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Disas, Dot11Auth, Dot11AssoReq, Dot11AssoResp
from scapy.layers.eap import EAPOL, EAP
from scapy.layers.dot11 import Dot11Elt

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


class HandshakeState(Enum):
    """4-way handshake state enumeration."""
    IDLE = "idle"
    MSG1_SENT = "msg1_sent"
    MSG2_RECEIVED = "msg2_received" 
    MSG3_SENT = "msg3_sent"
    MSG4_RECEIVED = "msg4_received"
    COMPLETED = "completed"
    FAILED = "failed"


class PMFStatus(Enum):
    """PMF status enumeration."""
    REQUIRED = "required"
    OPTIONAL = "optional"
    DISABLED = "disabled"
    UNKNOWN = "unknown"


class EAPMethod(Enum):
    """EAP method enumeration."""
    IDENTITY = 1
    NOTIFICATION = 2
    NAK = 3
    MD5_CHALLENGE = 4
    OTP = 5
    GTC = 6
    TLS = 13
    LEAP = 17
    SIM = 18
    TTLS = 21
    AKA = 23
    PEAP = 25
    MSCHAP_V2 = 26
    TLV = 33
    FAST = 43
    PSK = 47
    SAKE = 48
    IKEV2 = 49
    AKA_PRIME = 50
    GPSK = 51
    PWD = 52
    TEAP = 55


@dataclass
class EAPOLFrame:
    """EAPOL frame information."""
    timestamp: float
    source_mac: str
    dest_mac: str
    frame_type: int  # EAPOL type
    message_type: Optional[int] = None  # For EAPOL-Key
    key_type: Optional[int] = None
    key_info: Optional[int] = None
    key_length: Optional[int] = None
    replay_counter: Optional[int] = None
    nonce: Optional[bytes] = None
    key_iv: Optional[bytes] = None
    rsc: Optional[int] = None
    key_id: Optional[int] = None
    mic: Optional[bytes] = None
    key_data_length: Optional[int] = None
    key_data: Optional[bytes] = None
    mic_valid: Optional[bool] = None


@dataclass
class FourWayHandshake:
    """4-way handshake tracking."""
    sta_mac: str
    ap_mac: str
    bssid: str
    
    # Handshake state
    state: HandshakeState = HandshakeState.IDLE
    start_time: Optional[datetime] = None
    complete_time: Optional[datetime] = None
    
    # Messages
    msg1: Optional[EAPOLFrame] = None
    msg2: Optional[EAPOLFrame] = None
    msg3: Optional[EAPOLFrame] = None
    msg4: Optional[EAPOLFrame] = None
    
    # Timing analysis
    msg1_to_msg2_time: Optional[float] = None
    msg2_to_msg3_time: Optional[float] = None
    msg3_to_msg4_time: Optional[float] = None
    total_time: Optional[float] = None
    
    # Retry analysis
    msg1_retries: int = 0
    msg2_retries: int = 0
    msg3_retries: int = 0
    msg4_retries: int = 0
    
    # Security analysis
    anonce: Optional[bytes] = None
    snonce: Optional[bytes] = None
    mic_errors: int = 0
    replay_attacks: int = 0
    
    # Success/failure
    successful: bool = False
    failure_reason: Optional[str] = None
    failure_stage: Optional[str] = None


@dataclass
class PMFAnalysis:
    """PMF analysis results."""
    ap_bssid: str
    ap_ssid: str
    
    # PMF configuration
    pmf_status: PMFStatus = PMFStatus.UNKNOWN
    pmf_capable: bool = False
    pmf_required: bool = False
    
    # Frame protection statistics  
    protected_mgmt_frames: int = 0
    unprotected_mgmt_frames: int = 0
    
    # Security analysis
    pmf_bypass_attempts: int = 0
    forged_mgmt_frames: int = 0
    pmf_violations: List[str] = field(default_factory=list)


@dataclass
class EAPSession:
    """EAP session tracking."""
    sta_mac: str
    ap_mac: str
    session_id: str
    
    # EAP method analysis
    methods_attempted: List[EAPMethod] = field(default_factory=list)
    method_negotiated: Optional[EAPMethod] = None
    
    # Session flow
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    success: bool = False
    failure_reason: Optional[str] = None
    
    # Frame analysis
    identity_requests: int = 0
    identity_responses: int = 0
    challenge_responses: int = 0
    success_frames: int = 0
    failure_frames: int = 0
    
    # Security analysis
    method_downgrades: int = 0
    unusual_patterns: List[str] = field(default_factory=list)


class EAPOLPMFAnalyzer(BaseAnalyzer):
    """
    Comprehensive EAPOL/PMF Analyzer.
    
    This analyzer performs detailed analysis of EAPOL frames, 4-way handshakes,
    PMF implementation, and EAP authentication flows to identify security
    issues, timing problems, and protocol violations.
    """
    
    def __init__(self):
        super().__init__(
            name="EAPOL/PMF Security Analyzer",
            category=AnalysisCategory.EAPOL_HANDSHAKE,
            version="1.0"
        )
        
        self.description = (
            "Analyzes EAPOL 4-way handshakes, PMF implementation, "
            "and EAP authentication security"
        )
        
        # Wireshark filters for EAPOL/PMF analysis
        self.wireshark_filters = [
            "eapol",  # EAPOL frames
            "eap",    # EAP frames
            "wlan.fc.protected == 1",  # Protected frames
            "wlan_mgt.fixed.capabilities.privacy == 1",
            "wlan.rsn.pmf.capable == 1",
            "wlan.rsn.pmf.required == 1"
        ]
        
        self.analysis_order = 35  # Run after auth/assoc flow analysis
        
        # Analysis storage
        self.handshakes: Dict[str, FourWayHandshake] = {}  # Key: sta_mac:ap_mac
        self.pmf_analysis: Dict[str, PMFAnalysis] = {}     # Key: ap_bssid
        self.eap_sessions: Dict[str, EAPSession] = {}      # Key: sta_mac:ap_mac
        self.eapol_frames: List[EAPOLFrame] = []
        
        # Security patterns
        self.known_vulnerabilities = {
            'krack': {'nonce_reuse': [], 'key_reinstall': []},
            'pmf_bypass': {'unprotected_deauth': [], 'unprotected_disassoc': []},
            'mic_attacks': {'mic_errors': [], 'mic_spoofing': []},
            'downgrade': {'method_downgrades': [], 'pmf_downgrades': []}
        }
        
        # Timing thresholds
        self.NORMAL_HANDSHAKE_TIME = 1.0    # 1 second
        self.MAX_HANDSHAKE_TIME = 10.0      # 10 seconds
        self.MSG_TIMEOUT = 2.0              # 2 seconds per message
        
        # Key info field masks
        self.KEY_INFO_KEY_TYPE = 0x0008      # 1 = Pairwise, 0 = Group
        self.KEY_INFO_INSTALL = 0x0040       # Install flag
        self.KEY_INFO_KEY_ACK = 0x0080       # Key Ack flag
        self.KEY_INFO_KEY_MIC = 0x0100       # Key MIC flag
        self.KEY_INFO_SECURE = 0x0200        # Secure flag
        self.KEY_INFO_ERROR = 0x0400         # Error flag
        self.KEY_INFO_REQUEST = 0x0800       # Request flag
        self.KEY_INFO_ENCRYPTED = 0x1000     # Encrypted Key Data flag

    def is_applicable(self, packet: Packet) -> bool:
        """Check if packet is relevant for EAPOL/PMF analysis."""
        return (packet_has_layer(packet, "EAPOL") or 
                packet_has_layer(packet, "EAP") or
                (packet_has_layer(packet, "Dot11") and self._is_protected_mgmt_frame(packet)))
        
    def _is_protected_mgmt_frame(self, packet: Packet) -> bool:
        """Check if packet is a protected management frame."""
        if not packet_has_layer(packet, "Dot11"):
            return False
            
        dot11 = get_packet_layer(packet, "Dot11")
        if not dot11:
            return False
            
        # Check if frame is protected (FCfield bit 6)
        fc_field = get_packet_field(packet, "Dot11", "FCfield")
        frame_type = get_packet_field(packet, "Dot11", "type")
        
        if fc_field is not None and (fc_field & 0x40):
            # Check if it's a management frame (type 0)
            if frame_type == 0:
                return True
        return False
        
    def get_display_filters(self) -> List[str]:
        """Get Wireshark display filters for EAPOL/PMF analysis."""
        return self.wireshark_filters
        
    def analyze(self, packets: List[Packet], context: AnalysisContext) -> List[Finding]:
        """
        Analyze EAPOL/PMF security aspects.
        
        Args:
            packets: List of EAPOL/EAP/protected management packets
            context: Analysis context
            
        Returns:
            List of findings
        """
        if not packets:
            return []
            
        self.logger.info(f"Analyzing EAPOL/PMF security from {len(packets)} packets")
        
        # Extract beacon inventory for PMF configuration
        beacon_inventory = context.metadata.get('beacon_inventory', {})
        self._initialize_pmf_analysis(beacon_inventory)
        
        # Process EAPOL and EAP frames
        self._process_security_frames(packets)
        
        # Analyze 4-way handshakes
        self._analyze_handshake_flows()
        
        # Analyze PMF implementation
        self._analyze_pmf_implementation(packets)
        
        # Analyze EAP sessions
        self._analyze_eap_sessions()
        
        # Detect security vulnerabilities
        self._detect_security_vulnerabilities()
        
        self.logger.info(f"Analyzed {len(self.handshakes)} handshakes, {len(self.eap_sessions)} EAP sessions")
        
        # Generate findings
        findings = []
        findings.extend(self._analyze_handshake_success_rates())
        findings.extend(self._analyze_handshake_timing())
        findings.extend(self._analyze_mic_errors())
        findings.extend(self._analyze_retry_patterns())
        findings.extend(self._analyze_pmf_compliance())
        findings.extend(self._analyze_eap_methods())
        findings.extend(self._analyze_security_vulnerabilities())
        
        # Store results in context
        context.metadata['eapol_pmf_analysis'] = {
            'handshakes': len(self.handshakes),
            'successful_handshakes': sum(1 for h in self.handshakes.values() if h.successful),
            'pmf_networks': len([p for p in self.pmf_analysis.values() if p.pmf_status != PMFStatus.DISABLED]),
            'eap_sessions': len(self.eap_sessions),
            'vulnerabilities': self.known_vulnerabilities
        }
        
        self.findings_generated = len(findings)
        return findings
        
    def _initialize_pmf_analysis(self, beacon_inventory: Dict) -> None:
        """Initialize PMF analysis from beacon inventory."""
        for bssid, beacon_entry in beacon_inventory.items():
            pmf_analysis = PMFAnalysis(
                ap_bssid=bssid,
                ap_ssid=getattr(beacon_entry, 'ssid', 'Unknown')
            )
            
            # Extract PMF status from beacon security config
            if hasattr(beacon_entry, 'security'):
                security = beacon_entry.security
                pmf_analysis.pmf_capable = getattr(security, 'pmf_capable', False)
                pmf_analysis.pmf_required = getattr(security, 'pmf_required', False)
                
                if pmf_analysis.pmf_required:
                    pmf_analysis.pmf_status = PMFStatus.REQUIRED
                elif pmf_analysis.pmf_capable:
                    pmf_analysis.pmf_status = PMFStatus.OPTIONAL
                else:
                    pmf_analysis.pmf_status = PMFStatus.DISABLED
                    
            self.pmf_analysis[bssid] = pmf_analysis
            
    def _process_security_frames(self, packets: List[Packet]) -> None:
        """Process EAPOL and EAP frames."""
        for packet in packets:
            try:
                if packet_has_layer(packet, EAPOL):
                    eapol_frame = self._extract_eapol_frame(packet)
                    if eapol_frame:
                        self.eapol_frames.append(eapol_frame)
                        self._process_eapol_frame(eapol_frame)
                        
                elif packet_has_layer(packet, EAP):
                    self._process_eap_frame(packet)
                    
                # Track protected management frames
                if self._is_protected_mgmt_frame(packet):
                    self._process_protected_mgmt_frame(packet)
                    
            except Exception as e:
                self.logger.debug(f"Error processing security frame: {e}")
                continue
                
    def _extract_eapol_frame(self, packet: Packet) -> Optional[EAPOLFrame]:
        """Extract EAPOL frame information."""
        try:
            if not packet_has_layer(packet, EAPOL):
                return None
                
            dot11 = get_packet_layer(packet, "Dot11")
            eapol = get_packet_layer(packet, "EAPOL")
            
            # Get timestamp
            timestamp = get_timestamp(packet) if hasattr(packet, 'time') else 0
            if hasattr(timestamp, '__float__'):
                timestamp = float(timestamp)
            elif hasattr(timestamp, 'val'):
                timestamp = float(timestamp.val)
            else:
                timestamp = float(timestamp)
            
            frame = EAPOLFrame(
                timestamp=timestamp,
                source_mac=dot11.addr2 if dot11.addr2 else "unknown",
                dest_mac=dot11.addr1 if dot11.addr1 else "unknown",
                frame_type=get_packet_field(packet, "Dot11", "type") if hasattr(eapol, 'type') else 0
            )
            
            # Extract EAPOL-Key specific fields
            if frame.frame_type == 3 and hasattr(eapol, 'payload'):  # EAPOL-Key
                key_frame = eapol.payload
                raw_data = bytes(key_frame)
                
                if len(raw_data) >= 95:  # Minimum EAPOL-Key frame size
                    # Parse key frame fields
                    frame.message_type = raw_data[0] if len(raw_data) > 0 else None
                    frame.key_info = struct.unpack('>H', raw_data[1:3])[0] if len(raw_data) >= 3 else None
                    frame.key_length = struct.unpack('>H', raw_data[3:5])[0] if len(raw_data) >= 5 else None
                    frame.replay_counter = struct.unpack('>Q', raw_data[5:13])[0] if len(raw_data) >= 13 else None
                    frame.nonce = raw_data[13:45] if len(raw_data) >= 45 else None
                    frame.key_iv = raw_data[45:61] if len(raw_data) >= 61 else None
                    frame.rsc = struct.unpack('>Q', raw_data[61:69])[0] if len(raw_data) >= 69 else None
                    frame.key_id = struct.unpack('>Q', raw_data[69:77])[0] if len(raw_data) >= 77 else None
                    frame.mic = raw_data[77:93] if len(raw_data) >= 93 else None
                    frame.key_data_length = struct.unpack('>H', raw_data[93:95])[0] if len(raw_data) >= 95 else None
                    
                    if frame.key_data_length and len(raw_data) >= 95 + frame.key_data_length:
                        frame.key_data = raw_data[95:95+frame.key_data_length]
            
            return frame
            
        except Exception as e:
            self.logger.debug(f"Error extracting EAPOL frame: {e}")
            return None
            
    def _process_eapol_frame(self, frame: EAPOLFrame) -> None:
        """Process EAPOL frame for handshake tracking."""
        if frame.frame_type != 3:  # Not EAPOL-Key
            return
            
        # Determine handshake key
        handshake_key = f"{frame.source_mac}:{frame.dest_mac}"
        
        # Determine message type based on key_info flags
        if frame.key_info:
            is_pairwise = bool(frame.key_info & self.KEY_INFO_KEY_TYPE)
            has_ack = bool(frame.key_info & self.KEY_INFO_KEY_ACK)
            has_mic = bool(frame.key_info & self.KEY_INFO_KEY_MIC)
            has_secure = bool(frame.key_info & self.KEY_INFO_SECURE)
            has_install = bool(frame.key_info & self.KEY_INFO_INSTALL)
            
            # Determine message number
            message_num = None
            if is_pairwise:
                if has_ack and not has_mic and not has_secure:
                    message_num = 1  # Message 1/4
                    # Reverse key for STA->AP direction
                    handshake_key = f"{frame.dest_mac}:{frame.source_mac}"
                elif not has_ack and has_mic and not has_secure:
                    message_num = 2  # Message 2/4
                elif has_ack and has_mic and has_secure and has_install:
                    message_num = 3  # Message 3/4
                    handshake_key = f"{frame.dest_mac}:{frame.source_mac}"
                elif not has_ack and has_mic and has_secure:
                    message_num = 4  # Message 4/4
            
            if message_num:
                self._update_handshake(handshake_key, frame, message_num)
                
    def _update_handshake(self, handshake_key: str, frame: EAPOLFrame, message_num: int) -> None:
        """Update 4-way handshake state."""
        if handshake_key not in self.handshakes:
            sta_mac, ap_mac = handshake_key.split(':')
            self.handshakes[handshake_key] = FourWayHandshake(
                sta_mac=sta_mac,
                ap_mac=ap_mac,
                bssid=ap_mac  # Assuming AP MAC is BSSID
            )
            
        handshake = self.handshakes[handshake_key]
        frame_time = datetime.fromtimestamp(frame.timestamp)
        
        if message_num == 1:
            if handshake.msg1 is None:
                handshake.msg1 = frame
                handshake.state = HandshakeState.MSG1_SENT
                handshake.start_time = frame_time
                handshake.anonce = frame.nonce
            else:
                handshake.msg1_retries += 1
                
        elif message_num == 2:
            if handshake.msg2 is None:
                handshake.msg2 = frame
                handshake.state = HandshakeState.MSG2_RECEIVED
                handshake.snonce = frame.nonce
                
                if handshake.start_time:
                    handshake.msg1_to_msg2_time = (frame_time - handshake.start_time).total_seconds()
            else:
                handshake.msg2_retries += 1
                
        elif message_num == 3:
            if handshake.msg3 is None:
                handshake.msg3 = frame
                handshake.state = HandshakeState.MSG3_SENT
                
                if handshake.msg2 and handshake.msg2.timestamp:
                    msg2_time = datetime.fromtimestamp(handshake.msg2.timestamp)
                    handshake.msg2_to_msg3_time = (frame_time - msg2_time).total_seconds()
            else:
                handshake.msg3_retries += 1
                
        elif message_num == 4:
            if handshake.msg4 is None:
                handshake.msg4 = frame
                handshake.state = HandshakeState.MSG4_RECEIVED
                handshake.complete_time = frame_time
                handshake.successful = True
                
                if handshake.msg3 and handshake.msg3.timestamp:
                    msg3_time = datetime.fromtimestamp(handshake.msg3.timestamp)
                    handshake.msg3_to_msg4_time = (frame_time - msg3_time).total_seconds()
                    
                if handshake.start_time:
                    handshake.total_time = (frame_time - handshake.start_time).total_seconds()
            else:
                handshake.msg4_retries += 1
        
        # Check for MIC errors (simplified)
        if frame.key_info and (frame.key_info & self.KEY_INFO_ERROR):
            handshake.mic_errors += 1
            
    def _process_eap_frame(self, packet: Packet) -> None:
        """Process EAP frame for session tracking."""
        try:
            if not packet_has_layer(packet, EAP):
                return
                
            dot11 = get_packet_layer(packet, "Dot11") 
            eap = get_packet_layer(packet, "EAP")
            
            session_key = f"{dot11.addr2}:{dot11.addr1}"
            
            if session_key not in self.eap_sessions:
                self.eap_sessions[session_key] = EAPSession(
                    sta_mac=dot11.addr2,
                    ap_mac=dot11.addr1,
                    session_id=session_key,
                    start_time=datetime.fromtimestamp(float(get_timestamp(packet)))
                )
                
            session = self.eap_sessions[session_key]
            
            # Analyze EAP method
            if hasattr(eap, 'type'):
                try:
                    method = EAPMethod(get_packet_field(packet, "Dot11", "type"))
                    if method not in session.methods_attempted:
                        session.methods_attempted.append(method)
                except ValueError:
                    pass  # Unknown method type
                    
            # Track frame types
            if hasattr(eap, 'code'):
                if eap.code == 1:  # Request
                    if hasattr(eap, 'type') and get_packet_field(packet, "Dot11", "type") == 1:  # Identity
                        session.identity_requests += 1
                elif eap.code == 2:  # Response
                    if hasattr(eap, 'type') and get_packet_field(packet, "Dot11", "type") == 1:  # Identity
                        session.identity_responses += 1
                    else:
                        session.challenge_responses += 1
                elif eap.code == 3:  # Success
                    session.success_frames += 1
                    session.success = True
                elif eap.code == 4:  # Failure
                    session.failure_frames += 1
                    
        except Exception as e:
            self.logger.debug(f"Error processing EAP frame: {e}")
            
    def _process_protected_mgmt_frame(self, packet: Packet) -> None:
        """Process protected management frame for PMF analysis."""
        try:
            dot11 = get_packet_layer(packet, "Dot11")
            bssid = dot11.addr3 if dot11.addr3 else dot11.addr2
            
            if bssid in self.pmf_analysis:
                self.pmf_analysis[bssid].protected_mgmt_frames += 1
                
        except Exception as e:
            self.logger.debug(f"Error processing protected management frame: {e}")
            
    def _analyze_handshake_flows(self) -> None:
        """Analyze 4-way handshake flows for completeness and timing."""
        for handshake in self.handshakes.values():
            # Check for incomplete handshakes
            if not handshake.successful:
                if handshake.state == HandshakeState.MSG1_SENT:
                    handshake.failure_reason = "No response to Message 1/4"
                    handshake.failure_stage = "msg1_timeout"
                elif handshake.state == HandshakeState.MSG2_RECEIVED:
                    handshake.failure_reason = "No Message 3/4 sent"
                    handshake.failure_stage = "msg3_missing"
                elif handshake.state == HandshakeState.MSG3_SENT:
                    handshake.failure_reason = "No Message 4/4 received"
                    handshake.failure_stage = "msg4_timeout"
                    
                handshake.state = HandshakeState.FAILED
                
    def _analyze_pmf_implementation(self, packets: List[Packet]) -> None:
        """Analyze PMF implementation and compliance."""
        for packet in packets:
            if packet_has_layer(packet, Dot11Deauth) or packet_has_layer(packet, Dot11Disas):
                dot11 = get_packet_layer(packet, "Dot11")
                bssid = dot11.addr3 if dot11.addr3 else dot11.addr2
                
                if bssid in self.pmf_analysis:
                    pmf_info = self.pmf_analysis[bssid]
                    
                    # Check if management frame is protected when PMF is required
                    is_protected = bool(dot11.FCfield & 0x40) if hasattr(dot11, 'FCfield') else False
                    
                    if pmf_info.pmf_status == PMFStatus.REQUIRED and not is_protected:
                        pmf_info.pmf_bypass_attempts += 1
                        pmf_info.pmf_violations.append("Unprotected deauth/disassoc with PMF required")
                    
                    if is_protected:
                        pmf_info.protected_mgmt_frames += 1
                    else:
                        pmf_info.unprotected_mgmt_frames += 1
                        
    def _analyze_eap_sessions(self) -> None:
        """Analyze EAP session patterns and methods."""
        for session in self.eap_sessions.values():
            # Detect method negotiations
            if len(session.methods_attempted) > 1:
                session.method_negotiated = session.methods_attempted[-1]
                
                # Check for potential downgrades
                if EAPMethod.TLS in session.methods_attempted and session.method_negotiated != EAPMethod.TLS:
                    session.method_downgrades += 1
                    session.unusual_patterns.append("TLS method downgraded")
                    
    def _detect_security_vulnerabilities(self) -> None:
        """Detect known security vulnerabilities."""
        # KRACK detection - Nonce reuse
        anonces_seen = defaultdict(list)
        snonces_seen = defaultdict(list)
        
        for handshake in self.handshakes.values():
            if handshake.anonce:
                anonces_seen[handshake.anonce].append(handshake)
            if handshake.snonce:
                snonces_seen[handshake.snonce].append(handshake)
                
        # Check for nonce reuse
        for nonce, handshakes in anonces_seen.items():
            if len(handshakes) > 1:
                self.known_vulnerabilities['krack']['nonce_reuse'].extend(handshakes)
                
        for nonce, handshakes in snonces_seen.items():
            if len(handshakes) > 1:
                self.known_vulnerabilities['krack']['nonce_reuse'].extend(handshakes)
                
        # Detect key reinstallation attacks
        for handshake in self.handshakes.values():
            if handshake.msg3_retries > 2:  # Excessive Message 3 retries
                self.known_vulnerabilities['krack']['key_reinstall'].append(handshake)
                
    # Analysis methods for generating findings
    
    def _analyze_handshake_success_rates(self) -> List[Finding]:
        """Analyze 4-way handshake success rates."""
        findings = []
        
        if not self.handshakes:
            return findings
            
        total_handshakes = len(self.handshakes)
        successful_handshakes = sum(1 for h in self.handshakes.values() if h.successful)
        success_rate = (successful_handshakes / total_handshakes * 100) if total_handshakes > 0 else 0
        
        # Failure analysis
        failure_reasons = Counter()
        for handshake in self.handshakes.values():
            if not handshake.successful and handshake.failure_reason:
                failure_reasons[handshake.failure_reason] += 1
                
        severity = Severity.CRITICAL if success_rate < 50 else \
                  Severity.WARNING if success_rate < 80 else Severity.INFO
                  
        findings.append(Finding(
            category=AnalysisCategory.EAPOL_HANDSHAKE,
            severity=severity,
            title="4-way Handshake Success Analysis",
            description=f"EAPOL handshake success rate: {success_rate:.1f}%",
            details={
                "total_handshakes": total_handshakes,
                "successful_handshakes": successful_handshakes,
                "failed_handshakes": total_handshakes - successful_handshakes,
                "success_rate_percentage": round(success_rate, 1),
                "failure_reasons": dict(failure_reasons.most_common(10)),
                "assessment": "POOR" if success_rate < 50 else 
                            "FAIR" if success_rate < 80 else "GOOD"
            },
            analyzer_name=self.name,
            analyzer_version=self.version
        ))
        
        return findings
        
    def _analyze_handshake_timing(self) -> List[Finding]:
        """Analyze handshake timing performance."""
        findings = []
        
        successful_handshakes = [h for h in self.handshakes.values() if h.successful]
        if not successful_handshakes:
            return findings
            
        # Collect timing metrics
        total_times = [h.total_time for h in successful_handshakes if h.total_time]
        msg_times = []
        
        for handshake in successful_handshakes:
            if handshake.msg1_to_msg2_time:
                msg_times.append(("1->2", handshake.msg1_to_msg2_time))
            if handshake.msg2_to_msg3_time:
                msg_times.append(("2->3", handshake.msg2_to_msg3_time))
            if handshake.msg3_to_msg4_time:
                msg_times.append(("3->4", handshake.msg3_to_msg4_time))
                
        # Timing analysis
        slow_handshakes = [t for t in total_times if t > self.NORMAL_HANDSHAKE_TIME]
        very_slow_handshakes = [t for t in total_times if t > self.MAX_HANDSHAKE_TIME]
        
        if total_times:
            import statistics
            avg_time = statistics.mean(total_times)
            max_time = max(total_times)
            
            findings.append(Finding(
                category=AnalysisCategory.EAPOL_HANDSHAKE,
                severity=Severity.WARNING if len(slow_handshakes) > len(total_times) * 0.2 else Severity.INFO,
                title="4-way Handshake Timing Analysis",
                description=f"Handshake timing analysis from {len(total_times)} successful handshakes",
                details={
                    "total_analyzed": len(total_times),
                    "avg_handshake_time": round(avg_time, 3),
                    "max_handshake_time": round(max_time, 3),
                    "slow_handshakes": len(slow_handshakes),
                    "very_slow_handshakes": len(very_slow_handshakes),
                    "normal_threshold": self.NORMAL_HANDSHAKE_TIME,
                    "max_threshold": self.MAX_HANDSHAKE_TIME
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
            
        return findings
        
    def _analyze_mic_errors(self) -> List[Finding]:
        """Analyze MIC errors and authentication issues."""
        findings = []
        
        handshakes_with_mic_errors = [h for h in self.handshakes.values() if h.mic_errors > 0]
        
        if handshakes_with_mic_errors:
            total_mic_errors = sum(h.mic_errors for h in handshakes_with_mic_errors)
            
            findings.append(Finding(
                category=AnalysisCategory.EAPOL_HANDSHAKE,
                severity=Severity.WARNING,
                title="MIC Errors Detected",
                description=f"Found {total_mic_errors} MIC errors across {len(handshakes_with_mic_errors)} handshakes",
                details={
                    "affected_handshakes": len(handshakes_with_mic_errors),
                    "total_mic_errors": total_mic_errors,
                    "handshake_details": [
                        {
                            "sta_mac": h.sta_mac,
                            "ap_mac": h.ap_mac,
                            "mic_errors": h.mic_errors,
                            "successful": h.successful
                        }
                        for h in handshakes_with_mic_errors[:10]
                    ],
                    "potential_causes": [
                        "Wrong passphrase/PMK",
                        "Key derivation issues",
                        "Replay attacks",
                        "Implementation bugs"
                    ]
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
            
        return findings
        
    def _analyze_retry_patterns(self) -> List[Finding]:
        """Analyze PTK/GTK retry patterns."""
        findings = []
        
        high_retry_handshakes = []
        total_retries = 0
        
        for handshake in self.handshakes.values():
            handshake_retries = (handshake.msg1_retries + handshake.msg2_retries + 
                               handshake.msg3_retries + handshake.msg4_retries)
            total_retries += handshake_retries
            
            if handshake_retries > 3:  # High retry threshold
                high_retry_handshakes.append({
                    "sta_mac": handshake.sta_mac,
                    "ap_mac": handshake.ap_mac,
                    "msg1_retries": handshake.msg1_retries,
                    "msg2_retries": handshake.msg2_retries,
                    "msg3_retries": handshake.msg3_retries,
                    "msg4_retries": handshake.msg4_retries,
                    "total_retries": handshake_retries,
                    "successful": handshake.successful
                })
                
        if high_retry_handshakes:
            findings.append(Finding(
                category=AnalysisCategory.EAPOL_HANDSHAKE,
                severity=Severity.WARNING,
                title="High EAPOL Message Retry Rates",
                description=f"Found {len(high_retry_handshakes)} handshakes with excessive retries",
                details={
                    "high_retry_handshakes": high_retry_handshakes[:10],
                    "total_retries_all_handshakes": total_retries,
                    "analysis": "High retry rates may indicate poor signal quality or processing delays",
                    "recommendation": "Investigate RF conditions and AP/client performance"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
            
        return findings
        
    def _analyze_pmf_compliance(self) -> List[Finding]:
        """Analyze PMF implementation and compliance."""
        findings = []
        
        if not self.pmf_analysis:
            return findings
            
        pmf_stats = {
            "required": 0,
            "optional": 0,
            "disabled": 0,
            "violations": 0
        }
        
        violation_details = []
        
        for bssid, pmf_info in self.pmf_analysis.items():
            pmf_stats[pmf_info.pmf_status.value] += 1
            
            if pmf_info.pmf_violations:
                pmf_stats["violations"] += len(pmf_info.pmf_violations)
                violation_details.append({
                    "ap_bssid": bssid,
                    "ap_ssid": pmf_info.ap_ssid,
                    "pmf_status": pmf_info.pmf_status.value,
                    "violations": pmf_info.pmf_violations,
                    "bypass_attempts": pmf_info.pmf_bypass_attempts
                })
        
        findings.append(Finding(
            category=AnalysisCategory.ENTERPRISE_SECURITY,
            severity=Severity.WARNING if pmf_stats["violations"] > 0 else Severity.INFO,
            title="PMF (Protected Management Frames) Analysis",
            description=f"PMF implementation analysis across {len(self.pmf_analysis)} networks",
            details={
                "pmf_distribution": pmf_stats,
                "networks_analyzed": len(self.pmf_analysis),
                "pmf_violations": violation_details if violation_details else None,
                "recommendation": "Enable PMF (802.11w) for enhanced security" if pmf_stats["disabled"] > 0 else None
            },
            analyzer_name=self.name,
            analyzer_version=self.version
        ))
        
        return findings
        
    def _analyze_eap_methods(self) -> List[Finding]:
        """Analyze EAP method usage and security."""
        findings = []
        
        if not self.eap_sessions:
            return findings
            
        method_usage = Counter()
        downgrades = []
        
        for session in self.eap_sessions.values():
            if session.method_negotiated:
                method_usage[session.method_negotiated.name] += 1
                
            if session.method_downgrades > 0:
                downgrades.append({
                    "sta_mac": session.sta_mac,
                    "ap_mac": session.ap_mac,
                    "methods_attempted": [m.name for m in session.methods_attempted],
                    "final_method": session.method_negotiated.name if session.method_negotiated else "Unknown",
                    "downgrade_count": session.method_downgrades
                })
        
        findings.append(Finding(
            category=AnalysisCategory.ENTERPRISE_SECURITY,
            severity=Severity.WARNING if downgrades else Severity.INFO,
            title="EAP Method Analysis",
            description=f"EAP authentication method analysis from {len(self.eap_sessions)} sessions",
            details={
                "total_sessions": len(self.eap_sessions),
                "method_distribution": dict(method_usage.most_common()),
                "method_downgrades": downgrades if downgrades else None,
                "security_note": "Prefer strong methods like EAP-TLS over legacy methods"
            },
            analyzer_name=self.name,
            analyzer_version=self.version
        ))
        
        return findings
        
    def _analyze_security_vulnerabilities(self) -> List[Finding]:
        """Analyze detected security vulnerabilities."""
        findings = []
        
        # KRACK vulnerability analysis
        krack_nonce_reuse = len(self.known_vulnerabilities['krack']['nonce_reuse'])
        krack_key_reinstall = len(self.known_vulnerabilities['krack']['key_reinstall'])
        
        if krack_nonce_reuse > 0 or krack_key_reinstall > 0:
            findings.append(Finding(
                category=AnalysisCategory.SECURITY_THREATS,
                severity=Severity.CRITICAL,
                title="KRACK Vulnerability Indicators",
                description=f"Detected potential KRACK vulnerability indicators",
                details={
                    "nonce_reuse_instances": krack_nonce_reuse,
                    "key_reinstall_instances": krack_key_reinstall,
                    "description": "Key Reinstallation Attack (KRACK) vulnerability detected",
                    "impact": "Allows decryption of WPA2 traffic",
                    "recommendation": "Update all devices to patched versions immediately"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
        
        # PMF bypass attempts
        pmf_bypasses = sum(p.pmf_bypass_attempts for p in self.pmf_analysis.values())
        if pmf_bypasses > 0:
            findings.append(Finding(
                category=AnalysisCategory.SECURITY_THREATS,
                severity=Severity.WARNING,
                title="PMF Bypass Attempts Detected",
                description=f"Detected {pmf_bypasses} PMF bypass attempts",
                details={
                    "bypass_attempts": pmf_bypasses,
                    "description": "Attempts to send unprotected management frames when PMF is required",
                    "recommendation": "Ensure PMF is properly implemented and enforced"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
            
        return findings