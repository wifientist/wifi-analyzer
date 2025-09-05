"""
PyShark-based EAPOL/PMF Analysis for wireless PCAP data.

This analyzer provides comprehensive EAPOL (Extensible Authentication Protocol over LAN) 
and PMF (Protected Management Frames) analysis using native PyShark packet parsing including:
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

try:
    import pyshark
    from pyshark.packet.packet import Packet as PySharkPacket
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False
    PySharkPacket = None

from ....core.base_analyzer import BasePySharkAnalyzer
from ....core.models import (
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


class PySharkEAPOLPMFAnalyzer(BasePySharkAnalyzer):
    """
    PyShark-based comprehensive EAPOL/PMF Analyzer.
    
    This analyzer performs detailed analysis of EAPOL frames, 4-way handshakes,
    PMF implementation, and EAP authentication flows using native PyShark packet
    parsing to identify security issues, timing problems, and protocol violations.
    """
    
    def __init__(self):
        super().__init__(
            name="PyShark EAPOL/PMF Security Analyzer",
            category=AnalysisCategory.EAPOL_HANDSHAKE,
            version="1.0"
        )
        
        self.description = (
            "Analyzes EAPOL 4-way handshakes, PMF implementation, "
            "and EAP authentication security using PyShark"
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

    def is_applicable(self, packet: PySharkPacket) -> bool:
        """Check if packet is relevant for EAPOL/PMF analysis."""
        if not PYSHARK_AVAILABLE or packet is None:
            return False
            
        try:
            return (hasattr(packet, 'eapol') or 
                    hasattr(packet, 'eap') or
                    (hasattr(packet, 'wlan') and self._is_protected_mgmt_frame(packet)))
        except:
            return False
        
    def _is_protected_mgmt_frame(self, packet: PySharkPacket) -> bool:
        """Check if packet is a protected management frame using PyShark."""
        try:
            if not hasattr(packet, 'wlan') or not packet.wlan:
                return False
                
            wlan = packet.wlan
            
            # Check if frame is protected and management
            if (hasattr(wlan, 'fc_protected') and wlan.fc_protected == '1' and
                hasattr(wlan, 'fc_type') and wlan.fc_type == '0'):
                return True
        except:
            pass
        return False
        
    def get_display_filters(self) -> List[str]:
        """Get Wireshark display filters for EAPOL/PMF analysis."""
        return self.wireshark_filters
        
    def analyze(self, packets: List[PySharkPacket], context: AnalysisContext) -> List[Finding]:
        """
        Analyze EAPOL/PMF security aspects using PyShark.
        
        Args:
            packets: List of EAPOL/EAP/protected management packets
            context: Analysis context
            
        Returns:
            List of findings
        """
        if not PYSHARK_AVAILABLE:
            self.logger.warning("PyShark is not available, skipping analysis")
            return []
            
        if not packets:
            return []
            
        self.logger.info(f"Analyzing EAPOL/PMF security from {len(packets)} packets using PyShark")
        
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
            
    def _process_security_frames(self, packets: List[PySharkPacket]) -> None:
        """Process EAPOL and EAP frames using PyShark."""
        for packet in packets:
            try:
                if hasattr(packet, 'eapol'):
                    eapol_frame = self._extract_eapol_frame(packet)
                    if eapol_frame:
                        self.eapol_frames.append(eapol_frame)
                        self._process_eapol_frame(eapol_frame)
                        
                elif hasattr(packet, 'eap'):
                    self._process_eap_frame(packet)
                    
                # Track protected management frames
                if self._is_protected_mgmt_frame(packet):
                    self._process_protected_mgmt_frame(packet)
                    
            except Exception as e:
                self.logger.debug(f"Error processing security frame: {e}")
                continue
                
    def _extract_eapol_frame(self, packet: PySharkPacket) -> Optional[EAPOLFrame]:
        """Extract EAPOL frame information using PyShark."""
        try:
            if not hasattr(packet, 'eapol'):
                return None
                
            wlan = packet.wlan if hasattr(packet, 'wlan') else None
            eapol = packet.eapol
            
            # Get timestamp
            timestamp = float(packet.sniff_timestamp) if hasattr(packet, 'sniff_timestamp') else 0
            
            frame = EAPOLFrame(
                timestamp=timestamp,
                source_mac=wlan.sa if wlan and hasattr(wlan, 'sa') else "unknown",
                dest_mac=wlan.da if wlan and hasattr(wlan, 'da') else "unknown",
                frame_type=int(eapol.type) if hasattr(eapol, 'type') else 0
            )
            
            # Extract EAPOL-Key specific fields
            if frame.frame_type == 3:  # EAPOL-Key
                if hasattr(eapol, 'keydes_type'):
                    frame.message_type = int(eapol.keydes_type)
                if hasattr(eapol, 'keydes_key_info'):
                    frame.key_info = int(eapol.keydes_key_info, 16) if isinstance(eapol.keydes_key_info, str) else int(eapol.keydes_key_info)
                if hasattr(eapol, 'keydes_key_len'):
                    frame.key_length = int(eapol.keydes_key_len)
                if hasattr(eapol, 'keydes_replay_counter'):
                    frame.replay_counter = int(eapol.keydes_replay_counter, 16) if isinstance(eapol.keydes_replay_counter, str) else int(eapol.keydes_replay_counter)
                if hasattr(eapol, 'keydes_nonce'):
                    frame.nonce = bytes.fromhex(eapol.keydes_nonce.replace(':', '')) if hasattr(eapol.keydes_nonce, 'replace') else None
                if hasattr(eapol, 'keydes_key_iv'):
                    frame.key_iv = bytes.fromhex(eapol.keydes_key_iv.replace(':', '')) if hasattr(eapol.keydes_key_iv, 'replace') else None
                if hasattr(eapol, 'keydes_rsc'):
                    frame.rsc = int(eapol.keydes_rsc, 16) if isinstance(eapol.keydes_rsc, str) else int(eapol.keydes_rsc)
                if hasattr(eapol, 'keydes_key_id'):
                    frame.key_id = int(eapol.keydes_key_id, 16) if isinstance(eapol.keydes_key_id, str) else int(eapol.keydes_key_id)
                if hasattr(eapol, 'keydes_mic'):
                    frame.mic = bytes.fromhex(eapol.keydes_mic.replace(':', '')) if hasattr(eapol.keydes_mic, 'replace') else None
                if hasattr(eapol, 'keydes_data_len'):
                    frame.key_data_length = int(eapol.keydes_data_len)
                if hasattr(eapol, 'keydes_data'):
                    frame.key_data = bytes.fromhex(eapol.keydes_data.replace(':', '')) if hasattr(eapol.keydes_data, 'replace') else None
            
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
            
    def _process_eap_frame(self, packet: PySharkPacket) -> None:
        """Process EAP frame for session tracking using PyShark."""
        try:
            if not hasattr(packet, 'eap'):
                return
                
            wlan = packet.wlan if hasattr(packet, 'wlan') else None
            eap = packet.eap
            
            if not wlan:
                return
                
            session_key = f"{wlan.sa}:{wlan.da}"
            
            if session_key not in self.eap_sessions:
                timestamp = float(packet.sniff_timestamp) if hasattr(packet, 'sniff_timestamp') else 0
                self.eap_sessions[session_key] = EAPSession(
                    sta_mac=wlan.sa,
                    ap_mac=wlan.da,
                    session_id=session_key,
                    start_time=datetime.fromtimestamp(timestamp)
                )
                
            session = self.eap_sessions[session_key]
            
            # Analyze EAP method
            if hasattr(eap, 'type'):
                try:
                    method = EAPMethod(int(eap.type))
                    if method not in session.methods_attempted:
                        session.methods_attempted.append(method)
                except ValueError:
                    pass  # Unknown method type
                    
            # Track frame types
            if hasattr(eap, 'code'):
                code = int(eap.code)
                if code == 1:  # Request
                    if hasattr(eap, 'type') and int(eap.type) == 1:  # Identity
                        session.identity_requests += 1
                elif code == 2:  # Response
                    if hasattr(eap, 'type') and int(eap.type) == 1:  # Identity
                        session.identity_responses += 1
                    else:
                        session.challenge_responses += 1
                elif code == 3:  # Success
                    session.success_frames += 1
                    session.success = True
                elif code == 4:  # Failure
                    session.failure_frames += 1
                    
        except Exception as e:
            self.logger.debug(f"Error processing EAP frame: {e}")
            
    def _process_protected_mgmt_frame(self, packet: PySharkPacket) -> None:
        """Process protected management frame for PMF analysis using PyShark."""
        try:
            if not hasattr(packet, 'wlan') or not packet.wlan:
                return
                
            wlan = packet.wlan
            bssid = wlan.bssid if hasattr(wlan, 'bssid') else wlan.sa
            
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
                
    def _analyze_pmf_implementation(self, packets: List[PySharkPacket]) -> None:
        """Analyze PMF implementation and compliance using PyShark."""
        for packet in packets:
            if not hasattr(packet, 'wlan') or not packet.wlan:
                continue
                
            wlan = packet.wlan
            
            # Check for deauth/disassoc frames
            is_deauth = (hasattr(wlan, 'fc_type_subtype') and 
                        wlan.fc_type_subtype in ['12', '10'])  # Deauth or Disassoc
            
            if is_deauth:
                bssid = wlan.bssid if hasattr(wlan, 'bssid') else wlan.sa
                
                if bssid in self.pmf_analysis:
                    pmf_info = self.pmf_analysis[bssid]
                    
                    # Check if management frame is protected when PMF is required
                    is_protected = (hasattr(wlan, 'fc_protected') and 
                                  wlan.fc_protected == '1')
                    
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
            title="4-way Handshake Success Analysis (PyShark)",
            description=f"EAPOL handshake success rate: {success_rate:.1f}%",
            details={
                "total_handshakes": total_handshakes,
                "successful_handshakes": successful_handshakes,
                "failed_handshakes": total_handshakes - successful_handshakes,
                "success_rate_percentage": round(success_rate, 1),
                "failure_reasons": dict(failure_reasons.most_common(10)),
                "assessment": "POOR" if success_rate < 50 else 
                            "FAIR" if success_rate < 80 else "GOOD",
                "parser": "pyshark"
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
                title="4-way Handshake Timing Analysis (PyShark)",
                description=f"Handshake timing analysis from {len(total_times)} successful handshakes",
                details={
                    "total_analyzed": len(total_times),
                    "avg_handshake_time": round(avg_time, 3),
                    "max_handshake_time": round(max_time, 3),
                    "slow_handshakes": len(slow_handshakes),
                    "very_slow_handshakes": len(very_slow_handshakes),
                    "normal_threshold": self.NORMAL_HANDSHAKE_TIME,
                    "max_threshold": self.MAX_HANDSHAKE_TIME,
                    "parser": "pyshark"
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
                title="MIC Errors Detected (PyShark)",
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
                    ],
                    "parser": "pyshark"
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
                title="High EAPOL Message Retry Rates (PyShark)",
                description=f"Found {len(high_retry_handshakes)} handshakes with excessive retries",
                details={
                    "high_retry_handshakes": high_retry_handshakes[:10],
                    "total_retries_all_handshakes": total_retries,
                    "analysis": "High retry rates may indicate poor signal quality or processing delays",
                    "recommendation": "Investigate RF conditions and AP/client performance",
                    "parser": "pyshark"
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
            title="PMF (Protected Management Frames) Analysis (PyShark)",
            description=f"PMF implementation analysis across {len(self.pmf_analysis)} networks",
            details={
                "pmf_distribution": pmf_stats,
                "networks_analyzed": len(self.pmf_analysis),
                "pmf_violations": violation_details if violation_details else None,
                "recommendation": "Enable PMF (802.11w) for enhanced security" if pmf_stats["disabled"] > 0 else None,
                "parser": "pyshark"
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
            title="EAP Method Analysis (PyShark)",
            description=f"EAP authentication method analysis from {len(self.eap_sessions)} sessions",
            details={
                "total_sessions": len(self.eap_sessions),
                "method_distribution": dict(method_usage.most_common()),
                "method_downgrades": downgrades if downgrades else None,
                "security_note": "Prefer strong methods like EAP-TLS over legacy methods",
                "parser": "pyshark"
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
                title="KRACK Vulnerability Indicators (PyShark)",
                description=f"Detected potential KRACK vulnerability indicators",
                details={
                    "nonce_reuse_instances": krack_nonce_reuse,
                    "key_reinstall_instances": krack_key_reinstall,
                    "description": "Key Reinstallation Attack (KRACK) vulnerability detected",
                    "impact": "Allows decryption of WPA2 traffic",
                    "recommendation": "Update all devices to patched versions immediately",
                    "parser": "pyshark"
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
                title="PMF Bypass Attempts Detected (PyShark)",
                description=f"Detected {pmf_bypasses} PMF bypass attempts",
                details={
                    "bypass_attempts": pmf_bypasses,
                    "description": "Attempts to send unprotected management frames when PMF is required",
                    "recommendation": "Ensure PMF is properly implemented and enforced",
                    "parser": "pyshark"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
            
        return findings