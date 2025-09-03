"""
Authentication & Association Flow Analysis for wireless PCAP data.

This analyzer provides comprehensive authentication and association flow analysis including:
- Per-station connection ladder tracking (auth→assoc→4-way handshake)
- Authentication frame analysis with failure codes and retries
- Association/reassociation flow analysis
- Capability negotiation analysis
- Connection timing metrics and performance analysis
- 4-way handshake tracking and analysis
- Retry pattern analysis
- Connection failure root cause analysis
- Roaming and reassociation behavior
"""

import statistics
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Any, Set, Optional, NamedTuple, Tuple
import logging

from scapy.all import Packet
from scapy.layers.dot11 import (
    Dot11, Dot11Auth, Dot11AssoReq, Dot11AssoResp, Dot11ReassoReq, Dot11ReassoResp,
    Dot11Deauth, Dot11Disas, Dot11Elt
)
from scapy.layers.eap import EAPOL

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


class ConnectionState(Enum):
    """Connection state enumeration."""
    DISCONNECTED = "disconnected"
    AUTH_PENDING = "auth_pending"
    AUTHENTICATED = "authenticated"
    ASSOC_PENDING = "assoc_pending"
    ASSOCIATED = "associated"
    HANDSHAKE_PENDING = "handshake_pending"
    CONNECTED = "connected"
    FAILED = "failed"


class FrameType(Enum):
    """Frame type enumeration for connection flow."""
    AUTH_REQ = "auth_request"
    AUTH_RESP = "auth_response"
    ASSOC_REQ = "assoc_request"
    ASSOC_RESP = "assoc_response"
    REASSOC_REQ = "reassoc_request"
    REASSOC_RESP = "reassoc_response"
    EAPOL_1 = "eapol_1_of_4"
    EAPOL_2 = "eapol_2_of_4"
    EAPOL_3 = "eapol_3_of_4"
    EAPOL_4 = "eapol_4_of_4"
    DEAUTH = "deauthentication"
    DISASSOC = "disassociation"


@dataclass
class ConnectionFrame:
    """Individual frame in the connection process."""
    timestamp: float
    frame_type: FrameType
    source_mac: str
    dest_mac: str
    bssid: str
    sequence_number: Optional[int]
    retry_flag: bool
    status_code: Optional[int] = None
    reason_code: Optional[int] = None
    capabilities: Optional[int] = None
    supported_rates: List[str] = field(default_factory=list)
    rssi: Optional[int] = None
    channel: Optional[int] = None


@dataclass
class ConnectionAttempt:
    """Complete connection attempt tracking."""
    station_mac: str
    ap_bssid: str
    ap_ssid: str
    
    # Connection timeline
    start_time: datetime
    end_time: Optional[datetime] = None
    
    # Connection states and timing
    auth_start: Optional[datetime] = None
    auth_complete: Optional[datetime] = None
    assoc_start: Optional[datetime] = None
    assoc_complete: Optional[datetime] = None
    handshake_start: Optional[datetime] = None
    handshake_complete: Optional[datetime] = None
    
    # Current state
    current_state: ConnectionState = ConnectionState.DISCONNECTED
    final_state: ConnectionState = ConnectionState.DISCONNECTED
    
    # Frame tracking
    frames: List[ConnectionFrame] = field(default_factory=list)
    
    # Metrics
    auth_attempts: int = 0
    assoc_attempts: int = 0
    retry_count: int = 0
    total_duration: Optional[float] = None
    auth_duration: Optional[float] = None
    assoc_duration: Optional[float] = None
    handshake_duration: Optional[float] = None
    
    # Failure analysis
    failed: bool = False
    failure_reason: Optional[str] = None
    failure_code: Optional[int] = None
    failure_stage: Optional[str] = None
    
    # Capability analysis
    negotiated_capabilities: Optional[int] = None
    supported_rates_sta: List[str] = field(default_factory=list)
    supported_rates_ap: List[str] = field(default_factory=list)


@dataclass
class StationProfile:
    """Per-station connection behavior profile."""
    station_mac: str
    vendor_oui: Optional[str]
    
    # Connection attempts
    connection_attempts: List[ConnectionAttempt] = field(default_factory=list)
    successful_connections: int = 0
    failed_connections: int = 0
    
    # Timing statistics
    avg_connection_time: Optional[float] = None
    min_connection_time: Optional[float] = None
    max_connection_time: Optional[float] = None
    
    # Failure analysis
    common_failure_reasons: Counter = field(default_factory=Counter)
    retry_patterns: List[int] = field(default_factory=list)
    
    # Roaming behavior
    associated_aps: Set[str] = field(default_factory=set)
    roaming_events: int = 0
    
    # Capability patterns
    capability_consistency: bool = True
    rate_negotiations: List[Tuple[List[str], List[str]]] = field(default_factory=list)


class AuthAssocFlowAnalyzer(BaseAnalyzer):
    """
    Comprehensive Authentication & Association Flow Analyzer.
    
    This analyzer tracks complete connection flows from authentication through
    association to 4-way handshake, analyzing timing, failures, and patterns.
    """
    
    def __init__(self):
        super().__init__(
            name="Auth/Assoc Flow Analyzer",
            category=AnalysisCategory.AUTH_ASSOC,
            version="1.0"
        )
        
        self.description = (
            "Analyzes authentication and association flows including timing, "
            "failures, retries, and capability negotiation"
        )
        
        # Wireshark filters for auth/assoc analysis
        self.wireshark_filters = [
            "wlan.fc.type_subtype == 11",  # Authentication
            "wlan.fc.type_subtype == 0",   # Association Request
            "wlan.fc.type_subtype == 1",   # Association Response
            "wlan.fc.type_subtype == 2",   # Reassociation Request
            "wlan.fc.type_subtype == 3",   # Reassociation Response
            "wlan.fc.type_subtype == 12",  # Deauthentication
            "wlan.fc.type_subtype == 10",  # Disassociation
            "eapol"  # 4-way handshake
        ]
        
        self.analysis_order = 30  # Run after probe behavior analysis
        
        # State tracking
        self.connection_attempts: Dict[str, ConnectionAttempt] = {}  # Key: station_mac:bssid
        self.station_profiles: Dict[str, StationProfile] = {}
        
        # Status/reason code mappings
        self.STATUS_CODES = {
            0: "Success",
            1: "Unspecified failure",
            2: "Previous authentication no longer valid",
            5: "Cannot support all requested capabilities",
            6: "Reassociation denied due to inability to confirm association exists",
            7: "Association denied due to reason outside scope of standard",
            8: "Association denied due to unsupported authentication algorithm",
            9: "Association denied due to authentication sequence number out of expected sequence",
            10: "Association denied due to challenge failure",
            11: "Association denied due to authentication timeout",
            12: "Association denied due to inability to handle additional associated stations",
            13: "Association denied due to requesting station not supporting basic rates",
            17: "Association denied due to requesting station not supporting short preamble",
            18: "Association denied due to requesting station not supporting PBCC",
            19: "Association denied due to requesting station not supporting channel agility",
            22: "Association request rejected because of MIC failure",
            23: "Association request rejected because of 4-way handshake timeout",
            24: "Association request rejected because of Group Key Handshake timeout",
            25: "Association request rejected because of IE mismatch",
            26: "Association request rejected because of multicast cipher mismatch",
            27: "Association request rejected because of unicast cipher mismatch",
            28: "Association request rejected because of AKMP mismatch",
            29: "Association request rejected because of unsupported RSN IE version",
            30: "Association request rejected because of invalid RSN IE capabilities",
            31: "Association request rejected because of 802.1X authentication failed",
            32: "Association request rejected because of cipher suite rejected per security policy"
        }
        
        self.REASON_CODES = {
            1: "Unspecified reason",
            2: "Previous authentication no longer valid",
            3: "Deauthenticated because sending station is leaving",
            4: "Disassociated due to inactivity",
            5: "Disassociated because AP is unable to handle all currently associated stations",
            6: "Class 2 frame received from nonauthenticated station",
            7: "Class 3 frame received from nonassociated station",
            8: "Disassociated because sending station is leaving",
            9: "Station requesting (re)association is not authenticated",
            13: "Invalid information element",
            14: "MIC failure",
            15: "4-way handshake timeout",
            16: "Group Key Handshake timeout",
            17: "Information element in 4-way handshake different from (Re)Association Request",
            18: "Invalid multicast cipher",
            19: "Invalid unicast cipher", 
            20: "Invalid AKMP",
            21: "Unsupported RSN information element version",
            22: "Invalid RSN information element capabilities",
            23: "IEEE 802.1X authentication failed",
            24: "Cipher suite rejected because of the security policy"
        }
        
        # Timing thresholds
        self.NORMAL_AUTH_TIME = 0.1     # 100ms
        self.NORMAL_ASSOC_TIME = 0.2    # 200ms
        self.NORMAL_HANDSHAKE_TIME = 1.0 # 1 second
        self.CONNECTION_TIMEOUT = 30.0   # 30 seconds

    def is_applicable(self, packet: Packet) -> bool:
        """Check if packet is relevant for auth/assoc analysis."""
        return (packet_has_layer(packet, Dot11Auth) or 
                packet_has_layer(packet, Dot11AssoReq) or 
                packet_has_layer(packet, Dot11AssoResp) or
                packet_has_layer(packet, Dot11ReassoReq) or
                packet_has_layer(packet, Dot11ReassoResp) or
                packet_has_layer(packet, Dot11Deauth) or
                packet_has_layer(packet, Dot11Disas) or
                packet_has_layer(packet, EAPOL))
        
    def get_display_filters(self) -> List[str]:
        """Get Wireshark display filters for auth/assoc analysis."""
        return self.wireshark_filters
        
    def analyze(self, packets: List[Packet], context: AnalysisContext) -> List[Finding]:
        """
        Analyze authentication and association flows.
        
        Args:
            packets: List of auth/assoc related packets
            context: Analysis context
            
        Returns:
            List of findings
        """
        if not packets:
            return []
            
        self.logger.info(f"Analyzing auth/assoc flows from {len(packets)} packets")
        
        # Process packets to build connection flows
        self._process_connection_packets(packets)
        
        # Build station profiles
        self._build_station_profiles()
        
        # Finalize incomplete attempts
        self._finalize_connection_attempts()
        
        self.logger.info(f"Tracked {len(self.connection_attempts)} connection attempts from {len(self.station_profiles)} stations")
        
        # Generate findings
        findings = []
        findings.extend(self._analyze_connection_success_rates())
        findings.extend(self._analyze_connection_timing())
        findings.extend(self._analyze_failure_patterns())
        findings.extend(self._analyze_retry_behavior())
        findings.extend(self._analyze_capability_negotiation())
        findings.extend(self._analyze_roaming_behavior())
        
        # Store results in context
        context.metadata['auth_assoc_flows'] = {
            'connection_attempts': len(self.connection_attempts),
            'station_profiles': self.station_profiles,
            'success_rate': self._calculate_overall_success_rate(),
            'common_failures': self._get_common_failures()
        }
        
        self.findings_generated = len(findings)
        return findings
        
    def _process_connection_packets(self, packets: List[Packet]) -> None:
        """Process packets to build connection flow state machines."""
        for packet in packets:
            try:
                frame = self._extract_connection_frame(packet)
                if not frame:
                    continue
                    
                # Determine connection attempt key
                attempt_key = f"{frame.source_mac}:{frame.bssid}"
                if frame.frame_type in [FrameType.AUTH_RESP, FrameType.ASSOC_RESP, FrameType.REASSOC_RESP]:
                    # For responses, use dest_mac as station
                    attempt_key = f"{frame.dest_mac}:{frame.bssid}"
                
                # Get or create connection attempt
                if attempt_key not in self.connection_attempts:
                    station_mac = attempt_key.split(':')[0]
                    self.connection_attempts[attempt_key] = ConnectionAttempt(
                        station_mac=station_mac,
                        ap_bssid=frame.bssid,
                        ap_ssid="",  # Will be filled from beacon inventory if available
                        start_time=datetime.fromtimestamp(frame.timestamp)
                    )
                
                attempt = self.connection_attempts[attempt_key]
                attempt.frames.append(frame)
                
                # Update state machine
                self._update_connection_state(attempt, frame)
                
            except Exception as e:
                self.logger.debug(f"Error processing connection packet: {e}")
                continue
                
    def _extract_connection_frame(self, packet: Packet) -> Optional[ConnectionFrame]:
        """Extract connection frame information."""
        try:
            if not packet_has_layer(packet, Dot11):
                return None
                
            dot11 = get_packet_layer(packet, "Dot11")
            
            # Get timestamp
            timestamp = get_timestamp(packet) if hasattr(packet, 'time') else 0
            if hasattr(timestamp, '__float__'):
                timestamp = float(timestamp)
            elif hasattr(timestamp, 'val'):
                timestamp = float(timestamp.val)
            else:
                timestamp = float(timestamp)
            
            # Extract basic frame info
            source_mac = dot11.addr2 if dot11.addr2 else "unknown"
            dest_mac = dot11.addr1 if dot11.addr1 else "unknown"
            bssid = dot11.addr3 if dot11.addr3 else "unknown"
            sequence_number = dot11.SC if hasattr(dot11, 'SC') else None
            retry_flag = bool(dot11.FCfield & 0x08) if hasattr(dot11, 'FCfield') else False
            
            # Determine frame type and extract specific info
            frame_type = None
            status_code = None
            reason_code = None
            capabilities = None
            supported_rates = []
            
            if packet_has_layer(packet, Dot11Auth):
                auth = get_packet_layer(packet, "Dot11Auth")
                if dot11.addr1 == bssid:  # Request (STA -> AP)
                    frame_type = FrameType.AUTH_REQ
                else:  # Response (AP -> STA)
                    frame_type = FrameType.AUTH_RESP
                status_code = auth.status if hasattr(auth, 'status') else None
                
            elif packet_has_layer(packet, Dot11AssoReq):
                frame_type = FrameType.ASSOC_REQ
                assoc_req = get_packet_layer(packet, "Dot11AssoReq")
                capabilities = assoc_req.cap if hasattr(assoc_req, 'cap') else None
                supported_rates = self._extract_supported_rates(packet)
                
            elif packet_has_layer(packet, Dot11AssoResp):
                frame_type = FrameType.ASSOC_RESP
                assoc_resp = get_packet_layer(packet, "Dot11AssoResp")
                status_code = assoc_resp.status if hasattr(assoc_resp, 'status') else None
                capabilities = assoc_resp.cap if hasattr(assoc_resp, 'cap') else None
                supported_rates = self._extract_supported_rates(packet)
                
            elif packet_has_layer(packet, Dot11ReassoReq):
                frame_type = FrameType.REASSOC_REQ
                reassoc_req = get_packet_layer(packet, "Dot11ReassoReq")
                capabilities = reassoc_req.cap if hasattr(reassoc_req, 'cap') else None
                supported_rates = self._extract_supported_rates(packet)
                
            elif packet_has_layer(packet, Dot11ReassoResp):
                frame_type = FrameType.REASSOC_RESP
                reassoc_resp = get_packet_layer(packet, "Dot11ReassoResp")
                status_code = reassoc_resp.status if hasattr(reassoc_resp, 'status') else None
                capabilities = reassoc_resp.cap if hasattr(reassoc_resp, 'cap') else None
                supported_rates = self._extract_supported_rates(packet)
                
            elif packet_has_layer(packet, Dot11Deauth):
                frame_type = FrameType.DEAUTH
                deauth = get_packet_layer(packet, "Dot11Deauth")
                reason_code = deauth.reason if hasattr(deauth, 'reason') else None
                
            elif packet_has_layer(packet, Dot11Disas):
                frame_type = FrameType.DISASSOC
                disas = get_packet_layer(packet, "Dot11Disas")
                reason_code = disas.reason if hasattr(disas, 'reason') else None
                
            elif packet_has_layer(packet, EAPOL):
                eapol = get_packet_layer(packet, "EAPOL")
                # Determine EAPOL message type (simplified)
                if hasattr(eapol, 'type') and get_packet_field(packet, "Dot11", "type") == 3:  # Key frame
                    # This is a simplified classification - more detailed analysis would examine key info
                    frame_type = FrameType.EAPOL_1  # Default to first message
                else:
                    return None
                    
            if frame_type is None:
                return None
            
            # Extract RSSI if available
            rssi = None
            if hasattr(packet, 'haslayer') and packet_has_layer(packet, 'RadioTap'):
                try:
                    from scapy.layers.dot11 import RadioTap
                    if packet_has_layer(packet, RadioTap):
                        radiotap = get_packet_layer(packet, "RadioTap")
                        if hasattr(radiotap, 'dBm_AntSignal'):
                            rssi = radiotap.dBm_AntSignal
                except:
                    pass
            
            return ConnectionFrame(
                timestamp=timestamp,
                frame_type=frame_type,
                source_mac=source_mac,
                dest_mac=dest_mac,
                bssid=bssid,
                sequence_number=sequence_number,
                retry_flag=retry_flag,
                status_code=status_code,
                reason_code=reason_code,
                capabilities=capabilities,
                supported_rates=supported_rates,
                rssi=rssi
            )
            
        except Exception as e:
            self.logger.debug(f"Error extracting connection frame: {e}")
            return None
            
    def _extract_supported_rates(self, packet: Packet) -> List[str]:
        """Extract supported rates from packet IEs."""
        rates = []
        
        if packet_has_layer(packet, Dot11Elt):
            current_ie = get_packet_layer(packet, "Dot11Elt")
            while current_ie:
                if current_ie.ID == 1:  # Supported Rates
                    ie_data = bytes(current_ie.info) if current_ie.info else b''
                    for byte_val in ie_data:
                        rate_500k = byte_val & 0x7F
                        rate_mbps = rate_500k * 0.5
                        rates.append(f"{rate_mbps:.1f}")
                elif current_ie.ID == 50:  # Extended Supported Rates
                    ie_data = bytes(current_ie.info) if current_ie.info else b''
                    for byte_val in ie_data:
                        rate_500k = byte_val & 0x7F
                        rate_mbps = rate_500k * 0.5
                        rates.append(f"{rate_mbps:.1f}")
                        
                current_ie = current_ie.payload if hasattr(current_ie, 'payload') and isinstance(current_ie.payload, Dot11Elt) else None
        
        return rates
        
    def _update_connection_state(self, attempt: ConnectionAttempt, frame: ConnectionFrame) -> None:
        """Update connection attempt state machine."""
        frame_time = datetime.fromtimestamp(frame.timestamp)
        
        if frame.retry_flag:
            attempt.retry_count += 1
        
        # State transitions based on frame type
        if frame.frame_type == FrameType.AUTH_REQ:
            if attempt.current_state == ConnectionState.DISCONNECTED:
                attempt.current_state = ConnectionState.AUTH_PENDING
                attempt.auth_start = frame_time
            attempt.auth_attempts += 1
            
        elif frame.frame_type == FrameType.AUTH_RESP:
            if frame.status_code == 0:  # Success
                attempt.current_state = ConnectionState.AUTHENTICATED
                attempt.auth_complete = frame_time
                if attempt.auth_start:
                    attempt.auth_duration = (frame_time - attempt.auth_start).total_seconds()
            else:
                attempt.failed = True
                attempt.failure_reason = self.STATUS_CODES.get(frame.status_code, f"Status {frame.status_code}")
                attempt.failure_code = frame.status_code
                attempt.failure_stage = "authentication"
                attempt.final_state = ConnectionState.FAILED
                
        elif frame.frame_type in [FrameType.ASSOC_REQ, FrameType.REASSOC_REQ]:
            if attempt.current_state == ConnectionState.AUTHENTICATED:
                attempt.current_state = ConnectionState.ASSOC_PENDING
                attempt.assoc_start = frame_time
                if frame.supported_rates:
                    attempt.supported_rates_sta = frame.supported_rates
                if frame.capabilities:
                    attempt.negotiated_capabilities = frame.capabilities
            attempt.assoc_attempts += 1
            
        elif frame.frame_type in [FrameType.ASSOC_RESP, FrameType.REASSOC_RESP]:
            if frame.status_code == 0:  # Success
                attempt.current_state = ConnectionState.ASSOCIATED
                attempt.assoc_complete = frame_time
                if attempt.assoc_start:
                    attempt.assoc_duration = (frame_time - attempt.assoc_start).total_seconds()
                if frame.supported_rates:
                    attempt.supported_rates_ap = frame.supported_rates
            else:
                attempt.failed = True
                attempt.failure_reason = self.STATUS_CODES.get(frame.status_code, f"Status {frame.status_code}")
                attempt.failure_code = frame.status_code
                attempt.failure_stage = "association"
                attempt.final_state = ConnectionState.FAILED
                
        elif frame.frame_type == FrameType.EAPOL_1:
            if attempt.current_state == ConnectionState.ASSOCIATED:
                attempt.current_state = ConnectionState.HANDSHAKE_PENDING
                attempt.handshake_start = frame_time
                
        elif frame.frame_type == FrameType.EAPOL_4:
            if attempt.current_state == ConnectionState.HANDSHAKE_PENDING:
                attempt.current_state = ConnectionState.CONNECTED
                attempt.handshake_complete = frame_time
                if attempt.handshake_start:
                    attempt.handshake_duration = (frame_time - attempt.handshake_start).total_seconds()
                attempt.final_state = ConnectionState.CONNECTED
                
        elif frame.frame_type in [FrameType.DEAUTH, FrameType.DISASSOC]:
            attempt.failed = True
            attempt.failure_reason = self.REASON_CODES.get(frame.reason_code, f"Reason {frame.reason_code}")
            attempt.failure_code = frame.reason_code
            attempt.failure_stage = "disconnection"
            attempt.final_state = ConnectionState.FAILED
            
        # Update end time
        attempt.end_time = frame_time
        
    def _build_station_profiles(self) -> None:
        """Build comprehensive station profiles from connection attempts."""
        station_attempts = defaultdict(list)
        
        # Group attempts by station
        for attempt in self.connection_attempts.values():
            station_attempts[attempt.station_mac].append(attempt)
            
        # Build profile for each station
        for station_mac, attempts in station_attempts.items():
            profile = StationProfile(
                station_mac=station_mac,
                vendor_oui=self._extract_vendor_oui(station_mac)
            )
            
            profile.connection_attempts = attempts
            profile.successful_connections = sum(1 for a in attempts if a.final_state == ConnectionState.CONNECTED)
            profile.failed_connections = sum(1 for a in attempts if a.failed)
            
            # Calculate timing statistics
            successful_durations = []
            for attempt in attempts:
                if attempt.final_state == ConnectionState.CONNECTED and attempt.total_duration:
                    successful_durations.append(attempt.total_duration)
                    
                # Track failure reasons
                if attempt.failed and attempt.failure_reason:
                    profile.common_failure_reasons[attempt.failure_reason] += 1
                    
                # Track retry patterns
                profile.retry_patterns.append(attempt.retry_count)
                
                # Track associated APs
                profile.associated_aps.add(attempt.ap_bssid)
                
            if successful_durations:
                profile.avg_connection_time = statistics.mean(successful_durations)
                profile.min_connection_time = min(successful_durations)
                profile.max_connection_time = max(successful_durations)
                
            # Detect roaming
            profile.roaming_events = len(profile.associated_aps) - 1 if len(profile.associated_aps) > 1 else 0
            
            self.station_profiles[station_mac] = profile
            
    def _finalize_connection_attempts(self) -> None:
        """Finalize incomplete connection attempts."""
        current_time = datetime.now()
        
        for attempt in self.connection_attempts.values():
            if not attempt.end_time:
                attempt.end_time = attempt.start_time + timedelta(seconds=self.CONNECTION_TIMEOUT)
                
            # Calculate total duration
            if attempt.start_time and attempt.end_time:
                attempt.total_duration = (attempt.end_time - attempt.start_time).total_seconds()
                
            # Mark timed-out attempts as failed
            if (attempt.final_state not in [ConnectionState.CONNECTED, ConnectionState.FAILED] and 
                attempt.total_duration and attempt.total_duration > self.CONNECTION_TIMEOUT):
                attempt.failed = True
                attempt.failure_reason = "Connection timeout"
                attempt.failure_stage = "timeout"
                attempt.final_state = ConnectionState.FAILED
                
    def _extract_vendor_oui(self, mac: str) -> Optional[str]:
        """Extract vendor OUI from MAC address."""
        try:
            parts = mac.split(':')
            if len(parts) >= 3:
                return ':'.join(parts[:3]).upper()
        except:
            pass
        return None
        
    # Analysis methods for generating findings
    
    def _analyze_connection_success_rates(self) -> List[Finding]:
        """Analyze connection success rates and patterns."""
        findings = []
        
        if not self.station_profiles:
            return findings
            
        # Calculate overall statistics
        total_attempts = len(self.connection_attempts)
        successful_attempts = sum(1 for a in self.connection_attempts.values() 
                                if a.final_state == ConnectionState.CONNECTED)
        overall_success_rate = (successful_attempts / total_attempts * 100) if total_attempts > 0 else 0
        
        # Station-specific success rates
        low_success_stations = []
        for mac, profile in self.station_profiles.items():
            total = profile.successful_connections + profile.failed_connections
            if total > 0:
                success_rate = (profile.successful_connections / total) * 100
                if success_rate < 50 and total >= 3:  # At least 3 attempts
                    low_success_stations.append({
                        "station_mac": mac,
                        "success_rate": round(success_rate, 1),
                        "successful": profile.successful_connections,
                        "failed": profile.failed_connections,
                        "vendor_oui": profile.vendor_oui
                    })
        
        # Overall success rate finding
        severity = Severity.CRITICAL if overall_success_rate < 50 else \
                  Severity.WARNING if overall_success_rate < 80 else Severity.INFO
                  
        findings.append(Finding(
            category=AnalysisCategory.AUTH_ASSOC,
            severity=severity,
            title="Connection Success Rate Analysis",
            description=f"Overall connection success rate: {overall_success_rate:.1f}%",
            details={
                "total_attempts": total_attempts,
                "successful_attempts": successful_attempts,
                "failed_attempts": total_attempts - successful_attempts,
                "success_rate_percentage": round(overall_success_rate, 1),
                "unique_stations": len(self.station_profiles),
                "assessment": "POOR" if overall_success_rate < 50 else 
                            "FAIR" if overall_success_rate < 80 else "GOOD"
            },
            analyzer_name=self.name,
            analyzer_version=self.version
        ))
        
        if low_success_stations:
            findings.append(Finding(
                category=AnalysisCategory.AUTH_ASSOC,
                severity=Severity.WARNING,
                title="Stations with Low Connection Success Rates",
                description=f"Found {len(low_success_stations)} stations with poor connection success",
                details={
                    "problematic_stations": low_success_stations,
                    "recommendation": "Investigate signal quality, authentication issues, or client problems"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
            
        return findings
        
    def _analyze_connection_timing(self) -> List[Finding]:
        """Analyze connection timing and performance."""
        findings = []
        
        # Collect timing metrics
        auth_times = []
        assoc_times = []
        handshake_times = []
        total_times = []
        
        for attempt in self.connection_attempts.values():
            if attempt.auth_duration is not None:
                auth_times.append(attempt.auth_duration)
            if attempt.assoc_duration is not None:
                assoc_times.append(attempt.assoc_duration)
            if attempt.handshake_duration is not None:
                handshake_times.append(attempt.handshake_duration)
            if attempt.total_duration is not None and attempt.final_state == ConnectionState.CONNECTED:
                total_times.append(attempt.total_duration)
        
        # Analyze timing performance
        timing_issues = []
        
        if auth_times:
            avg_auth = statistics.mean(auth_times)
            max_auth = max(auth_times)
            if avg_auth > self.NORMAL_AUTH_TIME * 2:
                timing_issues.append({
                    "stage": "Authentication",
                    "avg_time": round(avg_auth, 3),
                    "max_time": round(max_auth, 3),
                    "threshold": self.NORMAL_AUTH_TIME,
                    "issue": "Slow authentication responses"
                })
        
        if assoc_times:
            avg_assoc = statistics.mean(assoc_times)
            max_assoc = max(assoc_times)
            if avg_assoc > self.NORMAL_ASSOC_TIME * 2:
                timing_issues.append({
                    "stage": "Association",
                    "avg_time": round(avg_assoc, 3),
                    "max_time": round(max_assoc, 3),
                    "threshold": self.NORMAL_ASSOC_TIME,
                    "issue": "Slow association processing"
                })
        
        if handshake_times:
            avg_handshake = statistics.mean(handshake_times)
            max_handshake = max(handshake_times)
            if avg_handshake > self.NORMAL_HANDSHAKE_TIME * 2:
                timing_issues.append({
                    "stage": "4-way Handshake",
                    "avg_time": round(avg_handshake, 3),
                    "max_time": round(max_handshake, 3),
                    "threshold": self.NORMAL_HANDSHAKE_TIME,
                    "issue": "Slow 4-way handshake completion"
                })
        
        if timing_issues:
            findings.append(Finding(
                category=AnalysisCategory.AUTH_ASSOC,
                severity=Severity.WARNING,
                title="Connection Timing Performance Issues",
                description=f"Found {len(timing_issues)} stages with timing performance issues",
                details={
                    "timing_issues": timing_issues,
                    "recommendation": "Investigate AP processing delays, network congestion, or client issues"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
        
        # Overall timing summary
        if total_times:
            findings.append(Finding(
                category=AnalysisCategory.AUTH_ASSOC,
                severity=Severity.INFO,
                title="Connection Timing Analysis",
                description=f"Connection timing analysis from {len(total_times)} successful connections",
                details={
                    "successful_connections": len(total_times),
                    "avg_connection_time": round(statistics.mean(total_times), 3),
                    "min_connection_time": round(min(total_times), 3),
                    "max_connection_time": round(max(total_times), 3),
                    "median_connection_time": round(statistics.median(total_times), 3),
                    "timing_breakdown": {
                        "avg_auth_time": round(statistics.mean(auth_times), 3) if auth_times else None,
                        "avg_assoc_time": round(statistics.mean(assoc_times), 3) if assoc_times else None,
                        "avg_handshake_time": round(statistics.mean(handshake_times), 3) if handshake_times else None
                    }
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
        
        return findings
        
    def _analyze_failure_patterns(self) -> List[Finding]:
        """Analyze connection failure patterns and root causes."""
        findings = []
        
        # Collect failure statistics
        failure_stages = Counter()
        failure_reasons = Counter()
        failure_codes = Counter()
        
        for attempt in self.connection_attempts.values():
            if attempt.failed:
                if attempt.failure_stage:
                    failure_stages[attempt.failure_stage] += 1
                if attempt.failure_reason:
                    failure_reasons[attempt.failure_reason] += 1
                if attempt.failure_code:
                    failure_codes[attempt.failure_code] += 1
        
        if not failure_reasons:
            return findings
            
        # Analyze failure patterns
        total_failures = sum(failure_reasons.values())
        top_failure_reasons = failure_reasons.most_common(10)
        
        findings.append(Finding(
            category=AnalysisCategory.AUTH_ASSOC,
            severity=Severity.WARNING,
            title="Connection Failure Analysis",
            description=f"Analysis of {total_failures} connection failures",
            details={
                "total_failures": total_failures,
                "failure_stages": dict(failure_stages),
                "top_failure_reasons": [
                    {"reason": reason, "count": count, "percentage": round(count/total_failures*100, 1)}
                    for reason, count in top_failure_reasons
                ],
                "failure_codes": dict(failure_codes.most_common(10))
            },
            analyzer_name=self.name,
            analyzer_version=self.version
        ))
        
        # Identify critical failure patterns
        critical_failures = []
        for reason, count in top_failure_reasons:
            percentage = (count / total_failures) * 100
            if percentage > 20:  # More than 20% of failures
                critical_failures.append({
                    "reason": reason,
                    "count": count,
                    "percentage": round(percentage, 1),
                    "impact": "HIGH"
                })
        
        if critical_failures:
            findings.append(Finding(
                category=AnalysisCategory.AUTH_ASSOC,
                severity=Severity.CRITICAL,
                title="Critical Connection Failure Patterns",
                description=f"Found {len(critical_failures)} dominant failure patterns",
                details={
                    "critical_patterns": critical_failures,
                    "recommendation": "Address these primary failure causes to improve connection success"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
        
        return findings
        
    def _analyze_retry_behavior(self) -> List[Finding]:
        """Analyze retry patterns and behavior."""
        findings = []
        
        # Collect retry statistics
        retry_counts = []
        high_retry_attempts = []
        
        for attempt in self.connection_attempts.values():
            retry_counts.append(attempt.retry_count)
            if attempt.retry_count > 5:  # High retry threshold
                high_retry_attempts.append({
                    "station_mac": attempt.station_mac,
                    "ap_bssid": attempt.ap_bssid,
                    "retry_count": attempt.retry_count,
                    "auth_attempts": attempt.auth_attempts,
                    "assoc_attempts": attempt.assoc_attempts,
                    "final_state": attempt.final_state.value,
                    "failure_reason": attempt.failure_reason
                })
        
        if retry_counts:
            avg_retries = statistics.mean(retry_counts)
            max_retries = max(retry_counts)
            
            findings.append(Finding(
                category=AnalysisCategory.AUTH_ASSOC,
                severity=Severity.WARNING if avg_retries > 2 else Severity.INFO,
                title="Retry Behavior Analysis",
                description=f"Connection retry pattern analysis",
                details={
                    "total_connection_attempts": len(retry_counts),
                    "avg_retries": round(avg_retries, 1),
                    "max_retries": max_retries,
                    "high_retry_attempts": len(high_retry_attempts),
                    "retry_distribution": dict(Counter(retry_counts).most_common(10))
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
        
        if high_retry_attempts:
            findings.append(Finding(
                category=AnalysisCategory.AUTH_ASSOC,
                severity=Severity.WARNING,
                title="High Retry Connection Attempts",
                description=f"Found {len(high_retry_attempts)} attempts with excessive retries",
                details={
                    "high_retry_attempts": high_retry_attempts[:10],  # Top 10
                    "analysis": "High retry counts may indicate poor signal quality or AP overload",
                    "recommendation": "Investigate RF conditions and AP capacity"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
        
        return findings
        
    def _analyze_capability_negotiation(self) -> List[Finding]:
        """Analyze capability negotiation patterns."""
        findings = []
        
        # Analyze capability negotiations
        capability_mismatches = []
        rate_negotiations = []
        
        for attempt in self.connection_attempts.values():
            if attempt.supported_rates_sta and attempt.supported_rates_ap:
                sta_rates = set(attempt.supported_rates_sta)
                ap_rates = set(attempt.supported_rates_ap)
                
                # Check for rate compatibility
                common_rates = sta_rates.intersection(ap_rates)
                if len(common_rates) < 2:  # Very few common rates
                    rate_negotiations.append({
                        "station_mac": attempt.station_mac,
                        "ap_bssid": attempt.ap_bssid,
                        "sta_rates": sorted(attempt.supported_rates_sta),
                        "ap_rates": sorted(attempt.supported_rates_ap),
                        "common_rates": sorted(list(common_rates)),
                        "issue": "Limited rate compatibility"
                    })
        
        if rate_negotiations:
            findings.append(Finding(
                category=AnalysisCategory.AUTH_ASSOC,
                severity=Severity.WARNING,
                title="Rate Negotiation Issues",
                description=f"Found {len(rate_negotiations)} connections with limited rate compatibility",
                details={
                    "problematic_negotiations": rate_negotiations[:10],
                    "recommendation": "Review AP and client rate configurations for optimal compatibility"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
        
        return findings
        
    def _analyze_roaming_behavior(self) -> List[Finding]:
        """Analyze roaming and reassociation behavior."""
        findings = []
        
        # Identify roaming stations
        roaming_stations = [
            (mac, profile) for mac, profile in self.station_profiles.items()
            if profile.roaming_events > 0
        ]
        
        if roaming_stations:
            roaming_stations.sort(key=lambda x: x[1].roaming_events, reverse=True)
            
            findings.append(Finding(
                category=AnalysisCategory.AUTH_ASSOC,
                severity=Severity.INFO,
                title="Client Roaming Behavior Analysis",
                description=f"Found {len(roaming_stations)} stations with roaming behavior",
                details={
                    "roaming_clients": [
                        {
                            "station_mac": mac,
                            "roaming_events": profile.roaming_events,
                            "associated_aps": list(profile.associated_aps),
                            "total_attempts": len(profile.connection_attempts),
                            "vendor_oui": profile.vendor_oui
                        }
                        for mac, profile in roaming_stations[:10]
                    ],
                    "note": "Roaming behavior indicates client mobility or AP selection optimization"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
        
        return findings
        
    def _calculate_overall_success_rate(self) -> float:
        """Calculate overall connection success rate."""
        if not self.connection_attempts:
            return 0.0
            
        successful = sum(1 for a in self.connection_attempts.values() 
                        if a.final_state == ConnectionState.CONNECTED)
        total = len(self.connection_attempts)
        return (successful / total) * 100
        
    def _get_common_failures(self) -> Dict[str, int]:
        """Get common failure reasons."""
        failure_reasons = Counter()
        for attempt in self.connection_attempts.values():
            if attempt.failed and attempt.failure_reason:
                failure_reasons[attempt.failure_reason] += 1
        return dict(failure_reasons.most_common(10))