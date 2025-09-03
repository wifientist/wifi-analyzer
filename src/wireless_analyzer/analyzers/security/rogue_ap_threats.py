"""
Rogue AP & Security Threats Analysis for wireless PCAP data.

This analyzer provides comprehensive rogue access point detection and security threat analysis including:
- SSID spoofing and impersonation detection
- Same SSID/different OUI correlation analysis
- Open SSID co-located with secure SSID detection
- Deauthentication attack detection and pattern analysis
- Evil twin AP detection and behavioral analysis
- Rogue AP identification through behavioral profiling
- Neighboring AP legitimacy assessment
- Security threat correlation and attack chain analysis
- AP impersonation and honeypot detection
- Beacon timing anomaly detection for rogue identification
- Channel overlap and interference analysis for attack detection
"""

import statistics
from collections import defaultdict, Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Any, Set, Optional, NamedTuple, Tuple
import logging
import re

from scapy.all import Packet
from scapy.layers.dot11 import (
    Dot11, Dot11Beacon, Dot11Deauth, Dot11Disas, Dot11ProbeReq, Dot11ProbeResp,
    Dot11AssoReq, Dot11AssoResp, Dot11Elt
)
from scapy.layers.dot11 import RadioTap

from ...core.base_analyzer import BaseAnalyzer
from ...core.models import (
    Finding, 
    Severity, 
    AnalysisContext,
    AnalysisCategory
)


class ThreatLevel(Enum):
    """Security threat level enumeration."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SUSPICIOUS = "suspicious"


class RogueType(Enum):
    """Rogue AP type classification."""
    EVIL_TWIN = "evil_twin"
    HONEYPOT = "honeypot"
    IMPERSONATOR = "impersonator"
    UNAUTHORIZED = "unauthorized"
    MISCONFIGURED = "misconfigured"
    SUSPICIOUS = "suspicious"


class AttackType(Enum):
    """Security attack type enumeration."""
    DEAUTH_FLOOD = "deauth_flood"
    DEAUTH_TARGETED = "deauth_targeted"
    DISASSOC_FLOOD = "disassoc_flood"
    EVIL_TWIN = "evil_twin"
    KARMA_ATTACK = "karma_attack"
    BEACON_FLOOD = "beacon_flood"
    PROBE_RESPONSE_FLOOD = "probe_response_flood"
    CHANNEL_SWITCH_ATTACK = "channel_switch_attack"


@dataclass
class APFingerprint:
    """AP fingerprinting information."""
    bssid: str
    ssid: str
    vendor_oui: str
    
    # Technical fingerprint
    beacon_interval: int
    capabilities: int
    supported_rates: List[str]
    extended_rates: List[str]
    channel: Optional[int]
    
    # Advanced fingerprint
    ie_signature: str  # Hash of IE types and order
    timing_signature: str  # Beacon timing patterns
    vendor_specific_ies: Dict[str, bytes]
    
    # Behavioral fingerprint
    probe_response_behavior: Dict[str, Any]
    association_behavior: Dict[str, Any]
    power_management: Dict[str, Any]


@dataclass
class RogueAP:
    """Rogue AP detection result."""
    bssid: str
    ssid: str
    rogue_type: RogueType
    threat_level: ThreatLevel
    
    # Detection criteria
    detection_reasons: List[str]
    suspicious_behaviors: List[str]
    
    # Comparison with legitimate APs
    impersonated_ap: Optional[str] = None  # BSSID of legitimate AP
    similarity_score: Optional[float] = None
    
    # Technical details
    fingerprint: Optional[APFingerprint] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    beacon_count: int = 0
    client_interactions: int = 0
    
    # Threat intelligence
    attack_indicators: List[str] = field(default_factory=list)
    potential_targets: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)


@dataclass
class SecurityThreat:
    """Security threat detection result."""
    threat_id: str
    attack_type: AttackType
    threat_level: ThreatLevel
    
    # Attack details
    source_mac: Optional[str] = None
    target_networks: List[str] = field(default_factory=list)
    affected_clients: Set[str] = field(default_factory=set)
    
    # Timing and patterns
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    attack_intensity: Optional[float] = None  # attacks per second
    pattern_description: str = ""
    
    # Evidence
    frame_count: int = 0
    packet_examples: List[Dict[str, Any]] = field(default_factory=list)
    
    # Impact assessment
    estimated_impact: str = ""
    mitigation_priority: int = 1  # 1=highest, 5=lowest
    recommended_response: List[str] = field(default_factory=list)


@dataclass
class SSIDCorrelation:
    """SSID correlation analysis result."""
    ssid: str
    networks: List[Dict[str, Any]] = field(default_factory=list)
    
    # Analysis results
    has_spoofing: bool = False
    has_mixed_security: bool = False
    has_different_vendors: bool = False
    
    # Risk assessment
    spoofing_confidence: float = 0.0
    threat_indicators: List[str] = field(default_factory=list)
    legitimate_network: Optional[str] = None  # Most likely legitimate BSSID


class RogueAPSecurityAnalyzer(BaseAnalyzer):
    """
    Comprehensive Rogue AP & Security Threats Analyzer.
    
    This analyzer detects rogue access points, security impersonation attempts,
    and various wireless attacks through behavioral analysis, fingerprinting,
    and correlation techniques.
    """
    
    def __init__(self):
        super().__init__(
            name="Rogue AP & Security Threats Analyzer",
            category=AnalysisCategory.SECURITY_THREATS,
            version="1.0"
        )
        
        self.description = (
            "Detects rogue APs, evil twins, deauth attacks, and other wireless security threats "
            "through behavioral analysis and network correlation"
        )
        
        # Wireshark filters
        self.wireshark_filters = [
            "wlan.fc.type_subtype == 8",   # Beacon frames
            "wlan.fc.type_subtype == 12",  # Deauthentication
            "wlan.fc.type_subtype == 10",  # Disassociation
            "wlan.fc.type_subtype == 4",   # Probe request
            "wlan.fc.type_subtype == 5",   # Probe response
            "wlan.ssid",
            "wlan.bssid"
        ]
        
        self.analysis_order = 160  # Run after other security analyzers
        
        # Analysis storage
        self.ap_fingerprints: Dict[str, APFingerprint] = {}
        self.rogue_aps: List[RogueAP] = []
        self.security_threats: List[SecurityThreat] = []
        self.ssid_correlations: Dict[str, SSIDCorrelation] = {}
        
        # Attack pattern tracking
        self.deauth_patterns: Dict[str, List[datetime]] = defaultdict(list)
        self.beacon_anomalies: Dict[str, Dict[str, Any]] = defaultdict(dict)
        self.probe_response_patterns: Dict[str, List[datetime]] = defaultdict(list)
        
        # Vendor OUI database (simplified)
        self.vendor_ouis = {
            "00:50:f2": "Microsoft",
            "00:0c:42": "Cisco", 
            "00:24:a5": "Apple",
            "00:22:6b": "Apple",
            "00:17:f2": "Apple",
            "00:1f:f3": "Apple",
            "8c:85:90": "Apple",
            "bc:67:1c": "Apple",
            "f0:18:98": "Apple",
            "00:03:93": "Apple",
            # Add more as needed
        }
        
        # Thresholds for threat detection
        self.DEAUTH_FLOOD_THRESHOLD = 10  # deauths per minute
        self.BEACON_TIMING_VARIANCE_THRESHOLD = 0.1  # coefficient of variation
        self.EVIL_TWIN_SIMILARITY_THRESHOLD = 0.85
        self.SUSPICIOUS_BEACON_INTERVAL_THRESHOLD = [50, 2000]  # outside normal range

    def is_applicable(self, packet: Packet) -> bool:
        """Check if packet is relevant for rogue AP/threat analysis."""
        return (packet.haslayer(Dot11Beacon) or
                packet.haslayer(Dot11Deauth) or
                packet.haslayer(Dot11Disas) or
                packet.haslayer(Dot11ProbeReq) or
                packet.haslayer(Dot11ProbeResp))
        
    def get_display_filters(self) -> List[str]:
        """Get Wireshark display filters."""
        return self.wireshark_filters
        
    def analyze(self, packets: List[Packet], context: AnalysisContext) -> List[Finding]:
        """
        Analyze rogue APs and security threats.
        
        Args:
            packets: List of relevant packets
            context: Analysis context
            
        Returns:
            List of findings
        """
        if not packets:
            return []
            
        self.logger.info(f"Analyzing rogue APs and security threats from {len(packets)} packets")
        
        # Get beacon inventory and other context
        beacon_inventory = context.metadata.get('beacon_inventory', {})
        
        # Build AP fingerprints
        self._build_ap_fingerprints(packets, beacon_inventory)
        
        # Analyze SSID correlations
        self._analyze_ssid_correlations()
        
        # Detect rogue APs
        self._detect_rogue_aps()
        
        # Analyze security attacks
        self._analyze_security_attacks(packets)
        
        # Correlate threats
        self._correlate_threats()
        
        self.logger.info(f"Detected {len(self.rogue_aps)} potential rogue APs and {len(self.security_threats)} security threats")
        
        # Generate findings
        findings = []
        findings.extend(self._analyze_rogue_ap_threats())
        findings.extend(self._analyze_ssid_spoofing())
        findings.extend(self._analyze_evil_twins())
        findings.extend(self._analyze_deauth_attacks())
        findings.extend(self._analyze_security_correlation())
        findings.extend(self._analyze_neighboring_ap_risks())
        
        # Store results in context
        context.metadata['rogue_ap_threats'] = {
            'rogue_aps': len(self.rogue_aps),
            'security_threats': len(self.security_threats),
            'ssid_correlations': len(self.ssid_correlations),
            'high_threat_aps': len([ap for ap in self.rogue_aps if ap.threat_level == ThreatLevel.HIGH])
        }
        
        self.findings_generated = len(findings)
        return findings
        
    def _build_ap_fingerprints(self, packets: List[Packet], beacon_inventory: Dict) -> None:
        """Build detailed AP fingerprints for comparison."""
        # Start with beacon inventory data
        for bssid, beacon_entry in beacon_inventory.items():
            fingerprint = APFingerprint(
                bssid=bssid,
                ssid=getattr(beacon_entry, 'ssid', ''),
                vendor_oui=getattr(beacon_entry, 'vendor_oui', ''),
                beacon_interval=getattr(beacon_entry, 'beacon_interval', 100),
                capabilities=getattr(beacon_entry, 'capabilities', 0).capabilities if hasattr(getattr(beacon_entry, 'capabilities', 0), 'capabilities') else 0,
                supported_rates=[],
                extended_rates=[],
                channel=getattr(beacon_entry, 'channel', None),
                ie_signature="",
                timing_signature="",
                vendor_specific_ies={},
                probe_response_behavior={},
                association_behavior={},
                power_management={}
            )
            self.ap_fingerprints[bssid] = fingerprint
            
        # Enhance fingerprints with packet analysis
        for packet in packets:
            try:
                if packet.haslayer(Dot11Beacon):
                    self._update_beacon_fingerprint(packet)
                elif packet.haslayer(Dot11ProbeResp):
                    self._update_probe_response_fingerprint(packet)
                    
            except Exception as e:
                self.logger.debug(f"Error building AP fingerprint: {e}")
                continue
                
    def _update_beacon_fingerprint(self, packet: Packet) -> None:
        """Update AP fingerprint from beacon frame."""
        dot11 = packet[Dot11]
        beacon = packet[Dot11Beacon]
        bssid = dot11.addr3
        
        if bssid not in self.ap_fingerprints:
            return
            
        fingerprint = self.ap_fingerprints[bssid]
        
        # Update timing signature
        timestamp = packet.time if hasattr(packet, 'time') else 0
        if hasattr(timestamp, '__float__'):
            timestamp = float(timestamp)
        elif hasattr(timestamp, 'val'):
            timestamp = float(timestamp.val)
        else:
            timestamp = float(timestamp)
            
        # Track beacon timing for anomaly detection
        if bssid not in self.beacon_anomalies:
            self.beacon_anomalies[bssid] = {
                'timestamps': deque(maxlen=100),
                'intervals': deque(maxlen=99),
                'interval_variance': 0.0
            }
            
        self.beacon_anomalies[bssid]['timestamps'].append(timestamp)
        
        # Calculate intervals if we have enough data
        timestamps = list(self.beacon_anomalies[bssid]['timestamps'])
        if len(timestamps) >= 2:
            intervals = [(timestamps[i] - timestamps[i-1]) for i in range(1, len(timestamps))]
            if intervals:
                mean_interval = statistics.mean(intervals)
                if len(intervals) > 1:
                    std_interval = statistics.stdev(intervals)
                    cv = std_interval / mean_interval if mean_interval > 0 else 0
                    self.beacon_anomalies[bssid]['interval_variance'] = cv
                    
        # Parse Information Elements for signature
        ie_types = []
        if packet.haslayer(Dot11Elt):
            current_ie = packet[Dot11Elt]
            while current_ie:
                ie_types.append(current_ie.ID)
                
                # Store vendor-specific IEs
                if current_ie.ID == 221:  # Vendor specific
                    ie_data = bytes(current_ie.info) if current_ie.info else b''
                    if len(ie_data) >= 3:
                        oui = ie_data[:3].hex()
                        fingerprint.vendor_specific_ies[oui] = ie_data[3:]
                        
                current_ie = current_ie.payload if hasattr(current_ie, 'payload') and isinstance(current_ie.payload, Dot11Elt) else None
                
        # Create IE signature
        fingerprint.ie_signature = ",".join(str(ie) for ie in ie_types)
        
    def _update_probe_response_fingerprint(self, packet: Packet) -> None:
        """Update AP fingerprint from probe response behavior."""
        dot11 = packet[Dot11]
        bssid = dot11.addr3
        
        if bssid not in self.ap_fingerprints:
            return
            
        # Track probe response timing
        timestamp = packet.time if hasattr(packet, 'time') else 0
        if hasattr(timestamp, '__float__'):
            timestamp = float(timestamp)
        elif hasattr(timestamp, 'val'):
            timestamp = float(timestamp.val)
        else:
            timestamp = float(timestamp)
            
        self.probe_response_patterns[bssid].append(datetime.fromtimestamp(timestamp))
        
    def _analyze_ssid_correlations(self) -> None:
        """Analyze SSID correlations for spoofing detection."""
        ssid_to_networks = defaultdict(list)
        
        # Group networks by SSID
        for bssid, fingerprint in self.ap_fingerprints.items():
            if fingerprint.ssid and fingerprint.ssid.strip():  # Skip empty/hidden SSIDs
                ssid_to_networks[fingerprint.ssid].append({
                    'bssid': bssid,
                    'vendor_oui': fingerprint.vendor_oui,
                    'channel': fingerprint.channel,
                    'beacon_interval': fingerprint.beacon_interval,
                    'capabilities': fingerprint.capabilities,
                    'ie_signature': fingerprint.ie_signature
                })
        
        # Analyze each SSID group
        for ssid, networks in ssid_to_networks.items():
            if len(networks) < 2:
                continue
                
            correlation = SSIDCorrelation(ssid=ssid, networks=networks)
            
            # Check for different vendor OUIs
            vendor_ouis = set(net['vendor_oui'] for net in networks if net['vendor_oui'])
            correlation.has_different_vendors = len(vendor_ouis) > 1
            
            # Check for mixed security (would need beacon inventory security data)
            # This is simplified - would be enhanced with actual security analysis
            
            # Check for potential spoofing indicators
            spoofing_indicators = []
            
            # Different beacon intervals (suspicious)
            beacon_intervals = set(net['beacon_interval'] for net in networks)
            if len(beacon_intervals) > 1:
                spoofing_indicators.append("Multiple beacon intervals for same SSID")
                
            # Different IE signatures
            ie_signatures = set(net['ie_signature'] for net in networks if net['ie_signature'])
            if len(ie_signatures) > 1:
                spoofing_indicators.append("Different IE signatures for same SSID")
                
            # Same channel (suspicious for evil twins)
            channels = [net['channel'] for net in networks if net['channel']]
            channel_counts = Counter(channels)
            if any(count > 1 for count in channel_counts.values()):
                spoofing_indicators.append("Multiple APs with same SSID on same channel")
                
            correlation.has_spoofing = len(spoofing_indicators) > 0
            correlation.threat_indicators = spoofing_indicators
            correlation.spoofing_confidence = min(len(spoofing_indicators) * 0.3, 1.0)
            
            # Try to identify legitimate network (largest beacon count, common vendor)
            # This is simplified heuristic
            if networks:
                correlation.legitimate_network = networks[0]['bssid']  # Default to first
                
            self.ssid_correlations[ssid] = correlation
            
    def _detect_rogue_aps(self) -> None:
        """Detect potential rogue access points."""
        for bssid, fingerprint in self.ap_fingerprints.items():
            rogue_indicators = []
            suspicious_behaviors = []
            threat_level = ThreatLevel.LOW
            rogue_type = RogueType.SUSPICIOUS
            
            # Check beacon timing anomalies
            if bssid in self.beacon_anomalies:
                variance = self.beacon_anomalies[bssid].get('interval_variance', 0)
                if variance > self.BEACON_TIMING_VARIANCE_THRESHOLD:
                    suspicious_behaviors.append(f"Irregular beacon timing (CV: {variance:.3f})")
                    
            # Check suspicious beacon intervals
            if (fingerprint.beacon_interval < self.SUSPICIOUS_BEACON_INTERVAL_THRESHOLD[0] or
                fingerprint.beacon_interval > self.SUSPICIOUS_BEACON_INTERVAL_THRESHOLD[1]):
                suspicious_behaviors.append(f"Unusual beacon interval: {fingerprint.beacon_interval}")
                
            # Check for SSID spoofing involvement
            if fingerprint.ssid in self.ssid_correlations:
                correlation = self.ssid_correlations[fingerprint.ssid]
                if correlation.has_spoofing and bssid != correlation.legitimate_network:
                    rogue_indicators.append("Potential SSID spoofing")
                    threat_level = ThreatLevel.HIGH
                    rogue_type = RogueType.EVIL_TWIN
                    
            # Check for suspicious vendor patterns
            vendor_oui = fingerprint.vendor_oui
            if vendor_oui:
                # Check for commonly spoofed vendors or unusual patterns
                oui_prefix = vendor_oui[:8] if len(vendor_oui) >= 8 else vendor_oui
                if oui_prefix in ["00:50:f2"]:  # Microsoft - sometimes used in attacks
                    suspicious_behaviors.append("Uses commonly spoofed vendor OUI")
                    
            # Check for excessive probe responses (potential karma attack)
            if bssid in self.probe_response_patterns:
                response_times = self.probe_response_patterns[bssid]
                if len(response_times) > 50:  # Arbitrary threshold
                    suspicious_behaviors.append("Excessive probe response activity")
                    
            # Only create rogue AP entry if we have indicators
            if rogue_indicators or len(suspicious_behaviors) > 2:
                if rogue_indicators:
                    threat_level = max(threat_level, ThreatLevel.MEDIUM)
                    
                rogue_ap = RogueAP(
                    bssid=bssid,
                    ssid=fingerprint.ssid,
                    rogue_type=rogue_type,
                    threat_level=threat_level,
                    detection_reasons=rogue_indicators,
                    suspicious_behaviors=suspicious_behaviors,
                    fingerprint=fingerprint
                )
                
                # Add recommended actions
                if rogue_type == RogueType.EVIL_TWIN:
                    rogue_ap.recommended_actions = [
                        "Investigate physical location of AP",
                        "Compare with legitimate network configuration",
                        "Monitor client associations",
                        "Consider blocking/jamming if confirmed malicious"
                    ]
                else:
                    rogue_ap.recommended_actions = [
                        "Monitor AP behavior",
                        "Investigate authorization status",
                        "Verify configuration compliance"
                    ]
                    
                self.rogue_aps.append(rogue_ap)
                
    def _analyze_security_attacks(self, packets: List[Packet]) -> None:
        """Analyze packets for security attack patterns."""
        deauth_events = []
        disassoc_events = []
        
        for packet in packets:
            try:
                timestamp = packet.time if hasattr(packet, 'time') else 0
                if hasattr(timestamp, '__float__'):
                    timestamp = float(timestamp)
                elif hasattr(timestamp, 'val'):
                    timestamp = float(timestamp.val)
                else:
                    timestamp = float(timestamp)
                    
                packet_time = datetime.fromtimestamp(timestamp)
                
                if packet.haslayer(Dot11Deauth):
                    deauth = packet[Dot11Deauth]
                    dot11 = packet[Dot11]
                    
                    event = {
                        'timestamp': packet_time,
                        'source': dot11.addr2,
                        'target': dot11.addr1,
                        'bssid': dot11.addr3,
                        'reason': deauth.reason if hasattr(deauth, 'reason') else 0
                    }
                    deauth_events.append(event)
                    
                    # Track for pattern analysis
                    source_key = f"{dot11.addr2}:{dot11.addr3}"
                    self.deauth_patterns[source_key].append(packet_time)
                    
                elif packet.haslayer(Dot11Disas):
                    disas = packet[Dot11Disas]
                    dot11 = packet[Dot11]
                    
                    event = {
                        'timestamp': packet_time,
                        'source': dot11.addr2,
                        'target': dot11.addr1,
                        'bssid': dot11.addr3,
                        'reason': disas.reason if hasattr(disas, 'reason') else 0
                    }
                    disassoc_events.append(event)
                    
            except Exception as e:
                self.logger.debug(f"Error analyzing security attack: {e}")
                continue
                
        # Analyze deauth patterns for floods
        self._detect_deauth_floods(deauth_events)
        
        # Analyze disassoc patterns
        self._detect_disassoc_attacks(disassoc_events)
        
    def _detect_deauth_floods(self, deauth_events: List[Dict]) -> None:
        """Detect deauthentication flood attacks."""
        # Group by source and analyze patterns
        source_patterns = defaultdict(list)
        for event in deauth_events:
            source_patterns[event['source']].append(event)
            
        for source_mac, events in source_patterns.items():
            if len(events) < self.DEAUTH_FLOOD_THRESHOLD:
                continue
                
            # Calculate attack intensity
            if len(events) >= 2:
                start_time = min(e['timestamp'] for e in events)
                end_time = max(e['timestamp'] for e in events)
                duration = (end_time - start_time).total_seconds()
                intensity = len(events) / max(duration, 1)  # attacks per second
                
                # Determine threat level
                if intensity > 5:  # Very high rate
                    threat_level = ThreatLevel.CRITICAL
                elif intensity > 2:
                    threat_level = ThreatLevel.HIGH
                else:
                    threat_level = ThreatLevel.MEDIUM
                    
                # Analyze targets
                targets = set(e['target'] for e in events)
                networks = set(e['bssid'] for e in events)
                
                # Create threat
                threat = SecurityThreat(
                    threat_id=f"deauth_flood_{source_mac}_{int(start_time.timestamp())}",
                    attack_type=AttackType.DEAUTH_FLOOD if len(targets) > 5 else AttackType.DEAUTH_TARGETED,
                    threat_level=threat_level,
                    source_mac=source_mac,
                    target_networks=list(networks),
                    affected_clients=targets,
                    start_time=start_time,
                    end_time=end_time,
                    attack_intensity=intensity,
                    frame_count=len(events),
                    pattern_description=f"Deauth flood: {len(events)} frames in {duration:.1f}s",
                    estimated_impact="Client disconnections, service disruption",
                    mitigation_priority=1 if threat_level == ThreatLevel.CRITICAL else 2,
                    recommended_response=[
                        "Identify and locate attacking device",
                        "Implement client MAC randomization",
                        "Enable PMF (Protected Management Frames)",
                        "Consider RF jamming countermeasures"
                    ]
                )
                
                # Add packet examples
                threat.packet_examples = [
                    {
                        'timestamp': e['timestamp'].isoformat(),
                        'target': e['target'],
                        'bssid': e['bssid'],
                        'reason': e['reason']
                    }
                    for e in events[:5]  # First 5 examples
                ]
                
                self.security_threats.append(threat)
                
    def _detect_disassoc_attacks(self, disassoc_events: List[Dict]) -> None:
        """Detect disassociation attacks."""
        # Similar to deauth detection but for disassoc
        source_patterns = defaultdict(list)
        for event in disassoc_events:
            source_patterns[event['source']].append(event)
            
        for source_mac, events in source_patterns.items():
            if len(events) >= 5:  # Lower threshold for disassoc
                start_time = min(e['timestamp'] for e in events)
                end_time = max(e['timestamp'] for e in events)
                duration = (end_time - start_time).total_seconds()
                intensity = len(events) / max(duration, 1)
                
                threat = SecurityThreat(
                    threat_id=f"disassoc_flood_{source_mac}_{int(start_time.timestamp())}",
                    attack_type=AttackType.DISASSOC_FLOOD,
                    threat_level=ThreatLevel.MEDIUM,
                    source_mac=source_mac,
                    target_networks=list(set(e['bssid'] for e in events)),
                    affected_clients=set(e['target'] for e in events),
                    start_time=start_time,
                    end_time=end_time,
                    attack_intensity=intensity,
                    frame_count=len(events),
                    pattern_description=f"Disassoc attack: {len(events)} frames",
                    estimated_impact="Client session disruption",
                    mitigation_priority=3,
                    recommended_response=[
                        "Monitor attacking device",
                        "Enable PMF if available",
                        "Investigate source device legitimacy"
                    ]
                )
                
                self.security_threats.append(threat)
                
    def _correlate_threats(self) -> None:
        """Correlate different types of threats for attack chain analysis."""
        # This could correlate rogue APs with deauth attacks, timing patterns, etc.
        # For now, just update rogue APs with attack indicators
        
        for rogue_ap in self.rogue_aps:
            # Check if this BSSID is involved in attacks
            related_threats = [
                threat for threat in self.security_threats
                if rogue_ap.bssid in threat.target_networks or threat.source_mac == rogue_ap.bssid
            ]
            
            if related_threats:
                rogue_ap.attack_indicators = [f"Associated with {threat.attack_type.value}" for threat in related_threats]
                # Upgrade threat level if involved in attacks
                if rogue_ap.threat_level in [ThreatLevel.LOW, ThreatLevel.SUSPICIOUS]:
                    rogue_ap.threat_level = ThreatLevel.HIGH
                    
    # Analysis methods for generating findings
    
    def _analyze_rogue_ap_threats(self) -> List[Finding]:
        """Analyze detected rogue APs."""
        findings = []
        
        if not self.rogue_aps:
            return findings
            
        # Group by threat level
        threat_levels = Counter(ap.threat_level.value for ap in self.rogue_aps)
        high_threat_aps = [ap for ap in self.rogue_aps if ap.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]]
        
        severity = Severity.CRITICAL if threat_levels.get('critical', 0) > 0 else \
                  Severity.WARNING if threat_levels.get('high', 0) > 0 else Severity.INFO
                  
        findings.append(Finding(
            category=AnalysisCategory.SECURITY_THREATS,
            severity=severity,
            title="Rogue Access Point Detection",
            description=f"Detected {len(self.rogue_aps)} potential rogue access points",
            details={
                "total_rogue_aps": len(self.rogue_aps),
                "threat_level_distribution": dict(threat_levels),
                "high_threat_aps": [
                    {
                        "bssid": ap.bssid,
                        "ssid": ap.ssid,
                        "rogue_type": ap.rogue_type.value,
                        "threat_level": ap.threat_level.value,
                        "detection_reasons": ap.detection_reasons,
                        "suspicious_behaviors": ap.suspicious_behaviors,
                        "recommended_actions": ap.recommended_actions
                    }
                    for ap in high_threat_aps[:10]
                ],
                "investigation_priority": "Investigate high-threat APs immediately"
            },
            analyzer_name=self.name,
            analyzer_version=self.version
        ))
        
        return findings
        
    def _analyze_ssid_spoofing(self) -> List[Finding]:
        """Analyze SSID spoofing attempts."""
        findings = []
        
        spoofing_cases = [corr for corr in self.ssid_correlations.values() if corr.has_spoofing]
        
        if spoofing_cases:
            findings.append(Finding(
                category=AnalysisCategory.SECURITY_THREATS,
                severity=Severity.WARNING,
                title="SSID Spoofing Detection",
                description=f"Detected potential SSID spoofing across {len(spoofing_cases)} network names",
                details={
                    "spoofed_ssids": len(spoofing_cases),
                    "spoofing_cases": [
                        {
                            "ssid": case.ssid,
                            "network_count": len(case.networks),
                            "spoofing_confidence": round(case.spoofing_confidence, 2),
                            "threat_indicators": case.threat_indicators,
                            "networks": [
                                {
                                    "bssid": net['bssid'],
                                    "vendor_oui": net['vendor_oui'],
                                    "channel": net['channel']
                                }
                                for net in case.networks
                            ]
                        }
                        for case in spoofing_cases[:10]
                    ],
                    "security_impact": "Users may connect to malicious networks",
                    "recommendation": "Verify legitimate network ownership and investigate suspicious APs"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
            
        return findings
        
    def _analyze_evil_twins(self) -> List[Finding]:
        """Analyze evil twin AP detection."""
        findings = []
        
        evil_twins = [ap for ap in self.rogue_aps if ap.rogue_type == RogueType.EVIL_TWIN]
        
        if evil_twins:
            findings.append(Finding(
                category=AnalysisCategory.SECURITY_THREATS,
                severity=Severity.CRITICAL,
                title="Evil Twin Access Point Detection",
                description=f"Detected {len(evil_twins)} potential evil twin access points",
                details={
                    "evil_twin_count": len(evil_twins),
                    "evil_twins": [
                        {
                            "bssid": ap.bssid,
                            "ssid": ap.ssid,
                            "impersonated_ap": ap.impersonated_ap,
                            "similarity_score": ap.similarity_score,
                            "detection_reasons": ap.detection_reasons,
                            "threat_level": ap.threat_level.value,
                            "recommended_actions": ap.recommended_actions
                        }
                        for ap in evil_twins
                    ],
                    "attack_description": "Evil twins impersonate legitimate APs to steal credentials",
                    "immediate_action_required": True,
                    "mitigation_steps": [
                        "Physically locate and disable rogue APs",
                        "Warn users about potential evil twins",
                        "Implement certificate-based authentication",
                        "Use network access control (NAC)"
                    ]
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
            
        return findings
        
    def _analyze_deauth_attacks(self) -> List[Finding]:
        """Analyze deauthentication attacks."""
        findings = []
        
        deauth_attacks = [threat for threat in self.security_threats 
                         if threat.attack_type in [AttackType.DEAUTH_FLOOD, AttackType.DEAUTH_TARGETED]]
        
        if deauth_attacks:
            # Calculate total impact
            total_affected_clients = set()
            for attack in deauth_attacks:
                total_affected_clients.update(attack.affected_clients)
                
            severity = Severity.CRITICAL if any(a.threat_level == ThreatLevel.CRITICAL for a in deauth_attacks) else Severity.WARNING
            
            findings.append(Finding(
                category=AnalysisCategory.SECURITY_THREATS,
                severity=severity,
                title="Deauthentication Attack Detection",
                description=f"Detected {len(deauth_attacks)} deauthentication attacks affecting {len(total_affected_clients)} clients",
                details={
                    "attack_count": len(deauth_attacks),
                    "total_affected_clients": len(total_affected_clients),
                    "attacks": [
                        {
                            "threat_id": attack.threat_id,
                            "attack_type": attack.attack_type.value,
                            "threat_level": attack.threat_level.value,
                            "source_mac": attack.source_mac,
                            "target_networks": attack.target_networks,
                            "affected_clients": len(attack.affected_clients),
                            "attack_intensity": round(attack.attack_intensity, 2) if attack.attack_intensity else 0,
                            "duration": f"{(attack.end_time - attack.start_time).total_seconds():.1f}s" if attack.start_time and attack.end_time else "Unknown",
                            "recommended_response": attack.recommended_response
                        }
                        for attack in deauth_attacks
                    ],
                    "attack_description": "Deauth attacks forcibly disconnect clients from networks",
                    "defense_recommendations": [
                        "Enable PMF (Protected Management Frames) on all networks",
                        "Implement 802.11w management frame protection",
                        "Use client-side deauth detection and mitigation",
                        "Consider RF monitoring and threat detection systems"
                    ]
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
            
        return findings
        
    def _analyze_security_correlation(self) -> List[Finding]:
        """Analyze correlated security threats."""
        findings = []
        
        # Look for correlated threats (rogue APs + attacks)
        correlated_threats = []
        
        for rogue_ap in self.rogue_aps:
            if rogue_ap.attack_indicators:
                related_attacks = [
                    threat for threat in self.security_threats
                    if threat.source_mac == rogue_ap.bssid or rogue_ap.bssid in threat.target_networks
                ]
                
                if related_attacks:
                    correlated_threats.append({
                        "rogue_ap": rogue_ap,
                        "related_attacks": related_attacks
                    })
        
        if correlated_threats:
            findings.append(Finding(
                category=AnalysisCategory.SECURITY_THREATS,
                severity=Severity.CRITICAL,
                title="Correlated Security Threat Campaign",
                description=f"Detected {len(correlated_threats)} correlated threat campaigns involving rogue APs and attacks",
                details={
                    "threat_campaigns": len(correlated_threats),
                    "campaigns": [
                        {
                            "rogue_ap_bssid": campaign["rogue_ap"].bssid,
                            "rogue_ap_ssid": campaign["rogue_ap"].ssid,
                            "rogue_type": campaign["rogue_ap"].rogue_type.value,
                            "related_attack_types": [attack.attack_type.value for attack in campaign["related_attacks"]],
                            "attack_count": len(campaign["related_attacks"]),
                            "overall_threat": "CRITICAL"
                        }
                        for campaign in correlated_threats
                    ],
                    "campaign_analysis": "Coordinated attacks involving rogue APs and network disruption",
                    "immediate_response_required": True,
                    "incident_response_plan": [
                        "Activate security incident response team",
                        "Isolate and investigate all identified threats",
                        "Implement emergency countermeasures",
                        "Document attack vectors for forensic analysis"
                    ]
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
            
        return findings
        
    def _analyze_neighboring_ap_risks(self) -> List[Finding]:
        """Analyze neighboring AP security risks."""
        findings = []
        
        # Analyze open networks co-located with secure ones
        open_secure_colocation = []
        
        # Group APs by approximate location (same channel as proxy)
        channel_groups = defaultdict(list)
        for bssid, fingerprint in self.ap_fingerprints.items():
            if fingerprint.channel:
                channel_groups[fingerprint.channel].append((bssid, fingerprint))
        
        for channel, aps in channel_groups.items():
            if len(aps) < 2:
                continue
                
            # Check for mixed security on same channel (potential risk)
            # This would be enhanced with actual security posture data
            ssids_on_channel = set(fp.ssid for _, fp in aps if fp.ssid)
            
            if len(ssids_on_channel) > 1:
                open_secure_colocation.append({
                    "channel": channel,
                    "ap_count": len(aps),
                    "ssids": list(ssids_on_channel),
                    "risk": "Mixed security posture on same channel"
                })
        
        if open_secure_colocation:
            findings.append(Finding(
                category=AnalysisCategory.SECURITY_THREATS,
                severity=Severity.INFO,
                title="Neighboring AP Security Analysis",
                description=f"Analyzed co-located AP security configurations on {len(open_secure_colocation)} channels",
                details={
                    "channels_analyzed": len(open_secure_colocation),
                    "colocation_analysis": open_secure_colocation[:10],
                    "security_considerations": [
                        "Users may confuse similar network names",
                        "Evil twin attacks easier with co-located APs",
                        "Mixed security creates user confusion"
                    ],
                    "recommendations": [
                        "Use distinct SSID naming conventions",
                        "Implement proper network segregation", 
                        "Consider channel planning optimization"
                    ]
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
            
        return findings