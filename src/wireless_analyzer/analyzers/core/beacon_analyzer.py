"""
Beacon Analysis for wireless PCAP data.

This analyzer provides comprehensive beacon frame analysis including:
- Beacon interval consistency and timing analysis
- Information Element (IE) validation and parsing
- Capability field analysis and assessment
- SSID and network identification validation
- Timestamp accuracy and synchronization checks
- Channel and frequency validation
- Security configuration detection
"""

import statistics
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta
from typing import List, Dict, Any, Set, Tuple, Optional, NamedTuple
import struct

from scapy.all import Packet
from scapy.layers.dot11 import (
    Dot11, Dot11Beacon, Dot11Elt, Dot11EltRates, Dot11EltDSSSet,
    Dot11EltCountry, Dot11EltVendorSpecific, Dot11EltRSN,
    Dot11EltMicrosoftWPA
)
from scapy.layers.dot11 import RadioTap

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
    PacketReference,
    FrameType
)


class BeaconInfo(NamedTuple):
    """Information extracted from a beacon frame."""
    timestamp: float
    bssid: str
    ssid: str
    beacon_interval: int
    capabilities: int
    channel: Optional[int]
    rssi: Optional[int]
    ies: Dict[int, bytes]
    packet_timestamp: float


class BeaconAnalyzer(BaseAnalyzer):
    """
    Comprehensive beacon frame analyzer.
    
    This analyzer performs detailed analysis of 802.11 beacon frames including:
    - Timing consistency and beacon interval validation
    - Information Element structure and content validation
    - Capability field analysis
    - Network configuration assessment
    - Security configuration detection
    - Channel and frequency validation
    """
    
    def __init__(self):
        super().__init__(
            name="Beacon Frame Analyzer",
            category=AnalysisCategory.BEACONS,
            version="1.0"
        )
        
        self.description = (
            "Analyzes 802.11 beacon frames for timing consistency, "
            "information element validation, and capability analysis"
        )
        
        # Wireshark filters for beacon analysis
        self.wireshark_filters = [
            "wlan.fc.type_subtype == 8",  # Beacon frames
            "wlan.fixed.beacon",
            "wlan.ssid",
            "wlan.ds.current_channel"
        ]
        
        self.analysis_order = 20  # Run after capture validation
        
        # Beacon tracking
        self.beacon_tracking: Dict[str, List[BeaconInfo]] = defaultdict(list)
        self.interval_tracking: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        
        # IE validation patterns
        self.ie_validators = self._initialize_ie_validators()
        
        # Standards-based thresholds
        self.min_beacon_interval = 1  # TU (Time Units)
        self.max_beacon_interval = 65535  # TU
        self.typical_beacon_intervals = {100, 102, 204}  # Common intervals
        self.max_interval_variance = 10  # Allowable variance in TU
        
    def _initialize_ie_validators(self) -> Dict[int, callable]:
        """Initialize Information Element validators."""
        return {
            0: self._validate_ssid_ie,      # SSID
            1: self._validate_rates_ie,     # Supported Rates
            3: self._validate_channel_ie,   # DS Parameter Set
            5: self._validate_tim_ie,       # Traffic Indication Map
            7: self._validate_country_ie,   # Country
            11: self._validate_qbss_ie,     # QBSS Load
            32: self._validate_power_ie,    # Power Constraint
            48: self._validate_rsn_ie,      # RSN (WPA2)
            50: self._validate_ext_rates_ie, # Extended Supported Rates
            61: self._validate_ht_info_ie,  # HT Information
            127: self._validate_ext_cap_ie, # Extended Capabilities
            191: self._validate_vht_cap_ie, # VHT Capabilities
            221: self._validate_vendor_ie,  # Vendor Specific
        }

    def is_applicable(self, packet: Packet) -> bool:
        """Check if packet is a beacon frame."""
        return packet_has_layer(packet, Dot11Beacon)
        
    def get_display_filters(self) -> List[str]:
        """Get Wireshark display filters for beacon analysis."""
        return self.wireshark_filters
        
    def analyze(self, packets: List[Packet], context: AnalysisContext) -> List[Finding]:
        """
        Analyze beacon frames for consistency, IE validation, and capabilities.
        
        Args:
            packets: List of beacon packets
            context: Analysis context
            
        Returns:
            List of findings
        """
        if not packets:
            return []
            
        self.logger.info(f"Analyzing {len(packets)} beacon frames")
        
        findings = []
        
        # Extract beacon information
        beacon_data = self._extract_beacon_info(packets)
        
        # Group by BSSID for per-AP analysis
        ap_beacons = defaultdict(list)
        for beacon in beacon_data:
            ap_beacons[beacon.bssid].extend([beacon])
            
        self.logger.info(f"Found beacons from {len(ap_beacons)} unique BSSIDs")
        
        # Analyze each AP's beacons
        for bssid, beacons in ap_beacons.items():
            findings.extend(self._analyze_beacon_timing(bssid, beacons))
            findings.extend(self._analyze_information_elements(bssid, beacons))
            findings.extend(self._analyze_capabilities(bssid, beacons))
            findings.extend(self._analyze_network_config(bssid, beacons))
            
        # Cross-AP analysis
        findings.extend(self._analyze_network_conflicts(ap_beacons))
        
        self.findings_generated = len(findings)
        return findings
        
    def _extract_beacon_info(self, packets: List[Packet]) -> List[BeaconInfo]:
        """Extract beacon information from packets."""
        beacon_info = []
        
        for packet in packets:
            try:
                if not packet_has_layer(packet, Dot11Beacon):
                    continue
                    
                dot11 = get_packet_layer(packet, "Dot11")
                beacon = get_packet_layer(packet, "Dot11Beacon")
                
                # Extract basic info
                bssid = dot11.addr3 if dot11.addr3 else "unknown"
                
                # Get packet timestamp
                packet_time = get_timestamp(packet) if hasattr(packet, 'time') else 0
                if hasattr(packet_time, '__float__'):
                    packet_time = float(packet_time)
                elif hasattr(packet_time, 'val'):
                    packet_time = float(packet_time.val)
                else:
                    packet_time = float(packet_time)
                
                # Extract SSID from IEs
                ssid = ""
                ies = {}
                if packet_has_layer(packet, Dot11Elt):
                    current_ie = get_packet_layer(packet, "Dot11Elt")
                    while current_ie:
                        ie_type = current_ie.ID
                        ie_data = bytes(current_ie.info) if current_ie.info else b''
                        ies[ie_type] = ie_data
                        
                        if ie_type == 0 and ie_data:  # SSID
                            try:
                                ssid = ie_data.decode('utf-8', errors='ignore')
                            except:
                                ssid = f"<binary:{len(ie_data)}bytes>"
                        
                        current_ie = current_ie.payload if hasattr(current_ie, 'payload') and isinstance(current_ie.payload, Dot11Elt) else None
                
                # Get RSSI if available from RadioTap
                rssi = None
                if packet_has_layer(packet, RadioTap):
                    radiotap = get_packet_layer(packet, "RadioTap")
                    if hasattr(radiotap, 'dBm_AntSignal'):
                        rssi = radiotap.dBm_AntSignal
                
                # Extract channel from DS Parameter Set IE (ID 3)
                channel = None
                if 3 in ies and len(ies[3]) >= 1:
                    channel = struct.unpack('B', ies[3][:1])[0]
                
                beacon_info.append(BeaconInfo(
                    timestamp=beacon.timestamp,
                    bssid=bssid,
                    ssid=ssid,
                    beacon_interval=beacon.beacon_interval,
                    capabilities=beacon.cap,
                    channel=channel,
                    rssi=rssi,
                    ies=ies,
                    packet_timestamp=packet_time
                ))
                
            except Exception as e:
                self.logger.debug(f"Error extracting beacon info: {e}")
                continue
                
        return beacon_info
        
    def _analyze_beacon_timing(self, bssid: str, beacons: List[BeaconInfo]) -> List[Finding]:
        """Analyze beacon timing consistency."""
        findings = []
        
        if len(beacons) < 2:
            return findings
            
        # Sort by packet timestamp
        beacons.sort(key=lambda x: x.packet_timestamp)
        
        # Check beacon interval consistency
        intervals = [b.beacon_interval for b in beacons]
        unique_intervals = set(intervals)
        
        if len(unique_intervals) > 1:
            findings.append(Finding(
                category=AnalysisCategory.BEACONS,
                severity=Severity.MEDIUM,
                title="Inconsistent Beacon Intervals",
                description=f"AP {bssid} has varying beacon intervals",
                details={
                    "bssid": bssid,
                    "ssid": beacons[0].ssid,
                    "intervals_observed": list(unique_intervals),
                    "interval_counts": dict(Counter(intervals)),
                    "expected_consistency": "Beacon intervals should remain constant"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
            
        # Check for unusual beacon intervals
        primary_interval = max(set(intervals), key=intervals.count)
        if primary_interval not in self.typical_beacon_intervals:
            severity = Severity.LOW if primary_interval in range(50, 1000) else Severity.MEDIUM
            findings.append(Finding(
                category=AnalysisCategory.BEACONS,
                severity=severity,
                title="Unusual Beacon Interval",
                description=f"AP {bssid} using non-standard beacon interval",
                details={
                    "bssid": bssid,
                    "ssid": beacons[0].ssid,
                    "beacon_interval": primary_interval,
                    "typical_intervals": list(self.typical_beacon_intervals),
                    "impact": "May indicate custom configuration or attack"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
            
        # Analyze actual timing between beacons
        if len(beacons) >= 3:
            actual_intervals = []
            for i in range(1, len(beacons)):
                time_diff = beacons[i].packet_timestamp - beacons[i-1].packet_timestamp
                # Convert to milliseconds and then to TU (1 TU = 1024 μs ≈ 1.024 ms)
                actual_interval_tu = (time_diff * 1000) / 1.024
                actual_intervals.append(actual_interval_tu)
            
            if actual_intervals:
                mean_interval = statistics.mean(actual_intervals)
                expected_interval = primary_interval
                
                # Check for significant deviation
                if abs(mean_interval - expected_interval) > self.max_interval_variance:
                    findings.append(Finding(
                        category=AnalysisCategory.BEACONS,
                        severity=Severity.MEDIUM,
                        title="Beacon Timing Deviation",
                        description=f"Actual beacon timing deviates from configured interval",
                        details={
                            "bssid": bssid,
                            "ssid": beacons[0].ssid,
                            "configured_interval_tu": expected_interval,
                            "actual_mean_interval_tu": round(mean_interval, 2),
                            "deviation_tu": round(mean_interval - expected_interval, 2),
                            "sample_count": len(actual_intervals),
                            "timing_variance": round(statistics.stdev(actual_intervals), 2) if len(actual_intervals) > 1 else 0
                        },
                        analyzer_name=self.name,
                        analyzer_version=self.version
                    ))
                    
        return findings
        
    def _analyze_information_elements(self, bssid: str, beacons: List[BeaconInfo]) -> List[Finding]:
        """Analyze Information Elements in beacon frames."""
        findings = []
        
        if not beacons:
            return findings
            
        # Analyze IE consistency across beacons from same AP
        ie_consistency = defaultdict(set)
        for beacon in beacons:
            for ie_id, ie_data in beacon.ies.items():
                ie_consistency[ie_id].add(ie_data)
        
        # Check for inconsistent IEs
        for ie_id, ie_values in ie_consistency.items():
            if len(ie_values) > 1:
                # Some IEs are expected to change (like TIM)
                if ie_id not in [5]:  # TIM can change
                    findings.append(Finding(
                        category=AnalysisCategory.NETWORK_MONITORING,
                        severity=Severity.LOW,
                        title=f"Inconsistent IE {ie_id}",
                        description=f"Information Element {ie_id} varies across beacons",
                        details={
                            "bssid": bssid,
                            "ssid": beacons[0].ssid,
                            "ie_id": ie_id,
                            "ie_name": self._get_ie_name(ie_id),
                            "unique_values": len(ie_values),
                            "variation_impact": "May indicate configuration changes or attack"
                        },
                        analyzer_name=self.name,
                        analyzer_version=self.version
                    ))
        
        # Validate individual IEs using the latest beacon
        latest_beacon = max(beacons, key=lambda x: x.packet_timestamp)
        for ie_id, ie_data in latest_beacon.ies.items():
            if ie_id in self.ie_validators:
                ie_findings = self.ie_validators[ie_id](bssid, latest_beacon.ssid, ie_id, ie_data)
                findings.extend(ie_findings)
        
        # Check for missing critical IEs
        critical_ies = {0: "SSID", 1: "Supported Rates", 3: "Channel"}
        for ie_id, ie_name in critical_ies.items():
            if ie_id not in latest_beacon.ies:
                findings.append(Finding(
                    category=AnalysisCategory.BEACONS,
                    severity=Severity.HIGH,
                    title=f"Missing Critical IE: {ie_name}",
                    description=f"Beacon missing required {ie_name} Information Element",
                    details={
                        "bssid": bssid,
                        "ssid": latest_beacon.ssid,
                        "missing_ie": ie_name,
                        "ie_id": ie_id,
                        "compliance_issue": "Required by 802.11 standard"
                    },
                    analyzer_name=self.name,
                    analyzer_version=self.version
                ))
        
        return findings
        
    def _analyze_capabilities(self, bssid: str, beacons: List[BeaconInfo]) -> List[Finding]:
        """Analyze capability fields in beacon frames."""
        findings = []
        
        if not beacons:
            return findings
            
        # Use latest beacon for capability analysis
        latest_beacon = max(beacons, key=lambda x: x.packet_timestamp)
        capabilities = latest_beacon.capabilities
        
        # Parse capability bits
        cap_analysis = {
            "ess": bool(capabilities & 0x0001),          # ESS capability
            "ibss": bool(capabilities & 0x0002),         # IBSS capability  
            "cf_pollable": bool(capabilities & 0x0004),  # CF Pollable
            "cf_poll_req": bool(capabilities & 0x0008),  # CF Poll Request
            "privacy": bool(capabilities & 0x0010),      # Privacy (WEP)
            "short_preamble": bool(capabilities & 0x0020), # Short Preamble
            "pbcc": bool(capabilities & 0x0040),         # PBCC
            "channel_agility": bool(capabilities & 0x0080), # Channel Agility
            "spectrum_mgmt": bool(capabilities & 0x0100), # Spectrum Management
            "qos": bool(capabilities & 0x0200),          # QoS
            "short_slot": bool(capabilities & 0x0400),   # Short Slot Time
            "apsd": bool(capabilities & 0x0800),         # Automatic Power Save Delivery
            "radio_measurement": bool(capabilities & 0x1000), # Radio Measurement
            "dsss_ofdm": bool(capabilities & 0x2000),    # DSSS-OFDM
            "delayed_ba": bool(capabilities & 0x4000),   # Delayed Block Ack
            "immediate_ba": bool(capabilities & 0x8000)  # Immediate Block Ack
        }
        
        # Check for conflicting capabilities
        if cap_analysis["ess"] and cap_analysis["ibss"]:
            findings.append(Finding(
                category=AnalysisCategory.BEACONS,
                severity=Severity.HIGH,
                title="Conflicting Network Type Capabilities",
                description="Both ESS and IBSS capabilities set simultaneously",
                details={
                    "bssid": bssid,
                    "ssid": latest_beacon.ssid,
                    "capabilities_raw": f"0x{capabilities:04x}",
                    "conflict": "ESS and IBSS are mutually exclusive",
                    "standard_violation": "802.11 standard violation"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
        
        # Check privacy bit vs. security IEs
        has_rsn = 48 in latest_beacon.ies  # RSN IE
        has_wpa = any(ie_id == 221 and ie_data.startswith(b'\x00\x50\xf2\x01') 
                     for ie_id, ie_data in latest_beacon.ies.items())  # WPA vendor IE
        
        if cap_analysis["privacy"] and not (has_rsn or has_wpa):
            # Privacy set but no modern security - likely WEP
            findings.append(Finding(
                category=AnalysisCategory.ENTERPRISE_SECURITY,
                severity=Severity.HIGH,
                title="Weak Security: WEP Detected",
                description="Network using deprecated WEP encryption",
                details={
                    "bssid": bssid,
                    "ssid": latest_beacon.ssid,
                    "privacy_bit": True,
                    "modern_security": False,
                    "security_recommendation": "Upgrade to WPA2/WPA3"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
        elif not cap_analysis["privacy"] and not (has_rsn or has_wpa):
            # No privacy at all
            findings.append(Finding(
                category=AnalysisCategory.ENTERPRISE_SECURITY,
                severity=Severity.MEDIUM,
                title="Open Network Detected",
                description="Network operating without encryption",
                details={
                    "bssid": bssid,
                    "ssid": latest_beacon.ssid,
                    "encryption": "None",
                    "security_risk": "Traffic transmitted in clear text"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
        
        return findings
        
    def _analyze_network_config(self, bssid: str, beacons: List[BeaconInfo]) -> List[Finding]:
        """Analyze network configuration from beacon data."""
        findings = []
        
        if not beacons:
            return findings
        
        latest_beacon = max(beacons, key=lambda x: x.packet_timestamp)
        
        # Check for hidden SSID
        if not latest_beacon.ssid or latest_beacon.ssid.strip() == "":
            findings.append(Finding(
                category=AnalysisCategory.BEACONS,
                severity=Severity.LOW,
                title="Hidden SSID Detected",
                description="Network broadcasting with hidden/empty SSID",
                details={
                    "bssid": bssid,
                    "ssid_hidden": True,
                    "security_note": "Hidden SSIDs provide limited security benefit"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
        
        # Check channel configuration
        if latest_beacon.channel:
            if latest_beacon.channel < 1 or latest_beacon.channel > 14:
                if latest_beacon.channel not in range(36, 166):  # 5GHz channels
                    findings.append(Finding(
                        category=AnalysisCategory.RF_PHY,
                        severity=Severity.MEDIUM,
                        title="Invalid Channel Configuration",
                        description=f"Network configured on invalid channel {latest_beacon.channel}",
                        details={
                            "bssid": bssid,
                            "ssid": latest_beacon.ssid,
                            "channel": latest_beacon.channel,
                            "valid_2_4ghz": "1-14",
                            "valid_5ghz": "36-165 (varies by region)"
                        },
                        analyzer_name=self.name,
                        analyzer_version=self.version
                    ))
        
        return findings
        
    def _analyze_network_conflicts(self, ap_beacons: Dict[str, List[BeaconInfo]]) -> List[Finding]:
        """Analyze conflicts between different networks."""
        findings = []
        
        # Check for SSID conflicts (same SSID, different BSSID)
        ssid_to_bssids = defaultdict(set)
        for bssid, beacons in ap_beacons.items():
            if beacons:
                ssid = beacons[0].ssid
                if ssid and ssid.strip():  # Ignore hidden SSIDs
                    ssid_to_bssids[ssid].add(bssid)
        
        for ssid, bssids in ssid_to_bssids.items():
            if len(bssids) > 1:
                # Check if it's likely legitimate (different channels)
                channels = set()
                for bssid in bssids:
                    latest_beacon = max(ap_beacons[bssid], key=lambda x: x.packet_timestamp)
                    if latest_beacon.channel:
                        channels.add(latest_beacon.channel)
                
                severity = Severity.LOW if len(channels) > 1 else Severity.MEDIUM
                findings.append(Finding(
                    category=AnalysisCategory.NETWORK_MONITORING,
                    severity=severity,
                    title="SSID Conflict Detected",
                    description=f"Multiple BSSIDs broadcasting same SSID: {ssid}",
                    details={
                        "ssid": ssid,
                        "conflicting_bssids": list(bssids),
                        "channels_used": list(channels) if channels else ["unknown"],
                        "analysis": "Could be legitimate multi-AP network or potential attack"
                    },
                    analyzer_name=self.name,
                    analyzer_version=self.version
                ))
        
        return findings
    
    # IE Validation Methods
    def _validate_ssid_ie(self, bssid: str, ssid: str, ie_id: int, ie_data: bytes) -> List[Finding]:
        """Validate SSID Information Element."""
        findings = []
        
        if len(ie_data) > 32:
            findings.append(Finding(
                category=AnalysisCategory.BEACONS,
                severity=Severity.HIGH,
                title="Invalid SSID Length",
                description="SSID exceeds maximum length of 32 bytes",
                details={
                    "bssid": bssid,
                    "ssid_length": len(ie_data),
                    "max_length": 32,
                    "standard_violation": "802.11 standard requires SSID ≤ 32 bytes"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
        
        return findings
    
    def _validate_rates_ie(self, bssid: str, ssid: str, ie_id: int, ie_data: bytes) -> List[Finding]:
        """Validate Supported Rates Information Element."""
        findings = []
        
        if len(ie_data) == 0:
            findings.append(Finding(
                category=AnalysisCategory.BEACONS,
                severity=Severity.HIGH,
                title="Empty Supported Rates IE",
                description="Supported Rates IE cannot be empty",
                details={
                    "bssid": bssid,
                    "ssid": ssid,
                    "requirement": "At least one supported rate must be specified"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
        elif len(ie_data) > 8:
            findings.append(Finding(
                category=AnalysisCategory.BEACONS,
                severity=Severity.MEDIUM,
                title="Too Many Rates in Basic Rates IE",
                description="Basic Supported Rates IE should contain ≤8 rates",
                details={
                    "bssid": bssid,
                    "ssid": ssid,
                    "rates_count": len(ie_data),
                    "max_basic_rates": 8,
                    "note": "Additional rates should use Extended Supported Rates IE"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
        
        return findings
    
    def _validate_channel_ie(self, bssid: str, ssid: str, ie_id: int, ie_data: bytes) -> List[Finding]:
        """Validate DS Parameter Set (Channel) Information Element."""
        findings = []
        
        if len(ie_data) != 1:
            findings.append(Finding(
                category=AnalysisCategory.BEACONS,
                severity=Severity.HIGH,
                title="Invalid Channel IE Length",
                description="DS Parameter Set IE must be exactly 1 byte",
                details={
                    "bssid": bssid,
                    "ssid": ssid,
                    "actual_length": len(ie_data),
                    "expected_length": 1
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
        
        return findings
    
    def _validate_tim_ie(self, bssid: str, ssid: str, ie_id: int, ie_data: bytes) -> List[Finding]:
        """Validate Traffic Indication Map Information Element."""
        findings = []
        
        if len(ie_data) < 4:
            findings.append(Finding(
                category=AnalysisCategory.BEACONS,
                severity=Severity.HIGH,
                title="Invalid TIM IE Length",
                description="TIM IE must be at least 4 bytes",
                details={
                    "bssid": bssid,
                    "ssid": ssid,
                    "actual_length": len(ie_data),
                    "minimum_length": 4
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
        
        return findings
    
    def _validate_country_ie(self, bssid: str, ssid: str, ie_id: int, ie_data: bytes) -> List[Finding]:
        """Validate Country Information Element."""
        findings = []
        
        if len(ie_data) < 6:
            findings.append(Finding(
                category=AnalysisCategory.BEACONS,
                severity=Severity.MEDIUM,
                title="Invalid Country IE Length",
                description="Country IE must be at least 6 bytes (country string + 1 triplet)",
                details={
                    "bssid": bssid,
                    "ssid": ssid,
                    "actual_length": len(ie_data),
                    "minimum_length": 6
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
        
        return findings
    
    def _validate_qbss_ie(self, bssid: str, ssid: str, ie_id: int, ie_data: bytes) -> List[Finding]:
        """Validate QBSS Load Information Element."""
        return []  # Basic validation only
    
    def _validate_power_ie(self, bssid: str, ssid: str, ie_id: int, ie_data: bytes) -> List[Finding]:
        """Validate Power Constraint Information Element."""
        return []  # Basic validation only
    
    def _validate_rsn_ie(self, bssid: str, ssid: str, ie_id: int, ie_data: bytes) -> List[Finding]:
        """Validate RSN (WPA2) Information Element."""
        findings = []
        
        if len(ie_data) < 2:
            findings.append(Finding(
                category=AnalysisCategory.ENTERPRISE_SECURITY,
                severity=Severity.HIGH,
                title="Invalid RSN IE Length",
                description="RSN IE too short to contain version field",
                details={
                    "bssid": bssid,
                    "ssid": ssid,
                    "actual_length": len(ie_data),
                    "minimum_length": 2
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
        
        return findings
    
    def _validate_ext_rates_ie(self, bssid: str, ssid: str, ie_id: int, ie_data: bytes) -> List[Finding]:
        """Validate Extended Supported Rates Information Element."""
        return []  # Basic validation only
    
    def _validate_ht_info_ie(self, bssid: str, ssid: str, ie_id: int, ie_data: bytes) -> List[Finding]:
        """Validate HT Information Element."""
        return []  # Basic validation only
    
    def _validate_ext_cap_ie(self, bssid: str, ssid: str, ie_id: int, ie_data: bytes) -> List[Finding]:
        """Validate Extended Capabilities Information Element."""
        return []  # Basic validation only
    
    def _validate_vht_cap_ie(self, bssid: str, ssid: str, ie_id: int, ie_data: bytes) -> List[Finding]:
        """Validate VHT Capabilities Information Element."""
        return []  # Basic validation only
    
    def _validate_vendor_ie(self, bssid: str, ssid: str, ie_id: int, ie_data: bytes) -> List[Finding]:
        """Validate Vendor Specific Information Element."""
        findings = []
        
        if len(ie_data) < 3:
            findings.append(Finding(
                category=AnalysisCategory.BEACONS,
                severity=Severity.MEDIUM,
                title="Invalid Vendor IE Length",
                description="Vendor Specific IE must contain at least 3-byte OUI",
                details={
                    "bssid": bssid,
                    "ssid": ssid,
                    "actual_length": len(ie_data),
                    "minimum_length": 3
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
        
        return findings
    
    def _get_ie_name(self, ie_id: int) -> str:
        """Get human-readable name for IE ID."""
        ie_names = {
            0: "SSID",
            1: "Supported Rates",
            3: "DS Parameter Set",
            5: "Traffic Indication Map",
            7: "Country",
            11: "QBSS Load",
            32: "Power Constraint",
            48: "RSN",
            50: "Extended Supported Rates",
            61: "HT Information",
            127: "Extended Capabilities",
            191: "VHT Capabilities",
            221: "Vendor Specific"
        }
        return ie_names.get(ie_id, f"IE_{ie_id}")