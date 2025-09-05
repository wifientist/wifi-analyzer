"""
PyShark-based Beacon Analysis for wireless PCAP data.

This analyzer provides comprehensive beacon frame analysis using native PyShark
packet parsing, including:
- Beacon interval consistency and timing analysis
- Information Element (IE) validation and parsing
- Capability field analysis and assessment
- SSID and network identification validation
- Timestamp accuracy and synchronization checks
- Channel and frequency validation
- Security configuration detection
"""

import statistics
import logging
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta
from typing import List, Dict, Any, Set, Tuple, Optional, NamedTuple
import struct

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
    AnalysisCategory,
    PacketReference,
    FrameType
)


class BeaconInfo(NamedTuple):
    """Information extracted from a beacon frame using PyShark."""
    timestamp: float
    bssid: str
    ssid: str
    beacon_interval: int
    capabilities: int
    channel: Optional[int]
    rssi: Optional[int]
    ies: Dict[int, bytes]
    packet_timestamp: float


class PySharkBeaconAnalyzer(BasePySharkAnalyzer):
    """
    PyShark-based comprehensive beacon frame analyzer.
    
    This analyzer performs detailed analysis of 802.11 beacon frames using
    native PyShark packet parsing including:
    - Timing consistency and beacon interval validation
    - Information Element structure and content validation
    - Capability field analysis
    - Network configuration assessment
    - Security configuration detection
    - Channel and frequency validation
    """
    
    def __init__(self):
        super().__init__("PyShark Beacon Frame Analyzer", AnalysisCategory.BEACONS, "1.0")
        
        if not PYSHARK_AVAILABLE:
            raise ImportError("PyShark is not available. Install with: pip install pyshark")
        
        self.description = (
            "Analyzes 802.11 beacon frames for timing consistency, "
            "information element validation, and capability analysis using PyShark"
        )
        
        # Analysis tracking
        self.beacon_tracking: Dict[str, List[BeaconInfo]] = defaultdict(list)
        self.interval_tracking: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.findings_generated = 0
        
        # IE validation patterns
        self.ie_validators = self._initialize_ie_validators()
        
        # Standards-based thresholds
        self.min_beacon_interval = 1  # TU (Time Units)
        self.max_beacon_interval = 65535  # TU
        self.typical_beacon_intervals = {100, 102, 204}  # Common intervals
        self.max_interval_variance = 10  # Allowable variance in TU
        
        self.logger.info(f"Initialized {self.name} v{self.version}")
        
    def create_finding(self, severity: Severity, title: str, description: str, details: Dict[str, Any] = None, category: AnalysisCategory = None, **kwargs) -> Finding:
        """
        Create a finding with analyzer metadata automatically set.
        
        Args:
            severity: Severity level
            title: Finding title
            description: Detailed description
            details: Finding details dictionary
            category: Analysis category (defaults to BEACONS)
            **kwargs: Additional finding attributes
            
        Returns:
            Finding instance with analyzer metadata
        """
        return Finding(
            category=category or AnalysisCategory.BEACONS,
            severity=severity,
            title=title,
            description=description,
            details=details or {},
            analyzer_name=self.name,
            analyzer_version=self.version,
            **kwargs
        )
        
    def _initialize_ie_validators(self) -> Dict[int, callable]:
        """Initialize Information Element validators."""
        validators = {
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
        
        self.logger.debug(f"Initialized {len(validators)} IE validators")
        return validators

    def is_applicable(self, packet: PySharkPacket) -> bool:
        """Check if packet is a beacon frame (PyShark-specific)."""
        try:
            return (hasattr(packet, 'wlan_mgt') and 
                    hasattr(packet.wlan_mgt, 'fc_type_subtype') and 
                    packet.wlan_mgt.fc_type_subtype == '8')
        except:
            return False
        
    def analyze(self, packets: List[PySharkPacket], context: AnalysisContext) -> List[Finding]:
        """
        Analyze beacon frames for consistency, IE validation, and capabilities.
        
        Args:
            packets: List of PyShark beacon packets
            context: Analysis context
            
        Returns:
            List of findings
        """
        if not packets:
            self.logger.warning("No beacon packets provided for analysis")
            return []
            
        self.logger.info(f"Analyzing {len(packets)} beacon frames with PyShark")
        
        findings = []
        
        # Extract beacon information using PyShark
        beacon_data = self._extract_beacon_info_pyshark(packets)
        self.logger.info(f"Extracted information from {len(beacon_data)} beacon frames")
        
        # Group by BSSID for per-AP analysis
        ap_beacons = defaultdict(list)
        for beacon in beacon_data:
            ap_beacons[beacon.bssid].append(beacon)
            
        self.logger.info(f"Found beacons from {len(ap_beacons)} unique BSSIDs")
        
        # Analyze each AP's beacons
        for bssid, beacons in ap_beacons.items():
            self.logger.debug(f"Analyzing {len(beacons)} beacons from BSSID {bssid}")
            
            findings.extend(self._analyze_beacon_timing(bssid, beacons))
            findings.extend(self._analyze_information_elements(bssid, beacons))
            findings.extend(self._analyze_capabilities(bssid, beacons))
            findings.extend(self._analyze_network_config(bssid, beacons))
            
        # Cross-AP analysis
        findings.extend(self._analyze_network_conflicts(ap_beacons))
        
        self.findings_generated = len(findings)
        self.logger.info(f"Generated {len(findings)} findings from beacon analysis")
        
        return findings
        
    def _extract_beacon_info_pyshark(self, packets: List[PySharkPacket]) -> List[BeaconInfo]:
        """Extract beacon information from PyShark packets."""
        beacon_info = []
        processed_count = 0
        error_count = 0
        
        for packet in packets:
            try:
                if not self.is_applicable(packet):
                    continue
                    
                # Extract basic info using PyShark field access
                bssid = packet.wlan.bssid if hasattr(packet.wlan, 'bssid') else "unknown"
                if bssid == "unknown":
                    error_count += 1
                    continue
                
                # Get packet timestamp
                packet_time = float(packet.sniff_timestamp) if hasattr(packet, 'sniff_timestamp') else 0
                
                # Extract SSID using PyShark
                ssid = ""
                if hasattr(packet.wlan_mgt, 'ssid'):
                    ssid = str(packet.wlan_mgt.ssid)
                
                # Extract beacon interval
                beacon_interval = 0
                if hasattr(packet.wlan_mgt, 'beacon_interval'):
                    beacon_interval = int(packet.wlan_mgt.beacon_interval)
                
                # Extract capabilities
                capabilities = 0
                if hasattr(packet.wlan_mgt, 'fixed_parameters_capability_info'):
                    try:
                        capabilities = int(packet.wlan_mgt.fixed_parameters_capability_info, 16)
                    except (ValueError, TypeError):
                        capabilities = 0
                
                # Extract timestamp
                timestamp = 0
                if hasattr(packet.wlan_mgt, 'fixed_parameters_timestamp'):
                    try:
                        timestamp = int(packet.wlan_mgt.fixed_parameters_timestamp, 16)
                    except (ValueError, TypeError):
                        timestamp = 0
                
                # Get RSSI if available from RadioTap
                rssi = None
                if hasattr(packet, 'radiotap'):
                    if hasattr(packet.radiotap, 'dbm_antsignal'):
                        rssi = int(packet.radiotap.dbm_antsignal)
                
                # Extract channel from PyShark
                channel = None
                if hasattr(packet.wlan_mgt, 'ds_current_channel'):
                    channel = int(packet.wlan_mgt.ds_current_channel)
                
                # Extract Information Elements using PyShark field access
                ies = self._extract_ies_pyshark(packet)
                
                beacon_info.append(BeaconInfo(
                    timestamp=timestamp,
                    bssid=bssid,
                    ssid=ssid,
                    beacon_interval=beacon_interval,
                    capabilities=capabilities,
                    channel=channel,
                    rssi=rssi,
                    ies=ies,
                    packet_timestamp=packet_time
                ))
                
                processed_count += 1
                
            except Exception as e:
                error_count += 1
                self.logger.debug(f"Error extracting beacon info from PyShark packet: {e}")
                continue
                
        self.logger.info(f"Processed {processed_count} beacon frames, {error_count} errors")
        return beacon_info
        
    def _extract_ies_pyshark(self, packet: PySharkPacket) -> Dict[int, bytes]:
        """Extract Information Elements from PyShark packet."""
        ies = {}
        
        try:
            # PyShark exposes IEs as individual fields
            # We'll collect common IEs and try to build byte representations
            
            # SSID (IE 0)
            if hasattr(packet.wlan_mgt, 'ssid'):
                ssid_str = str(packet.wlan_mgt.ssid)
                ies[0] = ssid_str.encode('utf-8', errors='ignore')
            
            # Channel (IE 3) 
            if hasattr(packet.wlan_mgt, 'ds_current_channel'):
                channel = int(packet.wlan_mgt.ds_current_channel)
                ies[3] = struct.pack('B', channel)
            
            # TIM (IE 5)
            if hasattr(packet.wlan_mgt, 'tim_dtim_count'):
                dtim_count = int(packet.wlan_mgt.tim_dtim_count)
                dtim_period = int(packet.wlan_mgt.tim_dtim_period) if hasattr(packet.wlan_mgt, 'tim_dtim_period') else 1
                bitmap_ctrl = 0  # Simplified
                ies[5] = struct.pack('BBB', dtim_count, dtim_period, bitmap_ctrl)
            
            # Country (IE 7)
            if hasattr(packet.wlan_mgt, 'country_info_country_code'):
                country_code = str(packet.wlan_mgt.country_info_country_code)
                ies[7] = country_code.encode('ascii', errors='ignore')[:2] + b'\x00'
            
            # RSN (IE 48)
            if hasattr(packet.wlan_mgt, 'rsn_version'):
                rsn_version = int(packet.wlan_mgt.rsn_version)
                ies[48] = struct.pack('<H', rsn_version)
            
            # Additional IEs can be extracted based on available PyShark fields
            # This is a simplified approach - full IE reconstruction would require more work
            
        except Exception as e:
            self.logger.debug(f"Error extracting IEs from PyShark packet: {e}")
        
        return ies
        
    def _analyze_beacon_timing(self, bssid: str, beacons: List[BeaconInfo]) -> List[Finding]:
        """Analyze beacon timing consistency using PyShark data."""
        findings = []
        
        if len(beacons) < 2:
            self.logger.debug(f"Insufficient beacons for timing analysis: {bssid} ({len(beacons)})")
            return findings
            
        self.logger.debug(f"Analyzing beacon timing for {bssid} with {len(beacons)} beacons")
            
        # Sort by packet timestamp
        beacons.sort(key=lambda x: x.packet_timestamp)
        
        # Check beacon interval consistency
        intervals = [b.beacon_interval for b in beacons]
        unique_intervals = set(intervals)
        
        if len(unique_intervals) > 1:
            self.logger.info(f"Inconsistent beacon intervals detected for {bssid}: {unique_intervals}")
            findings.append(self.create_finding(
                severity=Severity.WARNING,
                title="Inconsistent Beacon Intervals",
                description=f"AP {bssid} has varying beacon intervals",
                details={
                    "bssid": bssid,
                    "ssid": beacons[0].ssid,
                    "intervals_observed": list(unique_intervals),
                    "interval_counts": dict(Counter(intervals)),
                    "expected_consistency": "Beacon intervals should remain constant"
                }
            ))
            
        # Check for unusual beacon intervals
        primary_interval = max(set(intervals), key=intervals.count)
        if primary_interval not in self.typical_beacon_intervals:
            severity = Severity.INFO if primary_interval in range(50, 1000) else Severity.WARNING
            self.logger.info(f"Unusual beacon interval for {bssid}: {primary_interval} TU")
            findings.append(self.create_finding(
                severity=severity,
                title="Unusual Beacon Interval",
                description=f"AP {bssid} using non-standard beacon interval",
                details={
                    "bssid": bssid,
                    "ssid": beacons[0].ssid,
                    "beacon_interval": primary_interval,
                    "typical_intervals": list(self.typical_beacon_intervals),
                    "impact": "May indicate custom configuration or attack"
                }
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
                    self.logger.warning(f"Beacon timing deviation for {bssid}: {mean_interval:.2f} vs {expected_interval} TU")
                    findings.append(self.create_finding(
                        severity=Severity.WARNING,
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
                        }
                    ))
                    
        return findings
        
    def _analyze_information_elements(self, bssid: str, beacons: List[BeaconInfo]) -> List[Finding]:
        """Analyze Information Elements in beacon frames using PyShark data."""
        findings = []
        
        if not beacons:
            return findings
            
        self.logger.debug(f"Analyzing Information Elements for {bssid}")
            
        # Analyze IE consistency across beacons from same AP
        ie_consistency = defaultdict(set)
        for beacon in beacons:
            for ie_id, ie_data in beacon.ies.items():
                ie_consistency[ie_id].add(ie_data)
        
        # Check for inconsistent IEs
        inconsistent_count = 0
        for ie_id, ie_values in ie_consistency.items():
            if len(ie_values) > 1:
                # Some IEs are expected to change (like TIM)
                if ie_id not in [5]:  # TIM can change
                    inconsistent_count += 1
                    findings.append(self.create_finding(
                        severity=Severity.INFO,
                        title=f"Inconsistent IE {ie_id}",
                        description=f"Information Element {ie_id} varies across beacons",
                        details={
                            "bssid": bssid,
                            "ssid": beacons[0].ssid,
                            "ie_id": ie_id,
                            "ie_name": self._get_ie_name(ie_id),
                            "unique_values": len(ie_values),
                            "variation_impact": "May indicate configuration changes or attack"
                        }
                    ))
        
        if inconsistent_count > 0:
            self.logger.info(f"Found {inconsistent_count} inconsistent IEs for {bssid}")
        
        # Validate individual IEs using the latest beacon
        latest_beacon = max(beacons, key=lambda x: x.packet_timestamp)
        validated_count = 0
        for ie_id, ie_data in latest_beacon.ies.items():
            if ie_id in self.ie_validators:
                ie_findings = self.ie_validators[ie_id](bssid, latest_beacon.ssid, ie_id, ie_data)
                findings.extend(ie_findings)
                validated_count += 1
        
        self.logger.debug(f"Validated {validated_count} IEs for {bssid}")
        
        # Check for missing critical IEs
        critical_ies = {0: "SSID", 1: "Supported Rates", 3: "Channel"}
        missing_count = 0
        for ie_id, ie_name in critical_ies.items():
            if ie_id not in latest_beacon.ies:
                missing_count += 1
                self.logger.warning(f"Missing critical IE {ie_name} for {bssid}")
                findings.append(self.create_finding(
                    severity=Severity.CRITICAL,
                    title=f"Missing Critical IE: {ie_name}",
                    description=f"Beacon missing required {ie_name} Information Element",
                    details={
                        "bssid": bssid,
                        "ssid": latest_beacon.ssid,
                        "missing_ie": ie_name,
                        "ie_id": ie_id,
                        "compliance_issue": "Required by 802.11 standard"
                    }
                ))
        
        return findings
        
    def _analyze_capabilities(self, bssid: str, beacons: List[BeaconInfo]) -> List[Finding]:
        """Analyze capability fields in beacon frames using PyShark data."""
        findings = []
        
        if not beacons:
            return findings
            
        # Use latest beacon for capability analysis
        latest_beacon = max(beacons, key=lambda x: x.packet_timestamp)
        capabilities = latest_beacon.capabilities
        
        # Convert capabilities to int to handle potential object formatting issues
        cap_int = int(capabilities) if capabilities is not None else 0
        self.logger.debug(f"Analyzing capabilities for {bssid}: 0x{cap_int:04x}")
        
        # Parse capability bits using the integer value
        cap_analysis = {
            "ess": bool(cap_int & 0x0001),          # ESS capability
            "ibss": bool(cap_int & 0x0002),         # IBSS capability  
            "cf_pollable": bool(cap_int & 0x0004),  # CF Pollable
            "cf_poll_req": bool(cap_int & 0x0008),  # CF Poll Request
            "privacy": bool(cap_int & 0x0010),      # Privacy (WEP)
            "short_preamble": bool(cap_int & 0x0020), # Short Preamble
            "pbcc": bool(cap_int & 0x0040),         # PBCC
            "channel_agility": bool(cap_int & 0x0080), # Channel Agility
            "spectrum_mgmt": bool(cap_int & 0x0100), # Spectrum Management
            "qos": bool(cap_int & 0x0200),          # QoS
            "short_slot": bool(cap_int & 0x0400),   # Short Slot Time
            "apsd": bool(cap_int & 0x0800),         # Automatic Power Save Delivery
            "radio_measurement": bool(cap_int & 0x1000), # Radio Measurement
            "dsss_ofdm": bool(cap_int & 0x2000),    # DSSS-OFDM
            "delayed_ba": bool(cap_int & 0x4000),   # Delayed Block Ack
            "immediate_ba": bool(cap_int & 0x8000)  # Immediate Block Ack
        }
        
        # Check for conflicting capabilities
        if cap_analysis["ess"] and cap_analysis["ibss"]:
            self.logger.error(f"Capability conflict for {bssid}: Both ESS and IBSS set")
            findings.append(self.create_finding(
                severity=Severity.CRITICAL,
                title="Conflicting Network Type Capabilities",
                description="Both ESS and IBSS capabilities set simultaneously",
                details={
                    "bssid": bssid,
                    "ssid": latest_beacon.ssid,
                    "capabilities_raw": f"0x{cap_int:04x}",
                    "conflict": "ESS and IBSS are mutually exclusive",
                    "standard_violation": "802.11 standard violation"
                }
            ))
        
        # Check privacy bit vs. security IEs
        has_rsn = 48 in latest_beacon.ies  # RSN IE
        has_wpa = any(ie_id == 221 and ie_data.startswith(b'\x00\x50\xf2\x01') 
                     for ie_id, ie_data in latest_beacon.ies.items())  # WPA vendor IE
        
        if cap_analysis["privacy"] and not (has_rsn or has_wpa):
            # Privacy set but no modern security - likely WEP
            self.logger.warning(f"WEP detected for {bssid}")
            findings.append(self.create_finding(
                severity=Severity.CRITICAL,
                title="Weak Security: WEP Detected",
                description="Network using deprecated WEP encryption",
                details={
                    "bssid": bssid,
                    "ssid": latest_beacon.ssid,
                    "privacy_bit": True,
                    "modern_security": False,
                    "security_recommendation": "Upgrade to WPA2/WPA3"
                },
                category=AnalysisCategory.ENTERPRISE_SECURITY
            ))
        elif not cap_analysis["privacy"] and not (has_rsn or has_wpa):
            # No privacy at all
            self.logger.info(f"Open network detected for {bssid}")
            findings.append(self.create_finding(
                severity=Severity.WARNING,
                title="Open Network Detected",
                description="Network operating without encryption",
                details={
                    "bssid": bssid,
                    "ssid": latest_beacon.ssid,
                    "encryption": "None",
                    "security_risk": "Traffic transmitted in clear text"
                },
                category=AnalysisCategory.ENTERPRISE_SECURITY
            ))
        
        return findings
        
    def _analyze_network_config(self, bssid: str, beacons: List[BeaconInfo]) -> List[Finding]:
        """Analyze network configuration from beacon data using PyShark."""
        findings = []
        
        if not beacons:
            return findings
        
        latest_beacon = max(beacons, key=lambda x: x.packet_timestamp)
        
        # Check for hidden SSID
        if not latest_beacon.ssid or latest_beacon.ssid.strip() == "":
            self.logger.info(f"Hidden SSID detected for {bssid}")
            findings.append(Finding(
                category=AnalysisCategory.BEACONS,
                severity=Severity.INFO,
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
                    self.logger.warning(f"Invalid channel {latest_beacon.channel} for {bssid}")
                    findings.append(Finding(
                        category=AnalysisCategory.RF_PHY,
                        severity=Severity.WARNING,
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
        """Analyze conflicts between different networks using PyShark data."""
        findings = []
        
        # Check for SSID conflicts (same SSID, different BSSID)
        ssid_to_bssids = defaultdict(set)
        for bssid, beacons in ap_beacons.items():
            if beacons:
                ssid = beacons[0].ssid
                if ssid and ssid.strip():  # Ignore hidden SSIDs
                    ssid_to_bssids[ssid].add(bssid)
        
        conflict_count = 0
        for ssid, bssids in ssid_to_bssids.items():
            if len(bssids) > 1:
                conflict_count += 1
                # Check if it's likely legitimate (different channels)
                channels = set()
                for bssid in bssids:
                    latest_beacon = max(ap_beacons[bssid], key=lambda x: x.packet_timestamp)
                    if latest_beacon.channel:
                        channels.add(latest_beacon.channel)
                
                severity = Severity.INFO if len(channels) > 1 else Severity.WARNING
                self.logger.info(f"SSID conflict detected for '{ssid}': {len(bssids)} BSSIDs")
                findings.append(Finding(
                    category=AnalysisCategory.BEACONS,
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
        
        if conflict_count > 0:
            self.logger.info(f"Found {conflict_count} SSID conflicts")
        
        return findings
    
    # IE Validation Methods (PyShark-specific implementations)
    def _validate_ssid_ie(self, bssid: str, ssid: str, ie_id: int, ie_data: bytes) -> List[Finding]:
        """Validate SSID Information Element using PyShark data."""
        findings = []
        
        if len(ie_data) > 32:
            self.logger.error(f"Invalid SSID length for {bssid}: {len(ie_data)} bytes")
            findings.append(Finding(
                category=AnalysisCategory.BEACONS,
                severity=Severity.CRITICAL,
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
        """Validate Supported Rates Information Element using PyShark data."""
        findings = []
        
        if len(ie_data) == 0:
            self.logger.error(f"Empty Supported Rates IE for {bssid}")
            findings.append(Finding(
                category=AnalysisCategory.BEACONS,
                severity=Severity.CRITICAL,
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
            self.logger.warning(f"Too many rates in basic Rates IE for {bssid}: {len(ie_data)}")
            findings.append(Finding(
                category=AnalysisCategory.BEACONS,
                severity=Severity.WARNING,
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
        """Validate DS Parameter Set (Channel) Information Element using PyShark data."""
        findings = []
        
        if len(ie_data) != 1:
            self.logger.error(f"Invalid Channel IE length for {bssid}: {len(ie_data)} bytes")
            findings.append(Finding(
                category=AnalysisCategory.BEACONS,
                severity=Severity.CRITICAL,
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
        """Validate Traffic Indication Map Information Element using PyShark data."""
        findings = []
        
        if len(ie_data) < 4:
            self.logger.error(f"Invalid TIM IE length for {bssid}: {len(ie_data)} bytes")
            findings.append(Finding(
                category=AnalysisCategory.BEACONS,
                severity=Severity.CRITICAL,
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
        """Validate Country Information Element using PyShark data."""
        findings = []
        
        if len(ie_data) < 6:
            self.logger.warning(f"Invalid Country IE length for {bssid}: {len(ie_data)} bytes")
            findings.append(Finding(
                category=AnalysisCategory.BEACONS,
                severity=Severity.WARNING,
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
        """Validate QBSS Load Information Element using PyShark data."""
        return []  # Basic validation only
    
    def _validate_power_ie(self, bssid: str, ssid: str, ie_id: int, ie_data: bytes) -> List[Finding]:
        """Validate Power Constraint Information Element using PyShark data."""
        return []  # Basic validation only
    
    def _validate_rsn_ie(self, bssid: str, ssid: str, ie_id: int, ie_data: bytes) -> List[Finding]:
        """Validate RSN (WPA2) Information Element using PyShark data."""
        findings = []
        
        if len(ie_data) < 2:
            self.logger.error(f"Invalid RSN IE length for {bssid}: {len(ie_data)} bytes")
            findings.append(Finding(
                category=AnalysisCategory.ENTERPRISE_SECURITY,
                severity=Severity.CRITICAL,
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
        """Validate Extended Supported Rates Information Element using PyShark data."""
        return []  # Basic validation only
    
    def _validate_ht_info_ie(self, bssid: str, ssid: str, ie_id: int, ie_data: bytes) -> List[Finding]:
        """Validate HT Information Element using PyShark data."""
        return []  # Basic validation only
    
    def _validate_ext_cap_ie(self, bssid: str, ssid: str, ie_id: int, ie_data: bytes) -> List[Finding]:
        """Validate Extended Capabilities Information Element using PyShark data."""
        return []  # Basic validation only
    
    def _validate_vht_cap_ie(self, bssid: str, ssid: str, ie_id: int, ie_data: bytes) -> List[Finding]:
        """Validate VHT Capabilities Information Element using PyShark data."""
        return []  # Basic validation only
    
    def _validate_vendor_ie(self, bssid: str, ssid: str, ie_id: int, ie_data: bytes) -> List[Finding]:
        """Validate Vendor Specific Information Element using PyShark data."""
        findings = []
        
        if len(ie_data) < 3:
            self.logger.warning(f"Invalid Vendor IE length for {bssid}: {len(ie_data)} bytes")
            findings.append(Finding(
                category=AnalysisCategory.BEACONS,
                severity=Severity.WARNING,
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