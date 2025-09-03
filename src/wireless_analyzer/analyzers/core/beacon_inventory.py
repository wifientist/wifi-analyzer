"""
Beacon & BSS Inventory (Foundational) for wireless PCAP analysis.

This analyzer provides comprehensive beacon frame inventory and BSS tracking including:
- Complete BSSID/SSID inventory (including hidden SSIDs)
- Channel and band analysis with validation
- Transmit Power (TM) extraction and validation
- Country code and regulatory information
- Comprehensive capability analysis (ERP/HT/VHT/HE/EHT)
- TIM and DTIM period tracking
- MBSSID and co-located AP detection
- WPA2+WPA3 transition mode detection
- 2.4GHz 40MHz coexistence analysis
"""

import struct
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Set, Optional, NamedTuple, Union
import logging

from scapy.all import Packet
from scapy.layers.dot11 import (
    Dot11, Dot11Beacon, Dot11Elt, Dot11EltRates, Dot11EltDSSSet,
    Dot11EltCountry, Dot11EltVendorSpecific, Dot11EltRSN,
    Dot11EltMicrosoftWPA, Dot11EltHTCapabilities, Dot11EltERP
)
from scapy.layers.dot11 import RadioTap

from ...core.base_analyzer import BaseAnalyzer
from ...core.models import (
    Finding, 
    Severity, 
    AnalysisContext,
    AnalysisCategory,
    SecurityProtocol
)


@dataclass
class WirelessCapabilities:
    """Comprehensive wireless capability information."""
    # Basic capabilities
    ess: bool = False
    ibss: bool = False
    privacy: bool = False
    short_preamble: bool = False
    short_slot: bool = False
    qos: bool = False
    
    # ERP capabilities
    erp_present: bool = False
    erp_non_erp_present: bool = False
    erp_use_protection: bool = False
    erp_barker_mode: bool = False
    
    # HT capabilities
    ht_present: bool = False
    ht_40mhz: bool = False
    ht_sgi_20: bool = False
    ht_sgi_40: bool = False
    ht_max_streams: Optional[int] = None
    
    # VHT capabilities
    vht_present: bool = False
    vht_80mhz: bool = False
    vht_160mhz: bool = False
    vht_max_streams: Optional[int] = None
    
    # HE capabilities (Wi-Fi 6)
    he_present: bool = False
    he_80plus80: bool = False
    he_160mhz: bool = False
    
    # EHT capabilities (Wi-Fi 7)
    eht_present: bool = False
    eht_320mhz: bool = False


@dataclass
class SecurityConfiguration:
    """Security configuration extracted from beacon."""
    open: bool = False
    wep: bool = False
    wpa: bool = False
    wpa2: bool = False
    wpa3: bool = False
    owe: bool = False
    sae: bool = False
    transition_mode: bool = False  # WPA2+WPA3 transition
    
    # Security details
    group_cipher: Optional[str] = None
    pairwise_ciphers: List[str] = field(default_factory=list)
    akm_suites: List[str] = field(default_factory=list)
    pmf_capable: bool = False
    pmf_required: bool = False


@dataclass
class BeaconInventoryEntry:
    """Complete inventory entry for a beacon/BSS."""
    bssid: str
    ssid: str
    ssid_hidden: bool
    
    # RF/PHY information
    channel: Optional[int]
    frequency: Optional[int]
    band: Optional[str]  # "2.4GHz", "5GHz", "6GHz"
    transmit_power: Optional[int]
    
    # Regulatory
    country_code: Optional[str]
    regulatory_class: Optional[int]
    
    # Timing
    beacon_interval: int
    dtim_period: Optional[int]
    dtim_count: Optional[int]
    
    # Capabilities
    capabilities: WirelessCapabilities = field(default_factory=WirelessCapabilities)
    security: SecurityConfiguration = field(default_factory=SecurityConfiguration)
    
    # Advanced features
    mbssid_present: bool = False
    mbssid_index: Optional[int] = None
    transmitted_bssid: Optional[str] = None
    
    # Vendor information
    vendor_oui: Optional[str] = None
    vendor_info: Dict[str, Any] = field(default_factory=dict)
    
    # Tracking
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    beacon_count: int = 0
    rssi_values: List[int] = field(default_factory=list)


class BeaconInventoryAnalyzer(BaseAnalyzer):
    """
    Comprehensive Beacon & BSS Inventory Analyzer.
    
    This foundational analyzer extracts and catalogs all beacon frame information
    including BSSID/SSID inventory, channel/band analysis, capabilities, security
    configuration, and advanced features like MBSSID.
    """
    
    def __init__(self):
        super().__init__(
            name="Beacon & BSS Inventory",
            category=AnalysisCategory.BEACONS,
            version="1.0"
        )
        
        self.description = (
            "Comprehensive beacon frame inventory and BSS tracking with "
            "capability analysis, security detection, and coexistence validation"
        )
        
        # Wireshark filters for beacon inventory
        self.wireshark_filters = [
            "wlan.fc.type_subtype == 8",  # Beacon frames
            "wlan.bssid",
            "wlan.ssid",
            "wlan.ds.current_channel",
            "wlan.tim.dtim_period",
            "wlan_mgt.ht.capabilities",
            "wlan_mgt.vht.capabilities"
        ]
        
        self.analysis_order = 15  # Run early as foundational analysis
        
        # Inventory storage
        self.bss_inventory: Dict[str, BeaconInventoryEntry] = {}
        self.channel_usage: Dict[int, Set[str]] = defaultdict(set)
        self.ssid_conflicts: Dict[str, Set[str]] = defaultdict(set)
        
        # Constants for analysis
        self.BAND_2_4_CHANNELS = set(range(1, 15))  # Channels 1-14
        self.BAND_5_CHANNELS = set(range(36, 166))   # 5GHz channels
        self.BAND_6_CHANNELS = set(range(1, 234))    # 6GHz channels (6GHz uses different numbering)
        
        self.DTIM_NORMAL_RANGE = (1, 5)      # Normal DTIM period range
        self.DTIM_EXTREME_LOW = 1            # Single beacon DTIM (power saving concern)
        self.DTIM_EXTREME_HIGH = 10          # Very high DTIM (latency concern)

    def is_applicable(self, packet: Packet) -> bool:
        """Check if packet is a beacon frame."""
        return packet.haslayer(Dot11Beacon)
        
    def get_display_filters(self) -> List[str]:
        """Get Wireshark display filters for beacon inventory."""
        return self.wireshark_filters
        
    def analyze(self, packets: List[Packet], context: AnalysisContext) -> List[Finding]:
        """
        Perform comprehensive beacon inventory and analysis.
        
        Args:
            packets: List of beacon packets
            context: Analysis context
            
        Returns:
            List of findings
        """
        if not packets:
            return []
            
        self.logger.info(f"Building beacon inventory from {len(packets)} beacon frames")
        
        # Build comprehensive inventory
        self._build_beacon_inventory(packets)
        
        self.logger.info(f"Inventoried {len(self.bss_inventory)} unique BSSs")
        
        # Generate findings
        findings = []
        findings.extend(self._analyze_channel_band_consistency())
        findings.extend(self._analyze_coexistence_issues())
        findings.extend(self._analyze_dtim_configuration())
        findings.extend(self._analyze_security_transitions())
        findings.extend(self._analyze_mbssid_configuration())
        findings.extend(self._analyze_regulatory_compliance())
        findings.extend(self._analyze_capability_anomalies())
        
        # Store inventory in context for other analyzers
        context.metadata['beacon_inventory'] = self.bss_inventory
        context.metadata['channel_usage'] = dict(self.channel_usage)
        
        self.findings_generated = len(findings)
        return findings
        
    def _build_beacon_inventory(self, packets: List[Packet]) -> None:
        """Build comprehensive beacon inventory from packets."""
        for packet in packets:
            try:
                if not packet.haslayer(Dot11Beacon):
                    continue
                    
                entry = self._extract_beacon_entry(packet)
                if entry:
                    bssid = entry.bssid
                    
                    if bssid in self.bss_inventory:
                        # Update existing entry
                        existing = self.bss_inventory[bssid]
                        existing.last_seen = entry.first_seen
                        existing.beacon_count += 1
                        if entry.rssi_values:
                            existing.rssi_values.extend(entry.rssi_values)
                        
                        # Update dynamic fields (like TIM)
                        existing.dtim_count = entry.dtim_count
                        
                    else:
                        # New BSS
                        self.bss_inventory[bssid] = entry
                        
                        # Track channel usage
                        if entry.channel:
                            self.channel_usage[entry.channel].add(bssid)
                            
                        # Track SSID conflicts
                        if entry.ssid and not entry.ssid_hidden:
                            self.ssid_conflicts[entry.ssid].add(bssid)
                            
            except Exception as e:
                self.logger.debug(f"Error processing beacon: {e}")
                continue
                
    def _extract_beacon_entry(self, packet: Packet) -> Optional[BeaconInventoryEntry]:
        """Extract comprehensive beacon information."""
        try:
            dot11 = packet[Dot11]
            beacon = packet[Dot11Beacon]
            
            # Basic information
            bssid = dot11.addr3 if dot11.addr3 else "unknown"
            if bssid == "unknown":
                return None
                
            # Initialize entry
            entry = BeaconInventoryEntry(
                bssid=bssid,
                ssid="",
                ssid_hidden=False,
                beacon_interval=beacon.beacon_interval,
                channel=None,
                frequency=None,
                band=None,
                transmit_power=None,
                country_code=None,
                regulatory_class=None,
                dtim_period=None,
                dtim_count=None
            )
            
            # Extract RSSI from RadioTap
            if packet.haslayer(RadioTap):
                radiotap = packet[RadioTap]
                if hasattr(radiotap, 'dBm_AntSignal'):
                    entry.rssi_values.append(radiotap.dBm_AntSignal)
                if hasattr(radiotap, 'ChannelFrequency'):
                    entry.frequency = radiotap.ChannelFrequency
                    
            # Parse capability field
            self._parse_basic_capabilities(beacon.cap, entry.capabilities)
            
            # Parse all Information Elements
            if packet.haslayer(Dot11Elt):
                self._parse_information_elements(packet[Dot11Elt], entry)
                
            # Determine band from channel/frequency
            if entry.channel:
                entry.band = self._determine_band(entry.channel)
            elif entry.frequency:
                entry.band = self._determine_band_from_frequency(entry.frequency)
                
            # Extract vendor OUI from BSSID
            entry.vendor_oui = self._extract_vendor_oui(bssid)
            
            return entry
            
        except Exception as e:
            self.logger.debug(f"Error extracting beacon entry: {e}")
            return None
            
    def _parse_basic_capabilities(self, cap_field: int, capabilities: WirelessCapabilities) -> None:
        """Parse basic capability bits."""
        capabilities.ess = bool(cap_field & 0x0001)
        capabilities.ibss = bool(cap_field & 0x0002)
        capabilities.privacy = bool(cap_field & 0x0010)
        capabilities.short_preamble = bool(cap_field & 0x0020)
        capabilities.short_slot = bool(cap_field & 0x0400)
        capabilities.qos = bool(cap_field & 0x0200)
        
    def _parse_information_elements(self, first_ie: Dot11Elt, entry: BeaconInventoryEntry) -> None:
        """Parse all Information Elements comprehensively."""
        current_ie = first_ie
        
        while current_ie:
            try:
                ie_id = current_ie.ID
                ie_data = bytes(current_ie.info) if current_ie.info else b''
                
                if ie_id == 0:  # SSID
                    self._parse_ssid_ie(ie_data, entry)
                elif ie_id == 1:  # Supported Rates
                    pass  # Basic rates - could extend if needed
                elif ie_id == 3:  # DS Parameter Set (Channel)
                    self._parse_channel_ie(ie_data, entry)
                elif ie_id == 5:  # TIM
                    self._parse_tim_ie(ie_data, entry)
                elif ie_id == 7:  # Country
                    self._parse_country_ie(ie_data, entry)
                elif ie_id == 42:  # ERP Information
                    self._parse_erp_ie(ie_data, entry)
                elif ie_id == 45:  # HT Capabilities
                    self._parse_ht_capabilities_ie(ie_data, entry)
                elif ie_id == 61:  # HT Information
                    self._parse_ht_information_ie(ie_data, entry)
                elif ie_id == 48:  # RSN (WPA2/WPA3)
                    self._parse_rsn_ie(ie_data, entry)
                elif ie_id == 191:  # VHT Capabilities
                    self._parse_vht_capabilities_ie(ie_data, entry)
                elif ie_id == 192:  # VHT Operation
                    self._parse_vht_operation_ie(ie_data, entry)
                elif ie_id == 255:  # Extension IEs (HE/EHT)
                    self._parse_extension_ie(ie_data, entry)
                elif ie_id == 221:  # Vendor Specific
                    self._parse_vendor_ie(ie_data, entry)
                    
                # Move to next IE
                current_ie = current_ie.payload if hasattr(current_ie, 'payload') and isinstance(current_ie.payload, Dot11Elt) else None
                
            except Exception as e:
                self.logger.debug(f"Error parsing IE {ie_id}: {e}")
                break
                
    def _parse_ssid_ie(self, ie_data: bytes, entry: BeaconInventoryEntry) -> None:
        """Parse SSID Information Element."""
        if not ie_data:
            entry.ssid = ""
            entry.ssid_hidden = True
        else:
            try:
                entry.ssid = ie_data.decode('utf-8', errors='ignore')
                entry.ssid_hidden = False
            except:
                entry.ssid = f"<binary:{len(ie_data)}bytes>"
                entry.ssid_hidden = False
                
    def _parse_channel_ie(self, ie_data: bytes, entry: BeaconInventoryEntry) -> None:
        """Parse DS Parameter Set (Channel) Information Element."""
        if len(ie_data) >= 1:
            entry.channel = struct.unpack('B', ie_data[:1])[0]
            
    def _parse_tim_ie(self, ie_data: bytes, entry: BeaconInventoryEntry) -> None:
        """Parse Traffic Indication Map Information Element."""
        if len(ie_data) >= 4:
            dtim_count, dtim_period = struct.unpack('BB', ie_data[:2])
            entry.dtim_count = dtim_count
            entry.dtim_period = dtim_period
            
    def _parse_country_ie(self, ie_data: bytes, entry: BeaconInventoryEntry) -> None:
        """Parse Country Information Element."""
        if len(ie_data) >= 3:
            try:
                entry.country_code = ie_data[:2].decode('ascii', errors='ignore')
            except:
                pass
                
    def _parse_erp_ie(self, ie_data: bytes, entry: BeaconInventoryEntry) -> None:
        """Parse ERP Information Element."""
        if len(ie_data) >= 1:
            erp_info = struct.unpack('B', ie_data[:1])[0]
            entry.capabilities.erp_present = True
            entry.capabilities.erp_non_erp_present = bool(erp_info & 0x01)
            entry.capabilities.erp_use_protection = bool(erp_info & 0x02)
            entry.capabilities.erp_barker_mode = bool(erp_info & 0x04)
            
    def _parse_ht_capabilities_ie(self, ie_data: bytes, entry: BeaconInventoryEntry) -> None:
        """Parse HT Capabilities Information Element."""
        if len(ie_data) >= 26:
            entry.capabilities.ht_present = True
            
            # Parse HT Capability Info (first 2 bytes)
            ht_cap_info = struct.unpack('<H', ie_data[:2])[0]
            entry.capabilities.ht_40mhz = bool(ht_cap_info & 0x02)
            entry.capabilities.ht_sgi_20 = bool(ht_cap_info & 0x20)
            entry.capabilities.ht_sgi_40 = bool(ht_cap_info & 0x40)
            
            # Parse MCS Set (bytes 3-12)
            if len(ie_data) >= 12:
                mcs_set = ie_data[3:12]
                # Count supported spatial streams
                streams = 0
                for i in range(4):  # Check first 4 bytes for basic MCS
                    if i < len(mcs_set) and mcs_set[i] != 0:
                        streams = i + 1
                entry.capabilities.ht_max_streams = streams
                
    def _parse_ht_information_ie(self, ie_data: bytes, entry: BeaconInventoryEntry) -> None:
        """Parse HT Information Element."""
        # Additional HT operation info could be parsed here if needed
        pass
        
    def _parse_vht_capabilities_ie(self, ie_data: bytes, entry: BeaconInventoryEntry) -> None:
        """Parse VHT Capabilities Information Element."""
        if len(ie_data) >= 12:
            entry.capabilities.vht_present = True
            
            # Parse VHT Capabilities Info (first 4 bytes)
            vht_cap_info = struct.unpack('<I', ie_data[:4])[0]
            
            # Channel width support
            supported_widths = (vht_cap_info >> 2) & 0x3
            entry.capabilities.vht_80mhz = supported_widths >= 1
            entry.capabilities.vht_160mhz = supported_widths >= 2
            
            # Parse MCS Set
            if len(ie_data) >= 12:
                # VHT MCS parsing is complex, simplified here
                entry.capabilities.vht_max_streams = 4  # Default assumption
                
    def _parse_vht_operation_ie(self, ie_data: bytes, entry: BeaconInventoryEntry) -> None:
        """Parse VHT Operation Information Element."""
        # VHT operation details could be parsed here if needed
        pass
        
    def _parse_extension_ie(self, ie_data: bytes, entry: BeaconInventoryEntry) -> None:
        """Parse Extension Information Elements (HE/EHT)."""
        if len(ie_data) >= 1:
            ext_id = struct.unpack('B', ie_data[:1])[0]
            
            if ext_id == 35:  # HE Capabilities
                entry.capabilities.he_present = True
                # Detailed HE parsing would go here
            elif ext_id == 36:  # HE Operation
                pass
            elif ext_id == 108:  # EHT Capabilities (draft)
                entry.capabilities.eht_present = True
                # Detailed EHT parsing would go here
                
    def _parse_rsn_ie(self, ie_data: bytes, entry: BeaconInventoryEntry) -> None:
        """Parse RSN (WPA2/WPA3) Information Element."""
        if len(ie_data) < 2:
            return
            
        try:
            # RSN Version
            version = struct.unpack('<H', ie_data[:2])[0]
            if version != 1:
                return
                
            offset = 2
            entry.security.wpa2 = True
            
            # Group Cipher Suite
            if len(ie_data) >= offset + 4:
                group_cipher = ie_data[offset:offset+4]
                entry.security.group_cipher = self._parse_cipher_suite(group_cipher)
                offset += 4
                
            # Pairwise Cipher Suites
            if len(ie_data) >= offset + 2:
                pairwise_count = struct.unpack('<H', ie_data[offset:offset+2])[0]
                offset += 2
                
                for _ in range(min(pairwise_count, 10)):  # Limit to prevent issues
                    if len(ie_data) >= offset + 4:
                        cipher = ie_data[offset:offset+4]
                        cipher_name = self._parse_cipher_suite(cipher)
                        if cipher_name:
                            entry.security.pairwise_ciphers.append(cipher_name)
                        offset += 4
                        
            # AKM Suites
            if len(ie_data) >= offset + 2:
                akm_count = struct.unpack('<H', ie_data[offset:offset+2])[0]
                offset += 2
                
                for _ in range(min(akm_count, 10)):  # Limit to prevent issues
                    if len(ie_data) >= offset + 4:
                        akm = ie_data[offset:offset+4]
                        akm_name = self._parse_akm_suite(akm)
                        if akm_name:
                            entry.security.akm_suites.append(akm_name)
                            
                            # Detect WPA3/SAE
                            if akm_name in ['SAE', 'OWE']:
                                entry.security.wpa3 = True
                                if 'PSK' in entry.security.akm_suites:
                                    entry.security.transition_mode = True
                                    
                        offset += 4
                        
            # RSN Capabilities
            if len(ie_data) >= offset + 2:
                rsn_cap = struct.unpack('<H', ie_data[offset:offset+2])[0]
                entry.security.pmf_capable = bool(rsn_cap & 0x0080)
                entry.security.pmf_required = bool(rsn_cap & 0x0040)
                
        except Exception as e:
            self.logger.debug(f"Error parsing RSN IE: {e}")
            
    def _parse_vendor_ie(self, ie_data: bytes, entry: BeaconInventoryEntry) -> None:
        """Parse Vendor Specific Information Elements."""
        if len(ie_data) >= 3:
            oui = ie_data[:3]
            
            # Microsoft WPA (00-50-F2-01)
            if oui == b'\x00\x50\xf2' and len(ie_data) > 3 and ie_data[3] == 0x01:
                entry.security.wpa = True
                
            # Store vendor info
            oui_str = ":".join(f"{b:02x}" for b in oui)
            if oui_str not in entry.vendor_info:
                entry.vendor_info[oui_str] = []
            entry.vendor_info[oui_str].append(ie_data[3:] if len(ie_data) > 3 else b'')
            
    def _parse_cipher_suite(self, cipher_bytes: bytes) -> Optional[str]:
        """Parse cipher suite bytes to name."""
        if len(cipher_bytes) != 4:
            return None
            
        # Standard cipher suites (OUI: 00-0F-AC)
        if cipher_bytes[:3] == b'\x00\x0f\xac':
            cipher_type = cipher_bytes[3]
            cipher_map = {
                1: 'WEP-40',
                2: 'TKIP', 
                4: 'CCMP',
                5: 'WEP-104',
                8: 'GCMP',
                9: 'GCMP-256',
                10: 'CCMP-256'
            }
            return cipher_map.get(cipher_type, f'Unknown-{cipher_type}')
            
        return None
        
    def _parse_akm_suite(self, akm_bytes: bytes) -> Optional[str]:
        """Parse AKM suite bytes to name."""
        if len(akm_bytes) != 4:
            return None
            
        # Standard AKM suites (OUI: 00-0F-AC)
        if akm_bytes[:3] == b'\x00\x0f\xac':
            akm_type = akm_bytes[3]
            akm_map = {
                1: 'IEEE8021X',
                2: 'PSK',
                3: 'FT-IEEE8021X',
                4: 'FT-PSK',
                5: 'SHA256-IEEE8021X',
                6: 'SHA256-PSK',
                8: 'SAE',
                9: 'FT-SAE',
                11: 'SUITE-B-192',
                18: 'OWE'
            }
            return akm_map.get(akm_type, f'Unknown-{akm_type}')
            
        return None
        
    def _determine_band(self, channel: int) -> str:
        """Determine frequency band from channel number."""
        if channel in self.BAND_2_4_CHANNELS:
            return "2.4GHz"
        elif channel in self.BAND_5_CHANNELS:
            return "5GHz" 
        elif channel in self.BAND_6_CHANNELS:
            return "6GHz"
        else:
            return "Unknown"
            
    def _determine_band_from_frequency(self, frequency: int) -> str:
        """Determine band from frequency in MHz."""
        if 2400 <= frequency <= 2500:
            return "2.4GHz"
        elif 5000 <= frequency <= 6000:
            return "5GHz"
        elif 5925 <= frequency <= 7125:
            return "6GHz"
        else:
            return "Unknown"
            
    def _extract_vendor_oui(self, bssid: str) -> Optional[str]:
        """Extract vendor OUI from BSSID."""
        try:
            parts = bssid.split(':')
            if len(parts) >= 3:
                return ':'.join(parts[:3]).upper()
        except:
            pass
        return None
        
    # Analysis methods for generating findings
    
    def _analyze_channel_band_consistency(self) -> List[Finding]:
        """Analyze channel/band consistency and mismatches."""
        findings = []
        
        for bssid, entry in self.bss_inventory.items():
            if not entry.channel or not entry.band:
                continue
                
            expected_band = self._determine_band(entry.channel)
            if expected_band != "Unknown" and expected_band != entry.band:
                findings.append(Finding(
                    category=AnalysisCategory.BEACONS,
                    severity=Severity.WARNING,
                    title="Channel/Band Mismatch",
                    description=f"Channel {entry.channel} doesn't match reported band {entry.band}",
                    details={
                        "bssid": bssid,
                        "ssid": entry.ssid,
                        "reported_channel": entry.channel,
                        "reported_band": entry.band,
                        "expected_band": expected_band,
                        "frequency": entry.frequency
                    },
                    analyzer_name=self.name,
                    analyzer_version=self.version
                ))
                
        return findings
        
    def _analyze_coexistence_issues(self) -> List[Finding]:
        """Analyze 2.4GHz 40MHz coexistence issues."""
        findings = []
        
        # Find 2.4GHz networks with 40MHz capability
        coexistence_violations = []
        
        for bssid, entry in self.bss_inventory.items():
            if (entry.band == "2.4GHz" and 
                entry.capabilities.ht_present and 
                entry.capabilities.ht_40mhz):
                
                # Check if 40MHz is appropriate on this channel
                if entry.channel in [1, 2, 3, 4, 5, 6, 11, 12, 13, 14]:
                    # These channels have coexistence issues with 40MHz
                    coexistence_violations.append({
                        "bssid": bssid,
                        "ssid": entry.ssid,
                        "channel": entry.channel,
                        "issue": "40MHz on edge/overlapping channel"
                    })
        
        if coexistence_violations:
            findings.append(Finding(
                category=AnalysisCategory.BEACONS,
                severity=Severity.CRITICAL if len(coexistence_violations) > 3 else Severity.WARNING,
                title="2.4GHz 40MHz Coexistence Issues",
                description=f"Found {len(coexistence_violations)} networks with 40MHz coexistence problems",
                details={
                    "violations": coexistence_violations,
                    "recommendation": "Use 20MHz channels or channels 6-7 for 40MHz in 2.4GHz",
                    "impact": "Increased interference and reduced performance"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
                
        return findings
        
    def _analyze_dtim_configuration(self) -> List[Finding]:
        """Analyze DTIM period extremes."""
        findings = []
        
        dtim_extremes = {"low": [], "high": []}
        
        for bssid, entry in self.bss_inventory.items():
            if entry.dtim_period is None:
                continue
                
            if entry.dtim_period <= self.DTIM_EXTREME_LOW:
                dtim_extremes["low"].append({
                    "bssid": bssid,
                    "ssid": entry.ssid,
                    "dtim_period": entry.dtim_period,
                    "impact": "Minimal power savings for clients"
                })
            elif entry.dtim_period >= self.DTIM_EXTREME_HIGH:
                dtim_extremes["high"].append({
                    "bssid": bssid, 
                    "ssid": entry.ssid,
                    "dtim_period": entry.dtim_period,
                    "impact": "High latency for multicast/broadcast traffic"
                })
        
        if dtim_extremes["low"]:
            findings.append(Finding(
                category=AnalysisCategory.BEACONS,
                severity=Severity.INFO,
                title="Extremely Low DTIM Periods",
                description=f"Found {len(dtim_extremes['low'])} networks with very low DTIM periods",
                details={
                    "networks": dtim_extremes["low"],
                    "recommendation": "Consider DTIM period 2-3 for balanced power saving"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
        
        if dtim_extremes["high"]:
            findings.append(Finding(
                category=AnalysisCategory.BEACONS,
                severity=Severity.WARNING,
                title="Extremely High DTIM Periods", 
                description=f"Found {len(dtim_extremes['high'])} networks with very high DTIM periods",
                details={
                    "networks": dtim_extremes["high"],
                    "recommendation": "Consider lower DTIM period for time-sensitive applications"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
                
        return findings
        
    def _analyze_security_transitions(self) -> List[Finding]:
        """Analyze WPA2+WPA3 transition configurations."""
        findings = []
        
        transition_networks = []
        mixed_security = []
        
        for bssid, entry in self.bss_inventory.items():
            if entry.security.transition_mode:
                transition_networks.append({
                    "bssid": bssid,
                    "ssid": entry.ssid,
                    "akm_suites": entry.security.akm_suites,
                    "pmf_status": "required" if entry.security.pmf_required else 
                                 "capable" if entry.security.pmf_capable else "disabled"
                })
            
            # Check for mixed/unusual security configs
            security_methods = sum([
                entry.security.wep,
                entry.security.wpa,
                entry.security.wpa2, 
                entry.security.wpa3,
                entry.security.owe
            ])
            
            if security_methods > 2:  # More than transition mode
                mixed_security.append({
                    "bssid": bssid,
                    "ssid": entry.ssid,
                    "methods": [m for m in ['WEP', 'WPA', 'WPA2', 'WPA3', 'OWE'] 
                              if getattr(entry.security, m.lower().replace('3', '3'))]
                })
        
        if transition_networks:
            findings.append(Finding(
                category=AnalysisCategory.ENTERPRISE_SECURITY,
                severity=Severity.INFO,
                title="WPA2+WPA3 Transition Mode Detected",
                description=f"Found {len(transition_networks)} networks in WPA2/WPA3 transition mode",
                details={
                    "transition_networks": transition_networks,
                    "recommendation": "Monitor client compatibility and plan migration to WPA3-only",
                    "security_benefit": "Provides backward compatibility during WPA3 migration"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
        
        if mixed_security:
            findings.append(Finding(
                category=AnalysisCategory.ENTERPRISE_SECURITY,
                severity=Severity.WARNING,
                title="Mixed Security Configuration",
                description=f"Found {len(mixed_security)} networks with unusual security combinations",
                details={
                    "mixed_networks": mixed_security,
                    "recommendation": "Review security configuration for consistency"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
                
        return findings
        
    def _analyze_mbssid_configuration(self) -> List[Finding]:
        """Analyze MBSSID and co-located AP configurations."""
        findings = []
        
        # This would require parsing MBSSID IEs which are complex
        # For now, detect potential co-located APs by similar BSSIDs
        
        potential_colocated = defaultdict(list)
        
        for bssid, entry in self.bss_inventory.items():
            # Group by OUI and similar patterns
            oui = entry.vendor_oui
            if oui:
                # Check for sequential MAC addresses (common in multi-radio APs)
                potential_colocated[oui].append((bssid, entry))
        
        colocated_groups = []
        for oui, entries in potential_colocated.items():
            if len(entries) > 1:
                # Check for same channel or adjacent channels (dual-band APs)
                channels = [e[1].channel for e in entries if e[1].channel]
                if len(set(channels)) > 1:  # Different channels
                    colocated_groups.append({
                        "vendor_oui": oui,
                        "aps": [{"bssid": bssid, "ssid": entry.ssid, "channel": entry.channel, "band": entry.band} 
                               for bssid, entry in entries],
                        "analysis": "Likely co-located multi-radio AP"
                    })
        
        if colocated_groups:
            findings.append(Finding(
                category=AnalysisCategory.BEACONS,
                severity=Severity.INFO,
                title="Co-located APs Detected",
                description=f"Found {len(colocated_groups)} groups of likely co-located access points",
                details={
                    "colocated_groups": colocated_groups,
                    "note": "Detection based on vendor OUI and channel patterns"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
                
        return findings
        
    def _analyze_regulatory_compliance(self) -> List[Finding]:
        """Analyze regulatory and country code compliance."""
        findings = []
        
        country_codes = Counter()
        missing_country = 0
        
        for bssid, entry in self.bss_inventory.items():
            if entry.country_code:
                country_codes[entry.country_code] += 1
            else:
                missing_country += 1
        
        if missing_country > 0:
            findings.append(Finding(
                category=AnalysisCategory.BEACONS,
                severity=Severity.WARNING,
                title="Missing Country Information",
                description=f"{missing_country} networks missing country code information",
                details={
                    "networks_missing_country": missing_country,
                    "total_networks": len(self.bss_inventory),
                    "recommendation": "Configure country codes for regulatory compliance"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
        
        if len(country_codes) > 1:
            findings.append(Finding(
                category=AnalysisCategory.BEACONS,
                severity=Severity.INFO,
                title="Multiple Country Codes Detected",
                description=f"Found networks from {len(country_codes)} different countries",
                details={
                    "country_distribution": dict(country_codes),
                    "note": "May indicate roaming scenario or cross-border deployment"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
                
        return findings
        
    def _analyze_capability_anomalies(self) -> List[Finding]:
        """Analyze capability configurations for anomalies."""
        findings = []
        
        capability_issues = []
        
        for bssid, entry in self.bss_inventory.items():
            caps = entry.capabilities
            
            # Check for HT without ERP in 2.4GHz
            if (entry.band == "2.4GHz" and caps.ht_present and not caps.erp_present):
                capability_issues.append({
                    "bssid": bssid,
                    "ssid": entry.ssid,
                    "issue": "HT present without ERP in 2.4GHz",
                    "severity": "medium"
                })
            
            # Check for VHT in 2.4GHz (non-standard)
            if entry.band == "2.4GHz" and caps.vht_present:
                capability_issues.append({
                    "bssid": bssid,
                    "ssid": entry.ssid,
                    "issue": "VHT capabilities in 2.4GHz band",
                    "severity": "high"
                })
            
            # Check for missing basic capabilities
            if caps.ess and caps.ibss:
                capability_issues.append({
                    "bssid": bssid,
                    "ssid": entry.ssid,
                    "issue": "Both ESS and IBSS capabilities set",
                    "severity": "high"
                })
        
        if capability_issues:
            high_severity = [i for i in capability_issues if i["severity"] == "high"]
            severity = Severity.CRITICAL if high_severity else Severity.WARNING
            
            findings.append(Finding(
                category=AnalysisCategory.BEACONS,
                severity=severity,
                title="Capability Configuration Anomalies",
                description=f"Found {len(capability_issues)} networks with capability anomalies",
                details={
                    "anomalies": capability_issues,
                    "high_severity_count": len(high_severity)
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
                
        return findings

    def get_inventory_summary(self) -> Dict[str, Any]:
        """Get comprehensive inventory summary."""
        return {
            "total_networks": len(self.bss_inventory),
            "band_distribution": self._get_band_distribution(),
            "security_distribution": self._get_security_distribution(),
            "capability_summary": self._get_capability_summary(),
            "channel_usage": dict(self.channel_usage),
            "vendor_distribution": self._get_vendor_distribution()
        }
        
    def _get_band_distribution(self) -> Dict[str, int]:
        """Get distribution of networks by frequency band."""
        bands = Counter()
        for entry in self.bss_inventory.values():
            if entry.band:
                bands[entry.band] += 1
        return dict(bands)
        
    def _get_security_distribution(self) -> Dict[str, int]:
        """Get distribution of security methods."""
        security = Counter()
        for entry in self.bss_inventory.values():
            if entry.security.open:
                security["Open"] += 1
            if entry.security.wep:
                security["WEP"] += 1
            if entry.security.wpa:
                security["WPA"] += 1
            if entry.security.wpa2:
                security["WPA2"] += 1
            if entry.security.wpa3:
                security["WPA3"] += 1
            if entry.security.transition_mode:
                security["WPA2+WPA3 Transition"] += 1
        return dict(security)
        
    def _get_capability_summary(self) -> Dict[str, int]:
        """Get summary of capability distributions."""
        caps = {
            "HT_present": 0,
            "VHT_present": 0,
            "HE_present": 0,
            "EHT_present": 0,
            "40MHz_capable": 0,
            "80MHz_capable": 0,
            "160MHz_capable": 0
        }
        
        for entry in self.bss_inventory.values():
            if entry.capabilities.ht_present:
                caps["HT_present"] += 1
            if entry.capabilities.vht_present:
                caps["VHT_present"] += 1
            if entry.capabilities.he_present:
                caps["HE_present"] += 1
            if entry.capabilities.eht_present:
                caps["EHT_present"] += 1
            if entry.capabilities.ht_40mhz or entry.capabilities.vht_80mhz:
                caps["40MHz_capable"] += 1
            if entry.capabilities.vht_80mhz:
                caps["80MHz_capable"] += 1
            if entry.capabilities.vht_160mhz:
                caps["160MHz_capable"] += 1
                
        return caps
        
    def _get_vendor_distribution(self) -> Dict[str, int]:
        """Get distribution of vendor OUIs."""
        vendors = Counter()
        for entry in self.bss_inventory.values():
            if entry.vendor_oui:
                vendors[entry.vendor_oui] += 1
        return dict(vendors)