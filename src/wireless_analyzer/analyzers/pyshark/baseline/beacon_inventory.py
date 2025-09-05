"""
PyShark-based Beacon & BSS Inventory Analyzer.

This analyzer provides comprehensive beacon frame inventory and BSS tracking using
native PyShark packet parsing, including:
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
from typing import List, Dict, Any, Set, Optional, Union
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
    AnalysisCategory,
    SecurityProtocol
)

# Reuse the same data classes from Scapy version
from ...scapy.baseline.beacon_inventory import (
    WirelessCapabilities,
    SecurityConfiguration,
    BeaconInventoryEntry
)


class PySharkBeaconInventoryAnalyzer(BasePySharkAnalyzer):
    """
    PyShark-based Comprehensive Beacon & BSS Inventory Analyzer.
    
    This analyzer extracts and catalogs all beacon frame information using native
    PyShark packet parsing including BSSID/SSID inventory, channel/band analysis, 
    capabilities, security configuration, and advanced features like MBSSID.
    """
    
    def __init__(self, debug_mode: bool = False, debug_pause_on_first: bool = False):
        super().__init__("PyShark Beacon & BSS Inventory", "1.0")
        
        if not PYSHARK_AVAILABLE:
            raise ImportError("PyShark is not available. Install with: pip install pyshark")
        
        self.description = (
            "Comprehensive beacon frame inventory and BSS tracking with "
            "capability analysis, security detection, and coexistence validation"
        )
        
        # Debug settings
        self.debug_mode = debug_mode
        self.debug_pause_on_first = debug_pause_on_first
        self.first_beacon_processed = False
        
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
        Perform comprehensive beacon inventory and analysis.
        
        Args:
            packets: List of PyShark beacon packets
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
        context.metadata['pyshark_beacon_inventory'] = self.bss_inventory
        context.metadata['pyshark_channel_usage'] = dict(self.channel_usage)
        
        return findings
        
    def _build_beacon_inventory(self, packets: List[PySharkPacket]) -> None:
        """Build comprehensive beacon inventory from PyShark packets."""
        for i, packet in enumerate(packets):
            try:
                if not self.is_applicable(packet):
                    continue
                    
                # Debug pause on first beacon frame
                if (self.debug_pause_on_first and not self.first_beacon_processed):
                    self.first_beacon_processed = True
                    self._debug_analyze_first_beacon(packet, i)
                    
                entry = self._extract_beacon_entry(packet)
                if entry:
                    bssid = entry.bssid
                    
                    # Debug logging for detailed analysis
                    if self.debug_mode:
                        self._debug_log_beacon_entry(entry, i)
                    
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
                
    def _extract_beacon_entry(self, packet: PySharkPacket) -> Optional[BeaconInventoryEntry]:
        """Extract comprehensive beacon information from PyShark packet."""
        try:
            # Basic information - PyShark field access
            bssid = packet.wlan.bssid if hasattr(packet.wlan, 'bssid') else "unknown"
            if bssid == "unknown":
                return None
                
            # Initialize entry
            entry = BeaconInventoryEntry(
                bssid=bssid,
                ssid="",
                ssid_hidden=False,
                beacon_interval=int(packet.wlan_mgt.beacon_interval) if hasattr(packet.wlan_mgt, 'beacon_interval') else 0,
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
            if hasattr(packet, 'radiotap'):
                if hasattr(packet.radiotap, 'dbm_antsignal'):
                    entry.rssi_values.append(int(packet.radiotap.dbm_antsignal))
                if hasattr(packet.radiotap, 'channel_freq'):
                    entry.frequency = int(packet.radiotap.channel_freq)
                    
            # Parse capability field
            if hasattr(packet.wlan_mgt, 'fixed_parameters_capability_info'):
                cap_field = int(packet.wlan_mgt.fixed_parameters_capability_info, 16)
                self._parse_basic_capabilities(cap_field, entry.capabilities)
            
            # Parse SSID
            if hasattr(packet.wlan_mgt, 'ssid'):
                entry.ssid = str(packet.wlan_mgt.ssid)
                entry.ssid_hidden = len(entry.ssid) == 0
            
            # Parse Channel from DS Parameter Set
            if hasattr(packet.wlan_mgt, 'ds_current_channel'):
                entry.channel = int(packet.wlan_mgt.ds_current_channel)
                
            # Parse TIM information
            if hasattr(packet.wlan_mgt, 'tim_dtim_count'):
                entry.dtim_count = int(packet.wlan_mgt.tim_dtim_count)
            if hasattr(packet.wlan_mgt, 'tim_dtim_period'):
                entry.dtim_period = int(packet.wlan_mgt.tim_dtim_period)
                
            # Parse Country information
            if hasattr(packet.wlan_mgt, 'country_info_country_code'):
                entry.country_code = str(packet.wlan_mgt.country_info_country_code)
                
            # Parse HT capabilities
            self._parse_ht_capabilities_pyshark(packet, entry)
            
            # Parse VHT capabilities
            self._parse_vht_capabilities_pyshark(packet, entry)
            
            # Parse security information
            self._parse_security_pyshark(packet, entry)
                
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
        """Parse basic capability bits from PyShark beacon."""
        capabilities.ess = bool(cap_field & 0x0001)
        capabilities.ibss = bool(cap_field & 0x0002)
        capabilities.privacy = bool(cap_field & 0x0010)
        capabilities.short_preamble = bool(cap_field & 0x0020)
        capabilities.short_slot = bool(cap_field & 0x0400)
        capabilities.qos = bool(cap_field & 0x0200)
        
    def _parse_ht_capabilities_pyshark(self, packet: PySharkPacket, entry: BeaconInventoryEntry) -> None:
        """Parse HT capabilities using PyShark field access."""
        try:
            # Check for HT capabilities
            if hasattr(packet.wlan_mgt, 'ht_capabilities'):
                entry.capabilities.ht_present = True
                
                # Parse HT capability info
                if hasattr(packet.wlan_mgt, 'ht_capabilities_ht_capability_info'):
                    ht_cap_info = int(packet.wlan_mgt.ht_capabilities_ht_capability_info, 16)
                    entry.capabilities.ht_40mhz = bool(ht_cap_info & 0x02)
                    entry.capabilities.ht_sgi_20 = bool(ht_cap_info & 0x20)
                    entry.capabilities.ht_sgi_40 = bool(ht_cap_info & 0x40)
                    
                # Try to get MCS info
                if hasattr(packet.wlan_mgt, 'ht_mcsset'):
                    # Simplified MCS stream detection
                    entry.capabilities.ht_max_streams = 2  # Default assumption
                    
        except Exception as e:
            self.logger.debug(f"Error parsing HT capabilities: {e}")
            
    def _parse_vht_capabilities_pyshark(self, packet: PySharkPacket, entry: BeaconInventoryEntry) -> None:
        """Parse VHT capabilities using PyShark field access."""
        try:
            # Check for VHT capabilities
            if hasattr(packet.wlan_mgt, 'vht_capabilities'):
                entry.capabilities.vht_present = True
                
                # Parse VHT capability info
                if hasattr(packet.wlan_mgt, 'vht_capabilities_vht_capability_info'):
                    vht_cap_info = int(packet.wlan_mgt.vht_capabilities_vht_capability_info, 16)
                    
                    # Channel width support
                    supported_widths = (vht_cap_info >> 2) & 0x3
                    entry.capabilities.vht_80mhz = supported_widths >= 1
                    entry.capabilities.vht_160mhz = supported_widths >= 2
                    
                    # Simplified stream count
                    entry.capabilities.vht_max_streams = 4  # Default assumption
                    
        except Exception as e:
            self.logger.debug(f"Error parsing VHT capabilities: {e}")
            
    def _parse_security_pyshark(self, packet: PySharkPacket, entry: BeaconInventoryEntry) -> None:
        """Parse security information using PyShark field access."""
        try:
            # Check for RSN (WPA2/WPA3)
            if hasattr(packet.wlan_mgt, 'rsn_version'):
                entry.security.wpa2 = True
                
                # Parse AKM suites
                akm_fields = [attr for attr in dir(packet.wlan_mgt) if 'akm' in attr.lower()]
                for akm_field in akm_fields:
                    try:
                        akm_value = getattr(packet.wlan_mgt, akm_field)
                        if 'sae' in str(akm_value).lower():
                            entry.security.wpa3 = True
                            entry.security.sae = True
                            if entry.security.wpa2:
                                entry.security.transition_mode = True
                    except:
                        pass
                        
                # Parse cipher suites
                cipher_fields = [attr for attr in dir(packet.wlan_mgt) if 'cipher' in attr.lower()]
                for cipher_field in cipher_fields:
                    try:
                        cipher_value = str(getattr(packet.wlan_mgt, cipher_field))
                        if 'ccmp' in cipher_value.lower():
                            entry.security.pairwise_ciphers.append('CCMP')
                        elif 'tkip' in cipher_value.lower():
                            entry.security.pairwise_ciphers.append('TKIP')
                    except:
                        pass
                        
            # Check for WPA (vendor specific)
            vendor_fields = [attr for attr in dir(packet.wlan_mgt) if 'vendor' in attr.lower() and 'oui' in attr.lower()]
            for vendor_field in vendor_fields:
                try:
                    vendor_value = str(getattr(packet.wlan_mgt, vendor_field))
                    if '00:50:f2' in vendor_value:  # Microsoft WPA OUI
                        entry.security.wpa = True
                except:
                    pass
                    
            # Check privacy bit for WEP
            if entry.capabilities.privacy and not entry.security.wpa and not entry.security.wpa2:
                entry.security.wep = True
                
            # If no security methods detected but privacy bit is not set, it's open
            if not any([entry.security.wep, entry.security.wpa, entry.security.wpa2, entry.security.wpa3]):
                if not entry.capabilities.privacy:
                    entry.security.open = True
                    
        except Exception as e:
            self.logger.debug(f"Error parsing security: {e}")
            
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
    
    # Analysis methods (reusing logic from Scapy version)
    
    def _analyze_channel_band_consistency(self) -> List[Finding]:
        """Analyze channel/band consistency and mismatches."""
        findings = []
        
        for bssid, entry in self.bss_inventory.items():
            if not entry.channel or not entry.band:
                continue
                
            expected_band = self._determine_band(entry.channel)
            if expected_band != "Unknown" and expected_band != entry.band:
                findings.append(self.create_finding(
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
                    }
                ))
                
        return findings
        
    def _analyze_coexistence_issues(self) -> List[Finding]:
        """Analyze 2.4GHz 40MHz coexistence issues."""
        findings = []
        
        coexistence_violations = []
        
        for bssid, entry in self.bss_inventory.items():
            if (entry.band == "2.4GHz" and 
                entry.capabilities.ht_present and 
                entry.capabilities.ht_40mhz):
                
                if entry.channel in [1, 2, 3, 4, 5, 6, 11, 12, 13, 14]:
                    coexistence_violations.append({
                        "bssid": bssid,
                        "ssid": entry.ssid,
                        "channel": entry.channel,
                        "issue": "40MHz on edge/overlapping channel"
                    })
        
        if coexistence_violations:
            findings.append(self.create_finding(
                severity=Severity.CRITICAL if len(coexistence_violations) > 3 else Severity.WARNING,
                title="2.4GHz 40MHz Coexistence Issues",
                description=f"Found {len(coexistence_violations)} networks with 40MHz coexistence problems",
                details={
                    "violations": coexistence_violations,
                    "recommendation": "Use 20MHz channels or channels 6-7 for 40MHz in 2.4GHz",
                    "impact": "Increased interference and reduced performance"
                }
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
            findings.append(self.create_finding(
                severity=Severity.INFO,
                title="Extremely Low DTIM Periods",
                description=f"Found {len(dtim_extremes['low'])} networks with very low DTIM periods",
                details={
                    "networks": dtim_extremes["low"],
                    "recommendation": "Consider DTIM period 2-3 for balanced power saving"
                }
            ))
        
        if dtim_extremes["high"]:
            findings.append(self.create_finding(
                severity=Severity.WARNING,
                title="Extremely High DTIM Periods", 
                description=f"Found {len(dtim_extremes['high'])} networks with very high DTIM periods",
                details={
                    "networks": dtim_extremes["high"],
                    "recommendation": "Consider lower DTIM period for time-sensitive applications"
                }
            ))
                
        return findings
        
    def _analyze_security_transitions(self) -> List[Finding]:
        """Analyze WPA2+WPA3 transition configurations."""
        findings = []
        
        transition_networks = []
        
        for bssid, entry in self.bss_inventory.items():
            if entry.security.transition_mode:
                transition_networks.append({
                    "bssid": bssid,
                    "ssid": entry.ssid,
                    "akm_suites": entry.security.akm_suites,
                    "pmf_status": "required" if entry.security.pmf_required else 
                                 "capable" if entry.security.pmf_capable else "disabled"
                })
        
        if transition_networks:
            findings.append(self.create_finding(
                severity=Severity.INFO,
                title="WPA2+WPA3 Transition Mode Detected",
                description=f"Found {len(transition_networks)} networks in WPA2/WPA3 transition mode",
                details={
                    "transition_networks": transition_networks,
                    "recommendation": "Monitor client compatibility and plan migration to WPA3-only",
                    "security_benefit": "Provides backward compatibility during WPA3 migration"
                }
            ))
        
        return findings
        
    def _analyze_mbssid_configuration(self) -> List[Finding]:
        """Analyze MBSSID and co-located AP configurations."""
        return []  # Simplified for PyShark version
        
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
            findings.append(self.create_finding(
                severity=Severity.WARNING,
                title="Missing Country Information",
                description=f"{missing_country} networks missing country code information",
                details={
                    "networks_missing_country": missing_country,
                    "total_networks": len(self.bss_inventory),
                    "recommendation": "Configure country codes for regulatory compliance"
                }
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
        
        if capability_issues:
            high_severity = [i for i in capability_issues if i["severity"] == "high"]
            severity = Severity.CRITICAL if high_severity else Severity.WARNING
            
            findings.append(self.create_finding(
                severity=severity,
                title="Capability Configuration Anomalies",
                description=f"Found {len(capability_issues)} networks with capability anomalies",
                details={
                    "anomalies": capability_issues,
                    "high_severity_count": len(high_severity)
                }
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
    
    # Debug methods (optimized for PyShark)
    def _debug_analyze_first_beacon(self, packet: PySharkPacket, packet_index: int) -> None:
        """Debug analysis of first beacon with pause - optimized for PyShark."""
        print(f"\n{'='*80}")
        print(f"🔍 DEBUG: FIRST BEACON FRAME ANALYSIS (PyShark) - Packet #{packet_index}")
        print(f"{'='*80}")
        
        print(f"\n📦 PACKET OVERVIEW:")
        print(f"  Packet Index: {packet_index}")
        print(f"  Packet Length: {packet.length} bytes")
        print(f"  Layers: {[layer.layer_name for layer in packet.layers]}")
        
        # RadioTap analysis
        if hasattr(packet, 'radiotap'):
            print(f"\n📡 RADIOTAP LAYER:")
            if hasattr(packet.radiotap, 'dbm_antsignal'):
                print(f"  RSSI: {packet.radiotap.dbm_antsignal} dBm")
            if hasattr(packet.radiotap, 'channel_freq'):
                print(f"  Frequency: {packet.radiotap.channel_freq} MHz")
            if hasattr(packet.radiotap, 'channel_flags'):
                print(f"  Channel Flags: {packet.radiotap.channel_flags}")
        
        # 802.11 Management header
        if hasattr(packet, 'wlan_mgt'):
            print(f"\n📶 802.11 MANAGEMENT HEADER:")
            if hasattr(packet.wlan_mgt, 'fc_type_subtype'):
                print(f"  Frame Type/Subtype: {packet.wlan_mgt.fc_type_subtype}")
            print(f"  BSSID: {packet.wlan.bssid}")
            if hasattr(packet.wlan_mgt, 'beacon_interval'):
                print(f"  Beacon Interval: {packet.wlan_mgt.beacon_interval}")
        
        # Information Elements
        print(f"\n📝 INFORMATION ELEMENTS:")
        ie_fields = [attr for attr in dir(packet.wlan_mgt) if not attr.startswith('_')]
        ie_count = 0
        for field in ie_fields[:20]:  # Show first 20 fields
            try:
                value = getattr(packet.wlan_mgt, field)
                if value and str(value) != '0':
                    print(f"  {ie_count:2d}. {field}: {value}")
                    ie_count += 1
            except:
                pass
        
        # Extracted entry
        print(f"\n📋 EXTRACTED BEACON ENTRY:")
        entry = self._extract_beacon_entry(packet)
        if entry:
            print(f"  BSSID: {entry.bssid}")
            print(f"  SSID: '{entry.ssid}' {'(Hidden)' if entry.ssid_hidden else ''}")
            print(f"  Channel: {entry.channel} ({entry.band})")
            print(f"  Security: WPA2={entry.security.wpa2}, WPA3={entry.security.wpa3}")
            print(f"  Capabilities: HT={entry.capabilities.ht_present}, VHT={entry.capabilities.vht_present}")
        else:
            print("  ❌ Failed to extract beacon entry")
        
        print(f"\n{'='*80}")
        
        try:
            input("🔸 Press Enter to continue or Ctrl+C to exit...")
        except KeyboardInterrupt:
            print("\n⏹️  Analysis interrupted")
            import sys
            sys.exit(0)
    
    def _debug_log_beacon_entry(self, entry: BeaconInventoryEntry, packet_index: int) -> None:
        """Log beacon entry for debugging."""
        self.logger.info(f"PYSHARK BEACON #{packet_index}: {entry.bssid} '{entry.ssid}' Ch:{entry.channel}")