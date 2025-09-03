"""
Probe Behavior Analysis for wireless PCAP data.

This analyzer provides comprehensive probe request behavior analysis including:
- Client probe request pattern analysis
- Top probers identification and characterization
- Wildcard vs directed probe request analysis
- SSID leakage detection (Preferred Network List - PNL)
- Excessive probe rate detection
- Probe sequence timing and randomization analysis
- Privacy implications and client fingerprinting
- Probe response correlation and AP behavior
"""

import statistics
from collections import defaultdict, Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Dict, Any, Set, Optional, NamedTuple, Tuple
import re
import logging

from scapy.all import Packet
from scapy.layers.dot11 import (
    Dot11, Dot11ProbeReq, Dot11ProbeResp, Dot11Elt,
    Dot11EltRates, Dot11EltDSSSet
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
    AnalysisCategory
)


@dataclass
class ProbeRequestEntry:
    """Individual probe request entry."""
    timestamp: float
    client_mac: str
    target_ssid: str
    is_wildcard: bool
    sequence_number: Optional[int]
    rssi: Optional[int]
    channel: Optional[int]
    supported_rates: List[str] = field(default_factory=list)
    extended_rates: List[str] = field(default_factory=list)
    capabilities: Optional[int] = None
    vendor_ies: Dict[str, bytes] = field(default_factory=dict)


@dataclass  
class ClientProbeProfile:
    """Comprehensive client probing profile."""
    mac_address: str
    vendor_oui: Optional[str]
    
    # Probe statistics
    total_probes: int = 0
    wildcard_probes: int = 0
    directed_probes: int = 0
    unique_ssids: Set[str] = field(default_factory=set)
    
    # Timing analysis
    first_probe: Optional[datetime] = None
    last_probe: Optional[datetime] = None
    probe_intervals: List[float] = field(default_factory=list)
    
    # Rate analysis
    probes_per_minute: float = 0.0
    peak_probe_rate: float = 0.0
    
    # Privacy analysis
    pnl_exposure: List[str] = field(default_factory=list)  # Exposed SSIDs
    privacy_risk_score: float = 0.0
    
    # Behavioral patterns
    probe_patterns: Dict[str, int] = field(default_factory=dict)
    randomization_detected: bool = False
    
    # Technical characteristics
    supported_standards: Set[str] = field(default_factory=set)
    channel_usage: Counter = field(default_factory=Counter)
    rssi_values: List[int] = field(default_factory=list)


@dataclass
class ProbeSequencePattern:
    """Detected probe sequence pattern."""
    pattern_type: str  # "burst", "periodic", "random", "scanning"
    client_mac: str
    ssid_sequence: List[str]
    timing_pattern: List[float]
    frequency: float  # Occurrences per minute
    confidence: float  # Pattern confidence score


class ProbeBehaviorAnalyzer(BaseAnalyzer):
    """
    Comprehensive Probe Behavior Analyzer.
    
    This analyzer examines client probe request behavior to identify:
    - Privacy leaks through SSID exposure
    - Excessive or anomalous probing patterns
    - Client fingerprinting characteristics
    - Network discovery behavior analysis
    """
    
    def __init__(self):
        super().__init__(
            name="Probe Behavior Analyzer",
            category=AnalysisCategory.PROBE_BEHAVIOR,
            version="1.0"
        )
        
        self.description = (
            "Analyzes client probe request behavior for privacy leaks, "
            "excessive probing, and behavioral patterns"
        )
        
        # Wireshark filters for probe analysis
        self.wireshark_filters = [
            "wlan.fc.type_subtype == 4",   # Probe requests
            "wlan.fc.type_subtype == 5",   # Probe responses
            "wlan_mgt.ssid",
            "wlan.sa",  # Source address (client MAC)
            "wlan.ta"   # Transmitter address
        ]
        
        self.analysis_order = 25  # Run after beacon inventory
        
        # Analysis storage
        self.probe_requests: List[ProbeRequestEntry] = []
        self.client_profiles: Dict[str, ClientProbeProfile] = {}
        self.ssid_popularity: Counter = Counter()
        self.probe_sequences: List[ProbeSequencePattern] = []
        
        # Analysis thresholds
        self.EXCESSIVE_PROBE_RATE = 10.0  # Probes per minute
        self.HIGH_PROBE_RATE = 5.0        # Probes per minute
        self.PRIVACY_RISK_THRESHOLD = 3   # Number of unique SSIDs exposed
        self.BURST_THRESHOLD = 5          # Probes within burst window
        self.BURST_WINDOW = 10.0          # Seconds
        
        # Known patterns
        self.COMMON_SSIDS = {
            'linksys', 'netgear', 'dlink', 'belkin', 'asus',
            'tplink', 'default', 'wireless', 'wifi', 'internet'
        }
        
        self.CORPORATE_SSIDS_REGEX = [
            r'.*corp.*', r'.*enterprise.*', r'.*company.*',
            r'.*office.*', r'.*work.*', r'.*business.*'
        ]

    def is_applicable(self, packet: Packet) -> bool:
        """Check if packet is a probe request."""
        return packet_has_layer(packet, Dot11ProbeReq)
        
    def get_display_filters(self) -> List[str]:
        """Get Wireshark display filters for probe analysis."""
        return self.wireshark_filters
        
    def analyze(self, packets: List[Packet], context: AnalysisContext) -> List[Finding]:
        """
        Analyze probe request behavior patterns.
        
        Args:
            packets: List of probe request packets
            context: Analysis context
            
        Returns:
            List of findings
        """
        if not packets:
            return []
            
        self.logger.info(f"Analyzing probe behavior from {len(packets)} probe request frames")
        
        # Extract probe requests
        self._extract_probe_requests(packets)
        
        if not self.probe_requests:
            return []
            
        # Build client profiles
        self._build_client_profiles()
        
        # Detect probe patterns
        self._detect_probe_patterns()
        
        self.logger.info(f"Analyzed {len(self.client_profiles)} unique clients")
        
        # Generate findings
        findings = []
        findings.extend(self._analyze_top_probers())
        findings.extend(self._analyze_probe_rates())
        findings.extend(self._analyze_ssid_leakage())
        findings.extend(self._analyze_wildcard_behavior())
        findings.extend(self._analyze_probe_patterns())
        findings.extend(self._analyze_privacy_risks())
        
        # Store analysis results in context
        context.metadata['probe_behavior'] = {
            'client_profiles': self.client_profiles,
            'total_probes': len(self.probe_requests),
            'unique_clients': len(self.client_profiles),
            'ssid_popularity': dict(self.ssid_popularity),
            'probe_patterns': self.probe_sequences
        }
        
        self.findings_generated = len(findings)
        return findings
        
    def _extract_probe_requests(self, packets: List[Packet]) -> None:
        """Extract probe request information from packets."""
        for packet in packets:
            try:
                if not packet_has_layer(packet, Dot11ProbeReq):
                    continue
                    
                dot11 = get_packet_layer(packet, "Dot11")
                probe_req = get_packet_layer(packet, "Dot11ProbeReq")
                
                # Extract basic information
                client_mac = dot11.addr2 if dot11.addr2 else "unknown"
                if client_mac == "unknown":
                    continue
                    
                # Get packet timestamp
                timestamp = get_timestamp(packet) if hasattr(packet, 'time') else 0
                if hasattr(timestamp, '__float__'):
                    timestamp = float(timestamp)
                elif hasattr(timestamp, 'val'):
                    timestamp = float(timestamp.val)
                else:
                    timestamp = float(timestamp)
                
                # Extract SSID from Information Elements
                target_ssid = ""
                is_wildcard = True
                supported_rates = []
                extended_rates = []
                vendor_ies = {}
                channel = None
                
                if packet_has_layer(packet, Dot11Elt):
                    current_ie = get_packet_layer(packet, "Dot11Elt")
                    while current_ie:
                        ie_id = current_ie.ID
                        ie_data = bytes(current_ie.info) if current_ie.info else b''
                        
                        if ie_id == 0:  # SSID
                            if ie_data:
                                try:
                                    target_ssid = ie_data.decode('utf-8', errors='ignore')
                                    is_wildcard = False
                                except:
                                    target_ssid = f"<binary:{len(ie_data)}bytes>"
                                    is_wildcard = False
                        elif ie_id == 1:  # Supported Rates
                            supported_rates = self._parse_rates(ie_data)
                        elif ie_id == 50:  # Extended Supported Rates
                            extended_rates = self._parse_rates(ie_data)
                        elif ie_id == 3:  # DS Parameter Set
                            if len(ie_data) >= 1:
                                channel = ie_data[0]
                        elif ie_id == 221:  # Vendor Specific
                            if len(ie_data) >= 3:
                                oui = ie_data[:3].hex()
                                vendor_ies[oui] = ie_data[3:]
                        
                        current_ie = current_ie.payload if hasattr(current_ie, 'payload') and isinstance(current_ie.payload, Dot11Elt) else None
                
                # Extract RSSI from RadioTap
                rssi = None
                if packet_has_layer(packet, RadioTap):
                    radiotap = get_packet_layer(packet, "RadioTap")
                    if hasattr(radiotap, 'dBm_AntSignal'):
                        rssi = radiotap.dBm_AntSignal
                
                # Extract sequence number
                sequence_number = dot11.SC if hasattr(dot11, 'SC') else None
                
                # Create probe request entry
                probe_entry = ProbeRequestEntry(
                    timestamp=timestamp,
                    client_mac=client_mac,
                    target_ssid=target_ssid,
                    is_wildcard=is_wildcard,
                    sequence_number=sequence_number,
                    rssi=rssi,
                    channel=channel,
                    supported_rates=supported_rates,
                    extended_rates=extended_rates,
                    capabilities=probe_req.cap if hasattr(probe_req, 'cap') else None,
                    vendor_ies=vendor_ies
                )
                
                self.probe_requests.append(probe_entry)
                
                # Track SSID popularity
                if target_ssid and not is_wildcard:
                    self.ssid_popularity[target_ssid] += 1
                    
            except Exception as e:
                self.logger.debug(f"Error extracting probe request: {e}")
                continue
                
    def _parse_rates(self, rate_data: bytes) -> List[str]:
        """Parse supported rates from IE data."""
        rates = []
        for byte_val in rate_data:
            # Rate is in 500 kbps units, mask off basic rate bit
            rate_500k = byte_val & 0x7F
            rate_mbps = rate_500k * 0.5
            rates.append(f"{rate_mbps:.1f}")
        return rates
        
    def _build_client_profiles(self) -> None:
        """Build comprehensive client profiles from probe requests."""
        # Group probes by client
        client_probes = defaultdict(list)
        for probe in self.probe_requests:
            client_probes[probe.client_mac].append(probe)
        
        # Build profile for each client
        for client_mac, probes in client_probes.items():
            profile = ClientProbeProfile(
                mac_address=client_mac,
                vendor_oui=self._extract_vendor_oui(client_mac)
            )
            
            # Sort probes by timestamp
            probes.sort(key=lambda x: x.timestamp)
            
            # Basic statistics
            profile.total_probes = len(probes)
            profile.wildcard_probes = sum(1 for p in probes if p.is_wildcard)
            profile.directed_probes = sum(1 for p in probes if not p.is_wildcard)
            profile.unique_ssids = set(p.target_ssid for p in probes if p.target_ssid and not p.is_wildcard)
            
            # Timing analysis
            if probes:
                profile.first_probe = datetime.fromtimestamp(probes[0].timestamp)
                profile.last_probe = datetime.fromtimestamp(probes[-1].timestamp)
                
                # Calculate intervals
                for i in range(1, len(probes)):
                    interval = probes[i].timestamp - probes[i-1].timestamp
                    profile.probe_intervals.append(interval)
                
                # Calculate rates
                duration_minutes = (probes[-1].timestamp - probes[0].timestamp) / 60.0
                if duration_minutes > 0:
                    profile.probes_per_minute = len(probes) / duration_minutes
                
                # Calculate peak rate (max probes in 1-minute window)
                profile.peak_probe_rate = self._calculate_peak_rate(probes)
            
            # Privacy analysis
            profile.pnl_exposure = list(profile.unique_ssids)
            profile.privacy_risk_score = self._calculate_privacy_risk(profile.unique_ssids)
            
            # Technical characteristics
            for probe in probes:
                # Detect supported standards
                if probe.supported_rates or probe.extended_rates:
                    profile.supported_standards.update(self._detect_standards(probe))
                    
                # Channel usage
                if probe.channel:
                    profile.channel_usage[probe.channel] += 1
                    
                # RSSI values
                if probe.rssi is not None:
                    profile.rssi_values.append(probe.rssi)
            
            # Detect MAC randomization
            profile.randomization_detected = self._detect_mac_randomization(client_mac, probes)
            
            self.client_profiles[client_mac] = profile
            
    def _calculate_peak_rate(self, probes: List[ProbeRequestEntry]) -> float:
        """Calculate peak probe rate in 1-minute sliding window."""
        if len(probes) < 2:
            return 0.0
            
        max_rate = 0.0
        window_size = 60.0  # 1 minute
        
        for i, probe in enumerate(probes):
            window_start = probe.timestamp
            window_end = window_start + window_size
            
            # Count probes in window
            count = sum(1 for p in probes[i:] if p.timestamp <= window_end)
            rate = count / (window_size / 60.0)  # Probes per minute
            
            max_rate = max(max_rate, rate)
            
        return max_rate
        
    def _calculate_privacy_risk(self, exposed_ssids: Set[str]) -> float:
        """Calculate privacy risk score based on exposed SSIDs."""
        if not exposed_ssids:
            return 0.0
            
        risk_score = 0.0
        
        for ssid in exposed_ssids:
            # Base score for any SSID exposure
            risk_score += 1.0
            
            # Higher risk for corporate/enterprise SSIDs
            for pattern in self.CORPORATE_SSIDS_REGEX:
                if re.match(pattern, ssid.lower()):
                    risk_score += 2.0
                    break
            
            # Lower risk for common/generic SSIDs
            if ssid.lower() in self.COMMON_SSIDS:
                risk_score += 0.5
            else:
                risk_score += 1.5  # Unique/personal SSIDs are higher risk
                
        return min(risk_score, 10.0)  # Cap at 10
        
    def _detect_standards(self, probe: ProbeRequestEntry) -> Set[str]:
        """Detect supported 802.11 standards from probe request."""
        standards = set()
        
        # Basic rate analysis
        all_rates = probe.supported_rates + probe.extended_rates
        rates_set = set(all_rates)
        
        # 802.11b rates
        if any(rate in rates_set for rate in ['1.0', '2.0', '5.5', '11.0']):
            standards.add('802.11b')
            
        # 802.11g rates  
        if any(rate in rates_set for rate in ['6.0', '9.0', '12.0', '18.0', '24.0', '36.0', '48.0', '54.0']):
            standards.add('802.11g')
            
        # More sophisticated HT/VHT/HE detection would require parsing additional IEs
        
        return standards
        
    def _detect_mac_randomization(self, mac: str, probes: List[ProbeRequestEntry]) -> bool:
        """Detect if MAC address randomization is being used."""
        try:
            # Check locally administered bit (2nd bit of first octet)
            first_octet = int(mac.split(':')[0], 16)
            locally_administered = bool(first_octet & 0x02)
            
            # Additional heuristics could be added here
            return locally_administered
        except:
            return False
            
    def _extract_vendor_oui(self, mac: str) -> Optional[str]:
        """Extract vendor OUI from MAC address."""
        try:
            parts = mac.split(':')
            if len(parts) >= 3:
                return ':'.join(parts[:3]).upper()
        except:
            pass
        return None
        
    def _detect_probe_patterns(self) -> None:
        """Detect probe sequence patterns for each client."""
        for client_mac, profile in self.client_profiles.items():
            client_probes = [p for p in self.probe_requests if p.client_mac == client_mac]
            client_probes.sort(key=lambda x: x.timestamp)
            
            # Detect burst patterns
            bursts = self._detect_probe_bursts(client_probes)
            for burst in bursts:
                pattern = ProbeSequencePattern(
                    pattern_type="burst",
                    client_mac=client_mac,
                    ssid_sequence=burst['ssids'],
                    timing_pattern=burst['intervals'],
                    frequency=burst['frequency'],
                    confidence=burst['confidence']
                )
                self.probe_sequences.append(pattern)
                
            # Detect periodic patterns
            periodic = self._detect_periodic_probing(client_probes)
            if periodic:
                pattern = ProbeSequencePattern(
                    pattern_type="periodic",
                    client_mac=client_mac,
                    ssid_sequence=periodic['ssids'],
                    timing_pattern=periodic['intervals'],
                    frequency=periodic['frequency'],
                    confidence=periodic['confidence']
                )
                self.probe_sequences.append(pattern)
                
    def _detect_probe_bursts(self, probes: List[ProbeRequestEntry]) -> List[Dict[str, Any]]:
        """Detect probe burst patterns."""
        bursts = []
        
        if len(probes) < self.BURST_THRESHOLD:
            return bursts
            
        i = 0
        while i < len(probes) - self.BURST_THRESHOLD:
            # Check for burst within window
            burst_start = probes[i].timestamp
            burst_probes = []
            
            j = i
            while j < len(probes) and (probes[j].timestamp - burst_start) <= self.BURST_WINDOW:
                burst_probes.append(probes[j])
                j += 1
                
            if len(burst_probes) >= self.BURST_THRESHOLD:
                # Calculate burst characteristics
                ssids = [p.target_ssid for p in burst_probes if p.target_ssid]
                intervals = []
                for k in range(1, len(burst_probes)):
                    intervals.append(burst_probes[k].timestamp - burst_probes[k-1].timestamp)
                    
                bursts.append({
                    'ssids': ssids,
                    'intervals': intervals,
                    'frequency': len(burst_probes) / (self.BURST_WINDOW / 60.0),
                    'confidence': min(len(burst_probes) / self.BURST_THRESHOLD, 1.0)
                })
                
                i = j  # Skip processed probes
            else:
                i += 1
                
        return bursts
        
    def _detect_periodic_probing(self, probes: List[ProbeRequestEntry]) -> Optional[Dict[str, Any]]:
        """Detect periodic probing patterns."""
        if len(probes) < 10:  # Need enough samples
            return None
            
        # Calculate intervals
        intervals = []
        for i in range(1, len(probes)):
            intervals.append(probes[i].timestamp - probes[i-1].timestamp)
            
        if len(intervals) < 5:
            return None
            
        # Check for periodicity using coefficient of variation
        mean_interval = statistics.mean(intervals)
        std_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
        
        if mean_interval > 0:
            cv = std_interval / mean_interval
            
            # Low coefficient of variation suggests periodicity
            if cv < 0.3:  # Threshold for periodic behavior
                ssids = [p.target_ssid for p in probes if p.target_ssid]
                return {
                    'ssids': ssids,
                    'intervals': intervals,
                    'frequency': 60.0 / mean_interval,  # Probes per minute
                    'confidence': 1.0 - cv
                }
                
        return None
        
    # Analysis methods for generating findings
    
    def _analyze_top_probers(self) -> List[Finding]:
        """Analyze and identify top probing clients."""
        findings = []
        
        # Sort clients by probe count
        top_probers = sorted(
            self.client_profiles.items(),
            key=lambda x: x[1].total_probes,
            reverse=True
        )[:10]
        
        if not top_probers:
            return findings
            
        # Identify excessive probers
        excessive_probers = [
            (mac, profile) for mac, profile in top_probers
            if profile.total_probes > 50 or profile.probes_per_minute > self.HIGH_PROBE_RATE
        ]
        
        if excessive_probers:
            findings.append(Finding(
                category=AnalysisCategory.PROBE_BEHAVIOR,
                severity=Severity.WARNING,
                title="High-Volume Probing Clients Detected",
                description=f"Found {len(excessive_probers)} clients with high probe activity",
                details={
                    "top_probers": [
                        {
                            "client_mac": mac,
                            "total_probes": profile.total_probes,
                            "probes_per_minute": round(profile.probes_per_minute, 2),
                            "unique_ssids": len(profile.unique_ssids),
                            "vendor_oui": profile.vendor_oui,
                            "randomized_mac": profile.randomization_detected
                        }
                        for mac, profile in excessive_probers[:5]
                    ],
                    "analysis_impact": "High probe volumes may indicate scanning tools or misconfigured clients"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
            
        # Overall probe activity summary
        total_probes = sum(profile.total_probes for _, profile in self.client_profiles.items())
        findings.append(Finding(
            category=AnalysisCategory.PROBE_BEHAVIOR,
            severity=Severity.INFO,
            title="Probe Activity Summary",
            description=f"Analyzed probe behavior from {len(self.client_profiles)} unique clients",
            details={
                "total_probe_requests": total_probes,
                "unique_clients": len(self.client_profiles),
                "average_probes_per_client": round(total_probes / len(self.client_profiles), 1) if self.client_profiles else 0,
                "top_5_probers": [
                    {
                        "client_mac": mac,
                        "probe_count": profile.total_probes,
                        "vendor_oui": profile.vendor_oui
                    }
                    for mac, profile in top_probers[:5]
                ]
            },
            analyzer_name=self.name,
            analyzer_version=self.version
        ))
            
        return findings
        
    def _analyze_probe_rates(self) -> List[Finding]:
        """Analyze probe request rates for excessive behavior."""
        findings = []
        
        excessive_rate_clients = []
        high_rate_clients = []
        
        for mac, profile in self.client_profiles.items():
            if profile.probes_per_minute >= self.EXCESSIVE_PROBE_RATE:
                excessive_rate_clients.append((mac, profile))
            elif profile.probes_per_minute >= self.HIGH_PROBE_RATE:
                high_rate_clients.append((mac, profile))
        
        if excessive_rate_clients:
            findings.append(Finding(
                category=AnalysisCategory.PROBE_BEHAVIOR,
                severity=Severity.CRITICAL,
                title="Excessive Probe Request Rates",
                description=f"Found {len(excessive_rate_clients)} clients with excessive probe rates",
                details={
                    "excessive_clients": [
                        {
                            "client_mac": mac,
                            "probes_per_minute": round(profile.probes_per_minute, 2),
                            "peak_rate": round(profile.peak_probe_rate, 2),
                            "total_probes": profile.total_probes,
                            "vendor_oui": profile.vendor_oui,
                            "potential_issue": "Scanning tool, malware, or misconfigured client"
                        }
                        for mac, profile in excessive_rate_clients
                    ],
                    "threshold": self.EXCESSIVE_PROBE_RATE,
                    "recommendation": "Investigate these clients for potential security issues"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
        
        if high_rate_clients:
            findings.append(Finding(
                category=AnalysisCategory.PROBE_BEHAVIOR,
                severity=Severity.WARNING,
                title="High Probe Request Rates",
                description=f"Found {len(high_rate_clients)} clients with high probe rates",
                details={
                    "high_rate_clients": [
                        {
                            "client_mac": mac,
                            "probes_per_minute": round(profile.probes_per_minute, 2),
                            "total_probes": profile.total_probes,
                            "vendor_oui": profile.vendor_oui
                        }
                        for mac, profile in high_rate_clients
                    ],
                    "threshold": self.HIGH_PROBE_RATE,
                    "note": "Monitor for potential performance impact"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
                
        return findings
        
    def _analyze_ssid_leakage(self) -> List[Finding]:
        """Analyze SSID leakage and PNL exposure."""
        findings = []
        
        # Clients with high SSID exposure
        high_exposure_clients = [
            (mac, profile) for mac, profile in self.client_profiles.items()
            if len(profile.unique_ssids) >= self.PRIVACY_RISK_THRESHOLD
        ]
        
        if high_exposure_clients:
            # Sort by number of exposed SSIDs
            high_exposure_clients.sort(key=lambda x: len(x[1].unique_ssids), reverse=True)
            
            findings.append(Finding(
                category=AnalysisCategory.PROBE_BEHAVIOR,
                severity=Severity.WARNING,
                title="SSID Leakage and PNL Exposure",
                description=f"Found {len(high_exposure_clients)} clients exposing multiple SSIDs",
                details={
                    "exposed_clients": [
                        {
                            "client_mac": mac,
                            "exposed_ssids": list(profile.unique_ssids),
                            "ssid_count": len(profile.unique_ssids),
                            "privacy_risk_score": round(profile.privacy_risk_score, 1),
                            "vendor_oui": profile.vendor_oui,
                            "randomized_mac": profile.randomization_detected
                        }
                        for mac, profile in high_exposure_clients[:10]
                    ],
                    "privacy_impact": "Exposed SSIDs reveal user location history and behavior",
                    "recommendation": "Enable MAC randomization and disable auto-connect for untrusted networks"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
        
        # Analyze most commonly probed SSIDs
        if self.ssid_popularity:
            top_ssids = self.ssid_popularity.most_common(10)
            findings.append(Finding(
                category=AnalysisCategory.PROBE_BEHAVIOR,
                severity=Severity.INFO,
                title="Most Frequently Probed SSIDs",
                description=f"Analysis of {len(self.ssid_popularity)} unique SSIDs in probe requests",
                details={
                    "top_ssids": [
                        {"ssid": ssid, "probe_count": count}
                        for ssid, count in top_ssids
                    ],
                    "total_unique_ssids": len(self.ssid_popularity),
                    "note": "Popular SSIDs may indicate common networks or honeypots"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
                
        return findings
        
    def _analyze_wildcard_behavior(self) -> List[Finding]:
        """Analyze wildcard vs directed probe behavior."""
        findings = []
        
        # Calculate overall statistics
        total_probes = len(self.probe_requests)
        wildcard_probes = sum(1 for p in self.probe_requests if p.is_wildcard)
        directed_probes = total_probes - wildcard_probes
        
        wildcard_percentage = (wildcard_probes / total_probes * 100) if total_probes > 0 else 0
        
        # Analyze client-specific behavior
        wildcard_heavy_clients = []
        directed_only_clients = []
        
        for mac, profile in self.client_profiles.items():
            wildcard_ratio = profile.wildcard_probes / profile.total_probes if profile.total_probes > 0 else 0
            
            if wildcard_ratio > 0.8 and profile.total_probes > 10:
                wildcard_heavy_clients.append((mac, profile, wildcard_ratio))
            elif profile.wildcard_probes == 0 and profile.total_probes > 5:
                directed_only_clients.append((mac, profile))
        
        # Overall probe behavior analysis
        findings.append(Finding(
            category=AnalysisCategory.PROBE_BEHAVIOR,
            severity=Severity.INFO,
            title="Probe Request Behavior Analysis",
            description=f"Analysis of wildcard vs directed probe request patterns",
            details={
                "total_probes": total_probes,
                "wildcard_probes": wildcard_probes,
                "directed_probes": directed_probes,
                "wildcard_percentage": round(wildcard_percentage, 1),
                "behavior_implications": {
                    "high_wildcard": "May indicate scanning or discovery tools",
                    "high_directed": "Suggests specific network targeting or saved networks"
                }
            },
            analyzer_name=self.name,
            analyzer_version=self.version
        ))
        
        if wildcard_heavy_clients:
            findings.append(Finding(
                category=AnalysisCategory.PROBE_BEHAVIOR,
                severity=Severity.WARNING,
                title="Wildcard-Heavy Probing Clients",
                description=f"Found {len(wildcard_heavy_clients)} clients using primarily wildcard probes",
                details={
                    "wildcard_clients": [
                        {
                            "client_mac": mac,
                            "total_probes": profile.total_probes,
                            "wildcard_percentage": round(ratio * 100, 1),
                            "vendor_oui": profile.vendor_oui,
                            "behavior": "May indicate scanning tool or discovery mode"
                        }
                        for mac, profile, ratio in wildcard_heavy_clients[:10]
                    ],
                    "security_note": "Excessive wildcard probing may indicate reconnaissance"
                },
                analyzer_name=self.name,
                analyzer_version=self.version
            ))
                
        return findings
        
    def _analyze_probe_patterns(self) -> List[Finding]:
        """Analyze detected probe sequence patterns."""
        findings = []
        
        if not self.probe_sequences:
            return findings
            
        # Group patterns by type
        pattern_types = defaultdict(list)
        for pattern in self.probe_sequences:
            pattern_types[pattern.pattern_type].append(pattern)
        
        for pattern_type, patterns in pattern_types.items():
            if pattern_type == "burst":
                findings.append(Finding(
                    category=AnalysisCategory.PROBE_BEHAVIOR,
                    severity=Severity.WARNING,
                    title="Probe Burst Patterns Detected",
                    description=f"Found {len(patterns)} clients exhibiting probe burst behavior",
                    details={
                        "burst_clients": [
                            {
                                "client_mac": p.client_mac,
                                "burst_frequency": round(p.frequency, 2),
                                "ssids_in_burst": len(set(p.ssid_sequence)),
                                "confidence": round(p.confidence, 2)
                            }
                            for p in patterns[:10]
                        ],
                        "pattern_analysis": "Burst patterns may indicate automated scanning or rapid network discovery"
                    },
                    analyzer_name=self.name,
                    analyzer_version=self.version
                ))
            elif pattern_type == "periodic":
                findings.append(Finding(
                    category=AnalysisCategory.PROBE_BEHAVIOR,
                    severity=Severity.INFO,
                    title="Periodic Probe Patterns Detected", 
                    description=f"Found {len(patterns)} clients with periodic probing behavior",
                    details={
                        "periodic_clients": [
                            {
                                "client_mac": p.client_mac,
                                "probe_frequency": round(p.frequency, 2),
                                "pattern_confidence": round(p.confidence, 2),
                                "behavior": "Regular interval probing"
                            }
                            for p in patterns[:10]
                        ],
                        "note": "Periodic patterns are typical for normal client behavior"
                    },
                    analyzer_name=self.name,
                    analyzer_version=self.version
                ))
                
        return findings
        
    def _analyze_privacy_risks(self) -> List[Finding]:
        """Analyze overall privacy risks from probe behavior."""
        findings = []
        
        # Calculate privacy metrics
        total_clients = len(self.client_profiles)
        clients_with_exposure = sum(1 for p in self.client_profiles.values() if p.unique_ssids)
        high_risk_clients = sum(1 for p in self.client_profiles.values() if p.privacy_risk_score >= 5.0)
        randomized_clients = sum(1 for p in self.client_profiles.values() if p.randomization_detected)
        
        exposure_rate = (clients_with_exposure / total_clients * 100) if total_clients > 0 else 0
        randomization_rate = (randomized_clients / total_clients * 100) if total_clients > 0 else 0
        
        findings.append(Finding(
            category=AnalysisCategory.PROBE_BEHAVIOR,
            severity=Severity.WARNING if exposure_rate > 50 else Severity.INFO,
            title="Privacy Risk Assessment",
            description=f"Privacy analysis of client probe behavior patterns",
            details={
                "total_clients_analyzed": total_clients,
                "clients_exposing_ssids": clients_with_exposure,
                "exposure_rate_percentage": round(exposure_rate, 1),
                "high_risk_clients": high_risk_clients,
                "mac_randomization_rate": round(randomization_rate, 1),
                "privacy_recommendations": [
                    "Enable MAC address randomization",
                    "Disable auto-connect for public networks", 
                    "Regularly clear saved network list",
                    "Use directed probes only when necessary"
                ],
                "risk_assessment": "HIGH" if exposure_rate > 70 else "MEDIUM" if exposure_rate > 30 else "LOW"
            },
            analyzer_name=self.name,
            analyzer_version=self.version
        ))
            
        return findings