"""
PyShark-specific Probe Behavior Analyzer

Analyzes probe request behavior patterns to identify privacy risks and client tracking
vulnerabilities using PyShark's native packet parsing capabilities.
"""

import logging
from typing import Dict, List, Any, Optional, Set, Tuple
from collections import defaultdict, deque
import time

try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False

from ....core.base_analyzer import BasePySharkAnalyzer
from ....core.models import Finding, Severity, AnalysisCategory


class PySharkProbeBehaviorAnalyzer(BasePySharkAnalyzer):
    """PyShark-based probe behavior analyzer for privacy and tracking analysis."""
    
    def __init__(self):
        super().__init__()
        self.name = "PyShark Probe Behavior Analyzer"
        self.description = "Analyzes probe request patterns using PyShark parsing"
        self.version = "1.0.0"
        
        if not PYSHARK_AVAILABLE:
            self.logger.warning("PyShark not available - analyzer will not function")
        
        # Client tracking data structures
        self.clients = defaultdict(lambda: {
            'probe_requests': [],
            'ssids_probed': set(),
            'first_seen': None,
            'last_seen': None,
            'probe_count': 0,
            'randomized_mac': False,
            'vendor_oui': None,
            'signal_strengths': [],
            'probe_intervals': deque(maxlen=10),
            'ie_signatures': []
        })
        
        # Privacy analysis tracking
        self.broadcast_probes = []
        self.directed_probes = []
        self.privacy_risks = []
        self.tracking_indicators = []
        
        # Analysis parameters
        self.analysis_window = 300  # 5 minutes
        self.min_probes_for_analysis = 3
        self.privacy_threshold_score = 7
        
    def analyze_packet(self, packet, metadata: Dict[str, Any] = None) -> List[Finding]:
        """Analyze a single packet for probe behavior patterns."""
        if not PYSHARK_AVAILABLE:
            return []
            
        findings = []
        
        try:
            # Check if this is a probe request
            if not self._is_probe_request(packet):
                return findings
            
            # Extract probe request details
            probe_info = self._extract_probe_info(packet)
            if not probe_info:
                return findings
            
            # Update client tracking
            self._update_client_data(probe_info)
            
            # Perform privacy analysis
            privacy_findings = self._analyze_privacy_implications(probe_info)
            findings.extend(privacy_findings)
            
            # Perform tracking analysis
            tracking_findings = self._analyze_tracking_risks(probe_info)
            findings.extend(tracking_findings)
            
            # Perform behavioral analysis
            behavior_findings = self._analyze_probe_patterns(probe_info)
            findings.extend(behavior_findings)
            
        except Exception as e:
            self.logger.error(f"Error analyzing probe behavior: {e}")
            
        return findings
    
    def _is_probe_request(self, packet) -> bool:
        """Check if packet is a probe request."""
        try:
            if not hasattr(packet, 'wlan'):
                return False
            
            # Check frame type and subtype
            if hasattr(packet.wlan, 'fc_type'):
                frame_type = int(packet.wlan.fc_type)
                if frame_type != 0:  # Management frame
                    return False
            
            if hasattr(packet.wlan, 'fc_subtype'):
                subtype = int(packet.wlan.fc_subtype)
                return subtype == 4  # Probe request subtype
            
            return False
            
        except (AttributeError, ValueError):
            return False
    
    def _extract_probe_info(self, packet) -> Optional[Dict[str, Any]]:
        """Extract probe request information from packet."""
        try:
            probe_info = {
                'timestamp': float(packet.sniff_timestamp),
                'src_mac': packet.wlan.sa if hasattr(packet.wlan, 'sa') else None,
                'dst_mac': packet.wlan.da if hasattr(packet.wlan, 'da') else None,
                'bssid': packet.wlan.bssid if hasattr(packet.wlan, 'bssid') else None,
                'ssid': None,
                'signal_strength': None,
                'channel': None,
                'ies': []
            }
            
            if not probe_info['src_mac']:
                return None
            
            # Extract SSID from management frame
            if hasattr(packet, 'wlan_mgt') and hasattr(packet.wlan_mgt, 'ssid'):
                probe_info['ssid'] = packet.wlan_mgt.ssid
            
            # Extract signal strength from RadioTap
            if hasattr(packet, 'radiotap'):
                if hasattr(packet.radiotap, 'dbm_antsignal'):
                    probe_info['signal_strength'] = int(packet.radiotap.dbm_antsignal)
                
                if hasattr(packet.radiotap, 'channel_freq'):
                    freq = int(packet.radiotap.channel_freq)
                    probe_info['channel'] = self._freq_to_channel(freq)
            
            # Extract Information Elements
            probe_info['ies'] = self._extract_information_elements(packet)
            
            return probe_info
            
        except Exception as e:
            self.logger.error(f"Error extracting probe info: {e}")
            return None
    
    def _extract_information_elements(self, packet) -> List[Dict[str, Any]]:
        """Extract Information Elements from probe request."""
        ies = []
        
        try:
            # PyShark parses IEs differently - look for wlan_mgt fields
            if not hasattr(packet, 'wlan_mgt'):
                return ies
            
            # Common IE fields in PyShark
            ie_fields = [
                'supported_rates', 'extended_supported_rates', 'ht_capabilities',
                'vht_capabilities', 'extended_capabilities', 'power_capability'
            ]
            
            for field in ie_fields:
                if hasattr(packet.wlan_mgt, field):
                    ies.append({
                        'type': field,
                        'data': getattr(packet.wlan_mgt, field)
                    })
            
        except Exception as e:
            self.logger.debug(f"Error extracting IEs: {e}")
        
        return ies
    
    def _freq_to_channel(self, freq: int) -> int:
        """Convert frequency to WiFi channel number."""
        if 2412 <= freq <= 2484:
            if freq == 2484:
                return 14
            return (freq - 2412) // 5 + 1
        elif 5170 <= freq <= 5825:
            return (freq - 5000) // 5
        return 0
    
    def _update_client_data(self, probe_info: Dict[str, Any]):
        """Update client tracking data with probe information."""
        src_mac = probe_info['src_mac']
        timestamp = probe_info['timestamp']
        
        client = self.clients[src_mac]
        
        # Update timestamps
        if client['first_seen'] is None:
            client['first_seen'] = timestamp
        client['last_seen'] = timestamp
        
        # Update probe count and requests
        client['probe_count'] += 1
        client['probe_requests'].append(probe_info)
        
        # Track SSIDs
        if probe_info['ssid']:
            client['ssids_probed'].add(probe_info['ssid'])
        
        # Track signal strengths
        if probe_info['signal_strength'] is not None:
            client['signal_strengths'].append(probe_info['signal_strength'])
        
        # Calculate probe intervals
        if len(client['probe_requests']) > 1:
            prev_timestamp = client['probe_requests'][-2]['timestamp']
            interval = timestamp - prev_timestamp
            client['probe_intervals'].append(interval)
        
        # Analyze MAC address for randomization
        client['randomized_mac'] = self._is_randomized_mac(src_mac)
        client['vendor_oui'] = self._get_vendor_oui(src_mac)
        
        # Track IE signatures
        ie_signature = self._create_ie_signature(probe_info['ies'])
        if ie_signature and ie_signature not in client['ie_signatures']:
            client['ie_signatures'].append(ie_signature)
    
    def _is_randomized_mac(self, mac: str) -> bool:
        """Check if MAC address appears to be randomized."""
        try:
            # Remove colons and convert to bytes
            mac_bytes = bytes.fromhex(mac.replace(':', ''))
            # Check locally administered bit (bit 1 of first byte)
            return bool(mac_bytes[0] & 0x02)
        except:
            return False
    
    def _get_vendor_oui(self, mac: str) -> Optional[str]:
        """Extract vendor OUI from MAC address."""
        try:
            return mac[:8].upper()  # First 3 bytes
        except:
            return None
    
    def _create_ie_signature(self, ies: List[Dict[str, Any]]) -> Optional[str]:
        """Create a signature from Information Elements."""
        if not ies:
            return None
        
        # Sort IE types for consistent signature
        ie_types = sorted([ie['type'] for ie in ies])
        return ','.join(ie_types)
    
    def _analyze_privacy_implications(self, probe_info: Dict[str, Any]) -> List[Finding]:
        """Analyze privacy implications of probe behavior."""
        findings = []
        src_mac = probe_info['src_mac']
        client = self.clients[src_mac]
        
        try:
            # Check for SSID broadcasting
            if probe_info['ssid'] and probe_info['ssid'].strip():
                finding = Finding(
                    analyzer_name=self.name,
                    category=AnalysisCategory.PROBE_BEHAVIOR,
                    severity=Severity.WARNING,
                    title="SSID Broadcast in Probe Request",
                    description=f"Device {src_mac} is broadcasting SSID '{probe_info['ssid']}' in probe requests",
                    details={
                        "src_mac": src_mac,
                        "ssid": probe_info['ssid'],
                        "timestamp": probe_info['timestamp'],
                        "parser": "pyshark"
                    },
                    recommendations=[
                        "Configure device to use randomized MAC addresses",
                        "Disable automatic WiFi connection attempts",
                        "Use directed probe requests only"
                    ]
                )
                findings.append(finding)
            
            # Check for excessive probing
            if client['probe_count'] > 50:
                finding = Finding(
                    analyzer_name=self.name,
                    category=AnalysisCategory.PROBE_BEHAVIOR,
                    severity=Severity.CRITICAL,
                    title="Excessive Probe Request Activity",
                    description=f"Device {src_mac} has sent {client['probe_count']} probe requests",
                    details={
                        "src_mac": src_mac,
                        "probe_count": client['probe_count'],
                        "ssids_probed": list(client['ssids_probed']),
                        "parser": "pyshark"
                    },
                    recommendations=[
                        "Review device WiFi settings",
                        "Disable automatic network discovery",
                        "Use static network configurations"
                    ]
                )
                findings.append(finding)
            
            # Check for multiple SSID leakage
            if len(client['ssids_probed']) > 5:
                finding = Finding(
                    analyzer_name=self.name,
                    category=AnalysisCategory.PROBE_BEHAVIOR,
                    severity=Severity.CRITICAL,
                    title="Multiple Network History Disclosure",
                    description=f"Device {src_mac} is leaking history of {len(client['ssids_probed'])} networks",
                    details={
                        "src_mac": src_mac,
                        "ssids_leaked": list(client['ssids_probed']),
                        "parser": "pyshark"
                    },
                    recommendations=[
                        "Clear saved network list on device",
                        "Disable automatic reconnection to known networks",
                        "Use MAC address randomization"
                    ]
                )
                findings.append(finding)
        
        except Exception as e:
            self.logger.error(f"Error in privacy analysis: {e}")
        
        return findings
    
    def _analyze_tracking_risks(self, probe_info: Dict[str, Any]) -> List[Finding]:
        """Analyze tracking risks from probe behavior."""
        findings = []
        src_mac = probe_info['src_mac']
        client = self.clients[src_mac]
        
        try:
            # Check for consistent IE fingerprinting
            if len(client['ie_signatures']) == 1 and client['probe_count'] > 10:
                finding = Finding(
                    analyzer_name=self.name,
                    category=AnalysisCategory.PROBE_BEHAVIOR,
                    severity=Severity.WARNING,
                    title="Consistent Device Fingerprinting",
                    description=f"Device {src_mac} shows consistent IE signature across {client['probe_count']} probes",
                    details={
                        "src_mac": src_mac,
                        "ie_signature": client['ie_signatures'][0],
                        "probe_count": client['probe_count'],
                        "parser": "pyshark"
                    },
                    recommendations=[
                        "Use device randomization features",
                        "Update device firmware for better privacy",
                        "Consider privacy-focused WiFi settings"
                    ]
                )
                findings.append(finding)
            
            # Check for non-randomized MAC tracking
            if not client['randomized_mac'] and client['probe_count'] > 5:
                finding = Finding(
                    analyzer_name=self.name,
                    category=AnalysisCategory.PROBE_BEHAVIOR,
                    severity=Severity.CRITICAL,
                    title="Static MAC Address Tracking Risk",
                    description=f"Device {src_mac} uses static MAC address across {client['probe_count']} probes",
                    details={
                        "src_mac": src_mac,
                        "vendor_oui": client['vendor_oui'],
                        "probe_count": client['probe_count'],
                        "duration": client['last_seen'] - client['first_seen'] if client['first_seen'] else 0,
                        "parser": "pyshark"
                    },
                    recommendations=[
                        "Enable MAC address randomization",
                        "Use privacy mode in WiFi settings",
                        "Regularly reset network settings"
                    ]
                )
                findings.append(finding)
        
        except Exception as e:
            self.logger.error(f"Error in tracking analysis: {e}")
        
        return findings
    
    def _analyze_probe_patterns(self, probe_info: Dict[str, Any]) -> List[Finding]:
        """Analyze probe request patterns for behavioral insights."""
        findings = []
        src_mac = probe_info['src_mac']
        client = self.clients[src_mac]
        
        try:
            # Analyze probe timing patterns
            if len(client['probe_intervals']) >= 5:
                avg_interval = sum(client['probe_intervals']) / len(client['probe_intervals'])
                
                # Check for regular intervals (potential automated probing)
                if 0.5 <= avg_interval <= 2.0:  # Very regular intervals
                    variance = sum((x - avg_interval) ** 2 for x in client['probe_intervals']) / len(client['probe_intervals'])
                    
                    if variance < 0.1:  # Low variance = very regular
                        finding = Finding(
                            analyzer_name=self.name,
                            category=AnalysisCategory.PROBE_BEHAVIOR,
                            severity=Severity.INFO,
                            title="Regular Automated Probe Pattern",
                            description=f"Device {src_mac} shows regular probe intervals (avg: {avg_interval:.2f}s)",
                            details={
                                "src_mac": src_mac,
                                "avg_interval": avg_interval,
                                "variance": variance,
                                "probe_intervals": list(client['probe_intervals']),
                                "parser": "pyshark"
                            },
                            recommendations=[
                                "Review automated WiFi scanning settings",
                                "Consider disabling background network scanning"
                            ]
                        )
                        findings.append(finding)
            
            # Check for signal strength patterns (movement tracking)
            if len(client['signal_strengths']) > 5:
                signal_range = max(client['signal_strengths']) - min(client['signal_strengths'])
                
                if signal_range > 30:  # Significant signal variation
                    finding = Finding(
                        analyzer_name=self.name,
                        category=AnalysisCategory.PROBE_BEHAVIOR,
                        severity=Severity.INFO,
                        title="Device Movement Pattern Detected",
                        description=f"Device {src_mac} shows signal variation of {signal_range}dBm indicating movement",
                        details={
                            "src_mac": src_mac,
                            "signal_range": signal_range,
                            "min_signal": min(client['signal_strengths']),
                            "max_signal": max(client['signal_strengths']),
                            "parser": "pyshark"
                        },
                        recommendations=[
                            "Consider location privacy implications",
                            "Use static positioning for sensitive activities"
                        ]
                    )
                    findings.append(finding)
        
        except Exception as e:
            self.logger.error(f"Error in pattern analysis: {e}")
        
        return findings
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get comprehensive analysis summary."""
        if not PYSHARK_AVAILABLE:
            return {"error": "PyShark not available"}
        
        total_clients = len(self.clients)
        total_probes = sum(client['probe_count'] for client in self.clients.values())
        
        privacy_scores = []
        for client_data in self.clients.values():
            score = self._calculate_privacy_score(client_data)
            privacy_scores.append(score)
        
        return {
            "analyzer": self.name,
            "parser": "pyshark",
            "total_clients": total_clients,
            "total_probe_requests": total_probes,
            "clients_with_ssid_leakage": len([c for c in self.clients.values() if c['ssids_probed']]),
            "clients_using_random_mac": len([c for c in self.clients.values() if c['randomized_mac']]),
            "high_risk_clients": len([c for c in self.clients.values() 
                                   if self._calculate_privacy_score(c) >= self.privacy_threshold_score]),
            "average_privacy_score": sum(privacy_scores) / len(privacy_scores) if privacy_scores else 0,
            "unique_ssids_observed": len(set().union(*[c['ssids_probed'] for c in self.clients.values()])),
            "analysis_timespan": max([c['last_seen'] for c in self.clients.values()]) - 
                               min([c['first_seen'] for c in self.clients.values()]) 
                               if self.clients else 0
        }
    
    def _calculate_privacy_score(self, client_data: Dict[str, Any]) -> int:
        """Calculate privacy risk score for a client (0-10, higher is more risky)."""
        score = 0
        
        # SSID leakage
        ssid_count = len(client_data['ssids_probed'])
        if ssid_count > 0:
            score += min(ssid_count, 5)  # Max 5 points for SSID leakage
        
        # MAC randomization
        if not client_data['randomized_mac']:
            score += 3
        
        # Probe frequency
        if client_data['probe_count'] > 100:
            score += 2
        elif client_data['probe_count'] > 50:
            score += 1
        
        return min(score, 10)