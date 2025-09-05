"""
PyShark-specific Rogue AP & Security Threats Analyzer

Detects rogue access points, evil twin attacks, and security threats using PyShark's
native packet parsing capabilities.
"""

import statistics
from collections import defaultdict, Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Any, Set, Optional

try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False

from ....core.base_analyzer import BasePySharkAnalyzer
from ....core.models import Finding


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
    SUSPICIOUS = "suspicious"


@dataclass
class AccessPoint:
    """Access Point information."""
    bssid: str
    ssid: str
    channel: Optional[int] = None
    vendor_oui: Optional[str] = None
    beacon_interval: Optional[int] = None
    capabilities: Optional[str] = None
    encryption: List[str] = field(default_factory=list)
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    beacon_count: int = 0
    signal_strength: List[int] = field(default_factory=list)
    ie_signatures: List[str] = field(default_factory=list)


@dataclass
class RogueDetection:
    """Rogue AP detection result."""
    bssid: str
    ssid: str
    rogue_type: RogueType
    threat_level: ThreatLevel
    detection_reasons: List[str]
    legitimate_ap: Optional[str] = None
    confidence_score: float = 0.0


class PySharkRogueAPSecurityAnalyzer(BasePySharkAnalyzer):
    """
    PyShark-based rogue AP and security threats analyzer.
    
    Detects:
    - Evil twin access points
    - SSID spoofing attacks
    - Unauthorized access points
    - Suspicious AP behavior
    - Deauthentication attacks
    """
    
    def __init__(self):
        super().__init__()
        self.name = "PyShark Rogue AP & Security Threats Analyzer"
        self.description = "Detects rogue APs and security threats using PyShark parsing"
        self.version = "1.0.0"
        
        if not PYSHARK_AVAILABLE:
            self.logger.warning("PyShark not available - analyzer will not function")
        
        # AP tracking
        self.access_points: Dict[str, AccessPoint] = {}  # Key: bssid
        self.ssid_groups: Dict[str, List[str]] = defaultdict(list)  # Key: ssid, Value: list of bssids
        
        # Attack tracking
        self.deauth_attacks: Dict[str, List[float]] = defaultdict(list)  # Key: src_mac, Value: timestamps
        self.beacon_timing: Dict[str, List[float]] = defaultdict(list)  # Key: bssid, Value: timestamps
        
        # Vendor OUI database (simplified)
        self.vendor_ouis = {
            "00:50:f2": "Microsoft",
            "00:0c:42": "Cisco", 
            "00:24:a5": "Apple",
            "00:22:6b": "Apple",
            "8c:85:90": "Apple",
            "bc:67:1c": "Apple",
            "f0:18:98": "Apple"
        }
        
        # Detection thresholds
        self.DEAUTH_FLOOD_THRESHOLD = 10  # deauths per minute
        self.EVIL_TWIN_SIMILARITY_THRESHOLD = 0.8
        self.BEACON_TIMING_VARIANCE_THRESHOLD = 0.15

    def analyze_packet(self, packet, metadata: Dict[str, Any] = None) -> List[Finding]:
        """Analyze a single packet for rogue AP and security threats."""
        if not PYSHARK_AVAILABLE:
            return []
        
        findings = []
        
        try:
            if self._is_beacon_frame(packet):
                ap_info = self._extract_ap_info(packet)
                if ap_info:
                    findings.extend(self._analyze_ap_for_threats(ap_info))
            
            elif self._is_deauth_frame(packet):
                findings.extend(self._analyze_deauth_attack(packet))
            
            elif self._is_probe_response(packet):
                findings.extend(self._analyze_probe_response(packet))
        
        except Exception as e:
            self.logger.error(f"Error analyzing rogue AP threats: {e}")
        
        return findings
    
    def _is_beacon_frame(self, packet) -> bool:
        """Check if packet is a beacon frame."""
        try:
            if not hasattr(packet, 'wlan'):
                return False
            
            if hasattr(packet.wlan, 'fc_type') and hasattr(packet.wlan, 'fc_subtype'):
                frame_type = int(packet.wlan.fc_type)
                subtype = int(packet.wlan.fc_subtype)
                return frame_type == 0 and subtype == 8  # Management frame, beacon subtype
            
            return False
            
        except (AttributeError, ValueError):
            return False
    
    def _is_deauth_frame(self, packet) -> bool:
        """Check if packet is a deauthentication frame."""
        try:
            if not hasattr(packet, 'wlan'):
                return False
            
            if hasattr(packet.wlan, 'fc_type') and hasattr(packet.wlan, 'fc_subtype'):
                frame_type = int(packet.wlan.fc_type)
                subtype = int(packet.wlan.fc_subtype)
                return frame_type == 0 and subtype == 12  # Management frame, deauth subtype
            
            return False
            
        except (AttributeError, ValueError):
            return False
    
    def _is_probe_response(self, packet) -> bool:
        """Check if packet is a probe response frame."""
        try:
            if not hasattr(packet, 'wlan'):
                return False
            
            if hasattr(packet.wlan, 'fc_type') and hasattr(packet.wlan, 'fc_subtype'):
                frame_type = int(packet.wlan.fc_type)
                subtype = int(packet.wlan.fc_subtype)
                return frame_type == 0 and subtype == 5  # Management frame, probe response subtype
            
            return False
            
        except (AttributeError, ValueError):
            return False
    
    def _extract_ap_info(self, packet) -> Optional[AccessPoint]:
        """Extract access point information from beacon frame."""
        try:
            if not hasattr(packet, 'wlan'):
                return None
            
            bssid = packet.wlan.sa if hasattr(packet.wlan, 'sa') else None
            if not bssid:
                return None
            
            # Extract SSID
            ssid = ""
            if hasattr(packet, 'wlan_mgt') and hasattr(packet.wlan_mgt, 'ssid'):
                ssid = packet.wlan_mgt.ssid
            
            # Get or create AP entry
            if bssid not in self.access_points:
                self.access_points[bssid] = AccessPoint(bssid=bssid, ssid=ssid)
            
            ap = self.access_points[bssid]
            
            # Update basic info
            timestamp = float(packet.sniff_timestamp)
            if ap.first_seen is None:
                ap.first_seen = timestamp
            ap.last_seen = timestamp
            ap.beacon_count += 1
            
            # Extract beacon interval
            if hasattr(packet, 'wlan_mgt') and hasattr(packet.wlan_mgt, 'beacon_interval'):
                try:
                    ap.beacon_interval = int(packet.wlan_mgt.beacon_interval)
                except (ValueError, TypeError):
                    pass
            
            # Extract capabilities
            if hasattr(packet, 'wlan_mgt') and hasattr(packet.wlan_mgt, 'capabilities'):
                ap.capabilities = str(packet.wlan_mgt.capabilities)
            
            # Extract channel from RadioTap
            if hasattr(packet, 'radiotap'):
                if hasattr(packet.radiotap, 'channel_freq'):
                    try:
                        freq = int(packet.radiotap.channel_freq)
                        ap.channel = self._freq_to_channel(freq)
                    except (ValueError, TypeError):
                        pass
                
                # Extract signal strength
                if hasattr(packet.radiotap, 'dbm_antsignal'):
                    try:
                        ap.signal_strength.append(int(packet.radiotap.dbm_antsignal))
                    except (ValueError, TypeError):
                        pass
            
            # Extract vendor OUI
            oui = bssid[:8].upper()
            ap.vendor_oui = self.vendor_ouis.get(oui, "Unknown")
            
            # Track SSID groups
            if ssid not in self.ssid_groups:
                self.ssid_groups[ssid] = []
            if bssid not in self.ssid_groups[ssid]:
                self.ssid_groups[ssid].append(bssid)
            
            # Track beacon timing
            self.beacon_timing[bssid].append(timestamp)
            
            return ap
            
        except Exception as e:
            self.logger.debug(f"Error extracting AP info: {e}")
            return None
    
    def _analyze_ap_for_threats(self, ap: AccessPoint) -> List[Finding]:
        """Analyze access point for rogue/threat indicators."""
        findings = []
        
        try:
            # Check for evil twin attacks (same SSID, different BSSID)
            if ap.ssid and len(self.ssid_groups[ap.ssid]) > 1:
                findings.extend(self._detect_evil_twin(ap))
            
            # Check for suspicious beacon timing
            if len(self.beacon_timing[ap.bssid]) > 5:
                findings.extend(self._detect_beacon_anomalies(ap))
            
            # Check for open networks with suspicious characteristics
            if ap.capabilities and "privacy" not in ap.capabilities.lower():
                findings.extend(self._detect_suspicious_open_ap(ap))
        
        except Exception as e:
            self.logger.debug(f"Error analyzing AP threats: {e}")
        
        return findings
    
    def _detect_evil_twin(self, ap: AccessPoint) -> List[Finding]:
        """Detect potential evil twin attacks."""
        findings = []
        
        try:
            same_ssid_aps = [self.access_points[bssid] for bssid in self.ssid_groups[ap.ssid]]
            
            # Look for APs with same SSID but different characteristics
            for other_ap in same_ssid_aps:
                if other_ap.bssid == ap.bssid:
                    continue
                
                suspicion_reasons = []
                threat_level = ThreatLevel.LOW
                
                # Different vendor OUIs
                if ap.vendor_oui != other_ap.vendor_oui:
                    suspicion_reasons.append(f"Different vendors: {ap.vendor_oui} vs {other_ap.vendor_oui}")
                    threat_level = ThreatLevel.MEDIUM
                
                # Different channels
                if ap.channel and other_ap.channel and ap.channel != other_ap.channel:
                    suspicion_reasons.append(f"Different channels: {ap.channel} vs {other_ap.channel}")
                
                # Significant signal strength differences (potential proximity)
                if ap.signal_strength and other_ap.signal_strength:
                    ap_avg_signal = statistics.mean(ap.signal_strength)
                    other_avg_signal = statistics.mean(other_ap.signal_strength)
                    if abs(ap_avg_signal - other_avg_signal) > 20:
                        suspicion_reasons.append(f"Signal strength difference: {ap_avg_signal:.1f} vs {other_avg_signal:.1f} dBm")
                
                # Different beacon intervals
                if ap.beacon_interval and other_ap.beacon_interval and ap.beacon_interval != other_ap.beacon_interval:
                    suspicion_reasons.append(f"Different beacon intervals: {ap.beacon_interval} vs {other_ap.beacon_interval}")
                
                if len(suspicion_reasons) >= 2:
                    threat_level = ThreatLevel.HIGH
                    
                    findings.append(Finding(
                        analyzer_name=self.name,
                        finding_type="evil_twin_detected",
                        severity="warning" if threat_level == ThreatLevel.MEDIUM else "critical",
                        title="Potential Evil Twin AP Detected",
                        description=f"Suspicious AP {ap.bssid} mimicking SSID '{ap.ssid}'",
                        evidence={
                            "suspicious_bssid": ap.bssid,
                            "legitimate_bssid": other_ap.bssid,
                            "ssid": ap.ssid,
                            "suspicion_reasons": suspicion_reasons,
                            "threat_level": threat_level.value,
                            "ap_vendor": ap.vendor_oui,
                            "other_vendor": other_ap.vendor_oui,
                            "parser": "pyshark"
                        },
                        recommendations=[
                            "Investigate both APs to determine which is legitimate",
                            "Check physical location and ownership of APs",
                            "Monitor client connections to both APs",
                            "Consider blocking or isolating suspicious AP",
                            "Enable WPA3 with PMF to prevent impersonation"
                        ]
                    ))
        
        except Exception as e:
            self.logger.debug(f"Error detecting evil twin: {e}")
        
        return findings
    
    def _detect_beacon_anomalies(self, ap: AccessPoint) -> List[Finding]:
        """Detect suspicious beacon timing patterns."""
        findings = []
        
        try:
            timestamps = self.beacon_timing[ap.bssid]
            if len(timestamps) < 5:
                return findings
            
            # Calculate beacon intervals
            intervals = []
            for i in range(1, len(timestamps)):
                interval = timestamps[i] - timestamps[i-1]
                intervals.append(interval)
            
            if not intervals:
                return findings
            
            # Analyze timing regularity
            mean_interval = statistics.mean(intervals)
            if len(intervals) > 1:
                stddev = statistics.stdev(intervals)
                cv = stddev / mean_interval if mean_interval > 0 else 0
                
                # Very irregular timing might indicate fake AP
                if cv > self.BEACON_TIMING_VARIANCE_THRESHOLD:
                    findings.append(Finding(
                        analyzer_name=self.name,
                        finding_type="beacon_timing_anomaly",
                        severity="warning",
                        title="Irregular Beacon Timing Detected",
                        description=f"AP {ap.bssid} shows irregular beacon timing patterns",
                        evidence={
                            "bssid": ap.bssid,
                            "ssid": ap.ssid,
                            "mean_interval": mean_interval,
                            "timing_variance": cv,
                            "threshold": self.BEACON_TIMING_VARIANCE_THRESHOLD,
                            "beacon_count": len(timestamps),
                            "parser": "pyshark"
                        },
                        recommendations=[
                            "Investigate AP for potential rogue activity",
                            "Check if AP is using software-based beaconing",
                            "Monitor for other suspicious behaviors",
                            "Verify AP is authorized on network"
                        ]
                    ))
            
            # Check for extremely fast or slow beacon intervals
            expected_interval = (ap.beacon_interval / 1000.0) if ap.beacon_interval else 0.1
            if expected_interval > 0 and abs(mean_interval - expected_interval) > 0.05:
                findings.append(Finding(
                    analyzer_name=self.name,
                    finding_type="beacon_interval_mismatch",
                    severity="info",
                    title="Beacon Interval Mismatch",
                    description=f"AP {ap.bssid} actual timing differs from advertised interval",
                    evidence={
                        "bssid": ap.bssid,
                        "ssid": ap.ssid,
                        "advertised_interval": ap.beacon_interval,
                        "actual_interval": mean_interval,
                        "difference": abs(mean_interval - expected_interval),
                        "parser": "pyshark"
                    },
                    recommendations=[
                        "Check AP configuration for timing accuracy",
                        "Monitor for potential clock drift or tampering"
                    ]
                ))
        
        except Exception as e:
            self.logger.debug(f"Error detecting beacon anomalies: {e}")
        
        return findings
    
    def _detect_suspicious_open_ap(self, ap: AccessPoint) -> List[Finding]:
        """Detect suspicious characteristics in open APs."""
        findings = []
        
        try:
            # Check for open APs with common secure network SSIDs
            suspicious_open_ssids = [
                "Corporate", "Enterprise", "Company", "Internal", "Private",
                "Admin", "Management", "Secure", "VPN", "WiFi"
            ]
            
            if any(keyword.lower() in ap.ssid.lower() for keyword in suspicious_open_ssids):
                findings.append(Finding(
                    analyzer_name=self.name,
                    finding_type="suspicious_open_ap",
                    severity="warning", 
                    title="Suspicious Open AP Detected",
                    description=f"Open AP {ap.bssid} uses enterprise-sounding SSID '{ap.ssid}'",
                    evidence={
                        "bssid": ap.bssid,
                        "ssid": ap.ssid,
                        "vendor": ap.vendor_oui,
                        "channel": ap.channel,
                        "is_open": True,
                        "parser": "pyshark"
                    },
                    recommendations=[
                        "Investigate if this AP is authorized",
                        "Check if AP should have encryption enabled",
                        "Consider potential honeypot or rogue AP",
                        "Verify with network administrators"
                    ]
                ))
        
        except Exception as e:
            self.logger.debug(f"Error detecting suspicious open AP: {e}")
        
        return findings
    
    def _analyze_deauth_attack(self, packet) -> List[Finding]:
        """Analyze deauthentication attacks."""
        findings = []
        
        try:
            if not hasattr(packet, 'wlan'):
                return findings
            
            src_mac = packet.wlan.sa if hasattr(packet.wlan, 'sa') else None
            if not src_mac:
                return findings
            
            timestamp = float(packet.sniff_timestamp)
            self.deauth_attacks[src_mac].append(timestamp)
            
            # Check for deauth flood from this source
            recent_deauths = [t for t in self.deauth_attacks[src_mac] if timestamp - t < 60.0]  # Last minute
            
            if len(recent_deauths) >= self.DEAUTH_FLOOD_THRESHOLD:
                findings.append(Finding(
                    analyzer_name=self.name,
                    finding_type="deauth_flood",
                    severity="critical",
                    title="Deauthentication Flood Attack",
                    description=f"Source {src_mac} sending deauth flood ({len(recent_deauths)} in last minute)",
                    evidence={
                        "source_mac": src_mac,
                        "deauth_count": len(recent_deauths),
                        "time_window": "60 seconds",
                        "threshold": self.DEAUTH_FLOOD_THRESHOLD,
                        "timestamp": timestamp,
                        "parser": "pyshark"
                    },
                    recommendations=[
                        "Block or investigate source MAC address",
                        "Enable PMF (802.11w) to prevent deauth attacks",
                        "Monitor for continued attack activity",
                        "Check for rogue devices in physical area"
                    ]
                ))
        
        except Exception as e:
            self.logger.debug(f"Error analyzing deauth attack: {e}")
        
        return findings
    
    def _analyze_probe_response(self, packet) -> List[Finding]:
        """Analyze suspicious probe response patterns."""
        findings = []
        
        try:
            # Basic probe response analysis
            # Could expand to detect karma attacks, excessive responses, etc.
            pass
            
        except Exception as e:
            self.logger.debug(f"Error analyzing probe response: {e}")
        
        return findings
    
    def _freq_to_channel(self, freq: int) -> int:
        """Convert frequency to WiFi channel number."""
        if 2412 <= freq <= 2484:
            if freq == 2484:
                return 14
            return (freq - 2412) // 5 + 1
        elif 5170 <= freq <= 5825:
            return (freq - 5000) // 5
        return 0
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get comprehensive analysis summary."""
        if not PYSHARK_AVAILABLE:
            return {"error": "PyShark not available"}
        
        ssid_duplicates = {ssid: bssids for ssid, bssids in self.ssid_groups.items() if len(bssids) > 1}
        
        return {
            "analyzer": self.name,
            "parser": "pyshark",
            "total_access_points": len(self.access_points),
            "unique_ssids": len(self.ssid_groups),
            "ssid_duplicates": len(ssid_duplicates),
            "duplicate_ssid_details": ssid_duplicates,
            "deauth_sources": len(self.deauth_attacks),
            "total_deauth_attacks": sum(len(attacks) for attacks in self.deauth_attacks.values()),
            "vendor_distribution": Counter(ap.vendor_oui for ap in self.access_points.values()),
            "channel_distribution": Counter(ap.channel for ap in self.access_points.values() if ap.channel),
            "open_networks": sum(1 for ap in self.access_points.values() 
                               if ap.capabilities and "privacy" not in ap.capabilities.lower())
        }