"""
Scapy-specific Deauthentication Flood and Attack Detection Analyzer

Detects deauthentication flood attacks, targeted attacks, and unusual deauth patterns
using Scapy's native packet parsing capabilities.
"""

import statistics
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import List, Dict, Any, Set, Tuple

from scapy.all import Packet
from scapy.layers.dot11 import Dot11, Dot11Deauth

from ....core.base_analyzer import BaseScapyAnalyzer
from ....core.models import Finding


class ScapyDeauthFloodDetector(BaseScapyAnalyzer):
    """
    Scapy-based deauthentication flood and attack detector.
    
    This analyzer implements detection for:
    - High-rate deauth floods
    - Targeted deauth attacks
    - Suspicious reason code patterns
    - Broadcast vs unicast deauth analysis
    - Temporal pattern analysis
    """
    
    def __init__(self):
        super().__init__()
        self.name = "Scapy Deauthentication Flood Detector"
        self.description = "Detects deauth floods and attacks using Scapy parsing"
        self.version = "1.0.0"
        
        # Configuration thresholds
        self.flood_rate_threshold = 5.0  # deauths per second
        self.critical_rate_threshold = 20.0  # critical flood rate
        self.targeted_threshold = 10  # deauths to single target
        self.suspicious_reason_threshold = 10  # count for suspicious reasons
        
        # Known suspicious reason codes
        self.suspicious_reasons = {
            1: "Unspecified reason (common in attacks)",
            3: "Deauthenticated because sending STA is leaving",
            7: "Class 3 frame received from nonassociated STA",
            8: "Disassociated because sending STA is leaving BSS"
        }
        
        # Tracking state
        self.reset_analysis_state()
        
    def reset_analysis_state(self):
        """Reset analysis state for new capture."""
        self.deauth_packets = []
        self.deauth_timeline = []
        self.source_stats = Counter()
        self.target_stats = Counter()
        self.bssid_stats = Counter()
        self.reason_stats = Counter()
        self.capture_start_time = None
        self.capture_end_time = None

    def analyze_packet(self, packet, metadata: Dict[str, Any] = None) -> List[Finding]:
        """Analyze a single packet for deauthentication attacks."""
        findings = []
        
        try:
            if not packet.haslayer(Dot11Deauth):
                return findings
            
            # Extract packet information
            packet_info = self._extract_deauth_info(packet)
            if not packet_info:
                return findings
            
            # Store packet info
            self.deauth_packets.append(packet_info)
            if packet_info['timestamp'] > 0:
                self.deauth_timeline.append(packet_info['timestamp'])
                
                # Update time bounds
                if self.capture_start_time is None or packet_info['timestamp'] < self.capture_start_time:
                    self.capture_start_time = packet_info['timestamp']
                if self.capture_end_time is None or packet_info['timestamp'] > self.capture_end_time:
                    self.capture_end_time = packet_info['timestamp']
            
            # Update counters
            if packet_info['src_mac']:
                self.source_stats[packet_info['src_mac']] += 1
            if packet_info['dst_mac']:
                self.target_stats[packet_info['dst_mac']] += 1
            if packet_info['bssid']:
                self.bssid_stats[packet_info['bssid']] += 1
            if packet_info['reason']:
                self.reason_stats[packet_info['reason']] += 1
            
            # Real-time analysis for immediate threats
            findings.extend(self._analyze_immediate_threats(packet_info))
            
        except Exception as e:
            self.logger.error(f"Error analyzing deauth packet: {e}")
        
        return findings
    
    def _extract_deauth_info(self, packet) -> Dict[str, Any]:
        """Extract deauth packet information using Scapy."""
        try:
            if not packet.haslayer(Dot11) or not packet.haslayer(Dot11Deauth):
                return None
            
            dot11 = packet[Dot11]
            deauth = packet[Dot11Deauth]
            
            # Extract MAC addresses
            src_mac = self._normalize_mac(str(dot11.addr2)) if hasattr(dot11, 'addr2') and dot11.addr2 else None
            dst_mac = self._normalize_mac(str(dot11.addr1)) if hasattr(dot11, 'addr1') and dot11.addr1 else None
            bssid = self._normalize_mac(str(dot11.addr3)) if hasattr(dot11, 'addr3') and dot11.addr3 else None
            
            # Extract reason code
            reason = int(deauth.reason) if hasattr(deauth, 'reason') else 0
            
            # Extract timestamp
            timestamp = float(packet.time) if hasattr(packet, 'time') else 0.0
            
            return {
                'timestamp': timestamp,
                'src_mac': src_mac,
                'dst_mac': dst_mac,
                'bssid': bssid,
                'reason': reason,
                'is_broadcast': dst_mac == 'ff:ff:ff:ff:ff:ff' if dst_mac else False
            }
            
        except Exception as e:
            self.logger.debug(f"Error extracting deauth info: {e}")
            return None
    
    def _analyze_immediate_threats(self, packet_info: Dict[str, Any]) -> List[Finding]:
        """Analyze for immediate threats that require rapid response."""
        findings = []
        
        # Check for broadcast deauth (immediate critical threat)
        if packet_info['is_broadcast']:
            findings.append(self.create_finding(
                finding_type="deauth_attack",
                severity="critical",
                title="Broadcast Deauth Attack Frame",
                description=f"Broadcast deauth detected from {packet_info['src_mac']}",
                evidence={
                    "src_mac": packet_info['src_mac'],
                    "reason_code": packet_info['reason'],
                    "timestamp": packet_info['timestamp'],
                    "bssid": packet_info['bssid'],
                    "parser": "scapy"
                },
                recommendations=[
                    "Immediate network disruption threat detected",
                    "Enable 802.11w (Management Frame Protection)",
                    "Block source MAC if confirmed malicious",
                    "Consider emergency network isolation"
                ]
            ))
        
        # Check for suspicious reason codes
        if packet_info['reason'] in self.suspicious_reasons:
            findings.append(self.create_finding(
                finding_type="suspicious_reason",
                severity="warning",
                title="Suspicious Deauth Reason Code",
                description=f"Reason code {packet_info['reason']}: {self.suspicious_reasons[packet_info['reason']]}",
                evidence={
                    "reason_code": packet_info['reason'],
                    "reason_description": self.suspicious_reasons[packet_info['reason']],
                    "src_mac": packet_info['src_mac'],
                    "dst_mac": packet_info['dst_mac'],
                    "timestamp": packet_info['timestamp'],
                    "parser": "scapy"
                },
                recommendations=[
                    "Monitor for pattern of this reason code",
                    "Check if legitimate network operation",
                    "Consider as potential attack indicator"
                ]
            ))
        
        return findings
    
    def analyze_flood_patterns(self) -> List[Finding]:
        """Analyze accumulated deauth data for flood patterns."""
        findings = []
        
        if len(self.deauth_packets) < 5:
            return findings
        
        # Calculate capture duration
        if self.capture_start_time and self.capture_end_time:
            duration = self.capture_end_time - self.capture_start_time
            if duration > 0:
                deauth_rate = len(self.deauth_packets) / duration
                
                if deauth_rate > self.flood_rate_threshold:
                    severity = "critical" if deauth_rate > self.critical_rate_threshold else "warning"
                    
                    # Analyze source distribution
                    top_sources = dict(self.source_stats.most_common(5))
                    max_from_single = max(self.source_stats.values()) if self.source_stats else 0
                    
                    findings.append(self.create_finding(
                        finding_type="deauth_flood",
                        severity=severity,
                        title="Deauthentication Flood Attack",
                        description=f"High deauth rate: {deauth_rate:.1f} frames/sec over {duration:.1f}s",
                        evidence={
                            "deauth_rate_per_second": deauth_rate,
                            "total_deauth_frames": len(self.deauth_packets),
                            "capture_duration": duration,
                            "unique_sources": len(self.source_stats),
                            "max_from_single_source": max_from_single,
                            "top_sources": top_sources,
                            "parser": "scapy"
                        },
                        recommendations=self._get_flood_recommendations(deauth_rate)
                    ))
        
        return findings
    
    def analyze_targeted_attacks(self) -> List[Finding]:
        """Analyze for targeted deauth attacks against specific clients."""
        findings = []
        
        for target_mac, count in self.target_stats.most_common():
            if target_mac == 'ff:ff:ff:ff:ff:ff':  # Skip broadcast
                continue
            
            if count >= self.targeted_threshold:
                # Find sources targeting this MAC
                targeting_sources = []
                for packet_info in self.deauth_packets:
                    if packet_info['dst_mac'] == target_mac:
                        targeting_sources.append(packet_info['src_mac'])
                
                source_diversity = len(set(targeting_sources))
                severity = "critical" if count > 50 else "warning"
                
                findings.append(self.create_finding(
                    finding_type="targeted_deauth",
                    severity=severity,
                    title="Targeted Deauthentication Attack",
                    description=f"Client {target_mac} targeted with {count} deauth frames",
                    evidence={
                        "target_mac": target_mac,
                        "deauth_count": count,
                        "attacking_sources": list(set(targeting_sources)),
                        "source_diversity": source_diversity,
                        "attack_pattern": "focused" if source_diversity == 1 else "distributed",
                        "parser": "scapy"
                    },
                    recommendations=[
                        "Investigate client behavior or connectivity issues",
                        "Check if client is legitimate or potentially malicious",
                        "Consider MAC filtering or enhanced monitoring",
                        "Enable 802.11w (PMF) if supported by infrastructure"
                    ]
                ))
        
        return findings
    
    def analyze_temporal_patterns(self) -> List[Finding]:
        """Analyze temporal patterns in deauth timeline."""
        findings = []
        
        if len(self.deauth_timeline) < 10:
            return findings
        
        # Sort timeline and calculate intervals
        timeline = sorted(self.deauth_timeline)
        intervals = []
        for i in range(1, len(timeline)):
            interval = timeline[i] - timeline[i-1]
            intervals.append(interval)
        
        if not intervals:
            return findings
        
        # Analyze interval patterns
        avg_interval = statistics.mean(intervals)
        interval_stddev = statistics.stdev(intervals) if len(intervals) > 1 else 0
        
        # Detect very regular patterns (automated attacks)
        if interval_stddev < 0.1 and avg_interval < 1.0:
            findings.append(self.create_finding(
                finding_type="automated_attack",
                severity="warning",
                title="Regular Deauth Pattern Detected",
                description=f"Highly regular timing (avg={avg_interval:.3f}s, σ={interval_stddev:.3f}s)",
                evidence={
                    "average_interval_seconds": avg_interval,
                    "interval_standard_deviation": interval_stddev,
                    "regularity_score": 1.0 - (interval_stddev / max(avg_interval, 0.001)),
                    "total_intervals": len(intervals),
                    "pattern_type": "automated_attack",
                    "parser": "scapy"
                },
                recommendations=[
                    "Regular timing suggests automated attack tool",
                    "Look for attack software or rogue devices",
                    "Check for periodic patterns in source MAC addresses",
                    "Consider rate limiting or traffic shaping defenses"
                ]
            ))
        
        return findings
    
    def _get_flood_recommendations(self, rate: float) -> List[str]:
        """Get recommendations based on flood rate."""
        base_recommendations = [
            "Enable 802.11w (Management Frame Protection) on all capable devices",
            "Investigate source MAC addresses for potential rogue devices",
            "Review wireless IDS/IPS logs for correlated events"
        ]
        
        if rate > self.critical_rate_threshold:
            base_recommendations.extend([
                "IMMEDIATE ACTION REQUIRED - Critical flood rate detected",
                "Consider emergency network isolation",
                "Implement emergency MAC address blocking",
                "Contact security team immediately"
            ])
        elif rate > 10.0:
            base_recommendations.extend([
                "High priority investigation required",
                "Increase monitoring on affected network segments",
                "Prepare for potential network isolation"
            ])
        else:
            base_recommendations.extend([
                "Monitor for escalation of attack pattern",
                "Document pattern for future reference"
            ])
        
        return base_recommendations
    
    def _normalize_mac(self, mac: str) -> str:
        """Normalize MAC address format."""
        if not mac:
            return ""
        return mac.lower().replace('-', ':')
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get comprehensive analysis summary."""
        duration = 0
        if self.capture_start_time and self.capture_end_time:
            duration = self.capture_end_time - self.capture_start_time
        
        return {
            "analyzer": self.name,
            "parser": "scapy",
            "total_deauth_packets": len(self.deauth_packets),
            "unique_sources": len(self.source_stats),
            "unique_targets": len(self.target_stats),
            "unique_bssids": len(self.bssid_stats),
            "capture_duration": duration,
            "deauth_rate": len(self.deauth_packets) / duration if duration > 0 else 0,
            "reason_code_distribution": dict(self.reason_stats.most_common()),
            "top_sources": dict(self.source_stats.most_common(10)),
            "top_targets": dict(self.target_stats.most_common(10)),
            "broadcast_deauths": sum(1 for p in self.deauth_packets if p['is_broadcast'])
        }