"""
Deauthentication flood and attack detection analyzer.

This analyzer detects deauthentication flood attacks, targeted attacks,
and unusual deauth patterns based on the comprehensive wireless checklist.
"""

import statistics
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import List, Dict, Any, Set, Tuple

from scapy.all import Packet
from scapy.layers.dot11 import Dot11, Dot11Deauth

from ...core.base_analyzer import SecurityThreatAnalyzer
from ...core.models import (
    Finding, 
    Severity, 
    AnalysisContext,
    PacketReference
)


class DeauthFloodDetector(SecurityThreatAnalyzer):
    """
    Detects deauthentication flood attacks and suspicious patterns.
    
    This analyzer implements detection for:
    - High-rate deauth floods
    - Targeted deauth attacks
    - Suspicious reason code patterns
    - Broadcast vs unicast deauth analysis
    - Temporal pattern analysis
    """
    
    def __init__(self):
        super().__init__("Deauthentication Flood Detector", "1.0")
        self.description = "Detects deauth floods, targeted attacks, and unusual deauth patterns"
        
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
        
    def pre_analysis_setup(self, context: AnalysisContext) -> None:
        """Setup before analysis begins."""
        self.reset_analysis_state()
        self.logger.info(f"Starting {self.name} analysis")
        
    def is_applicable(self, packet: Packet) -> bool:
        """Check if packet is a deauthentication frame."""
        return packet.haslayer(Dot11Deauth)
        
    def analyze(self, packets: List[Packet], context: AnalysisContext) -> List[Finding]:
        """
        Analyze packets for deauthentication attacks and patterns.
        
        Args:
            packets: List of packets to analyze
            context: Analysis context
            
        Returns:
            List of findings
        """
        findings = []
        
        # Filter for deauth packets
        deauth_packets = [p for p in packets if self.is_applicable(p)]
        
        if not deauth_packets:
            self.logger.debug("No deauth packets found")
            return findings
            
        self.logger.info(f"Analyzing {len(deauth_packets)} deauth packets")
        
        # Collect deauth packet information
        self._collect_deauth_stats(deauth_packets)
        
        # Analyze different attack patterns
        findings.extend(self._detect_flood_attacks(context))
        findings.extend(self._detect_targeted_attacks())
        findings.extend(self._detect_suspicious_reasons())
        findings.extend(self._detect_broadcast_attacks())
        findings.extend(self._detect_temporal_patterns())
        findings.extend(self._detect_source_anomalies())
        
        self.logger.info(f"Generated {len(findings)} deauth-related findings")
        return findings
        
    def _collect_deauth_stats(self, packets: List[Packet]) -> None:
        """Collect statistics from deauth packets."""
        for i, packet in enumerate(packets):
            if not packet.haslayer(Dot11) or not packet.haslayer(Dot11Deauth):
                continue
                
            dot11 = packet[Dot11]
            deauth = packet[Dot11Deauth]
            
            # Basic addressing
            src_mac = self._normalize_mac(dot11.addr2)
            dst_mac = self._normalize_mac(dot11.addr1) 
            bssid = self._normalize_mac(dot11.addr3)
            
            # Reason code
            reason = getattr(deauth, 'reason', 0)
            
            # Timestamp
            timestamp = getattr(packet, 'time', 0.0)
            
            # Store packet info
            packet_info = {
                'packet_index': i,
                'timestamp': timestamp,
                'src_mac': src_mac,
                'dst_mac': dst_mac,
                'bssid': bssid,
                'reason': reason,
                'is_broadcast': dst_mac == 'ff:ff:ff:ff:ff:ff'
            }
            
            self.deauth_packets.append(packet_info)
            self.deauth_timeline.append(timestamp)
            
            # Update counters
            if src_mac:
                self.source_stats[src_mac] += 1
            if dst_mac:
                self.target_stats[dst_mac] += 1
            if bssid:
                self.bssid_stats[bssid] += 1
            if reason:
                self.reason_stats[reason] += 1
                
    def _detect_flood_attacks(self, context: AnalysisContext) -> List[Finding]:
        """Detect high-rate deauth flooding."""
        findings = []
        
        if not self.deauth_timeline:
            return findings
            
        duration = context.duration
        if duration <= 0:
            return findings
            
        deauth_rate = len(self.deauth_packets) / duration
        
        if deauth_rate > self.flood_rate_threshold:
            severity = (Severity.CRITICAL if deauth_rate > self.critical_rate_threshold 
                       else Severity.WARNING)
            
            # Analyze burst patterns
            burst_analysis = self._analyze_burst_patterns()
            
            # Get top sources
            top_sources = dict(self.source_stats.most_common(5))
            max_from_single = max(self.source_stats.values()) if self.source_stats else 0
            
            finding = self.create_finding(
                severity=severity,
                title="Deauthentication Flood Attack Detected",
                description=f"High deauth rate detected: {deauth_rate:.1f} frames/sec over {duration:.1f}s",
                details={
                    "deauth_rate_per_second": deauth_rate,
                    "total_deauth_frames": len(self.deauth_packets),
                    "capture_duration": duration,
                    "unique_sources": len(self.source_stats),
                    "max_from_single_source": max_from_single,
                    "top_sources": top_sources,
                    "burst_analysis": burst_analysis
                },
                recommendations=self._get_flood_recommendations(deauth_rate),
                confidence=0.9 if deauth_rate > self.critical_rate_threshold else 0.7
            )
            
            findings.append(finding)
            
        return findings
        
    def _detect_targeted_attacks(self) -> List[Finding]:
        """Detect targeted deauth attacks against specific clients."""
        findings = []
        
        for target_mac, count in self.target_stats.most_common():
            if target_mac == 'ff:ff:ff:ff:ff:ff':  # Skip broadcast
                continue
                
            if count >= self.targeted_threshold:
                # Analyze sources targeting this MAC
                targeting_sources = []
                for packet_info in self.deauth_packets:
                    if packet_info['dst_mac'] == target_mac:
                        targeting_sources.append(packet_info['src_mac'])
                        
                source_diversity = len(set(targeting_sources))
                
                severity = Severity.CRITICAL if count > 50 else Severity.WARNING
                
                finding = self.create_finding(
                    severity=severity,
                    title="Targeted Deauthentication Attack",
                    description=f"Client {target_mac} targeted with {count} deauth frames",
                    details={
                        "target_mac": target_mac,
                        "deauth_count": count,
                        "attacking_sources": list(set(targeting_sources)),
                        "source_diversity": source_diversity,
                        "attack_pattern": "focused" if source_diversity == 1 else "distributed"
                    },
                    station_mac=target_mac,
                    recommendations=[
                        "Investigate client behavior or connectivity issues",
                        "Check if client is legitimate or potentially malicious",
                        "Consider MAC filtering or enhanced monitoring",
                        "Enable 802.11w (PMF) if supported by infrastructure"
                    ],
                    confidence=0.8
                )
                
                findings.append(finding)
                
        return findings
        
    def _detect_suspicious_reasons(self) -> List[Finding]:
        """Detect suspicious reason code patterns."""
        findings = []
        
        for reason, count in self.reason_stats.items():
            if reason in self.suspicious_reasons and count >= self.suspicious_reason_threshold:
                
                # Calculate percentage of total deauths
                total_deauths = len(self.deauth_packets)
                percentage = (count / total_deauths) * 100
                
                finding = self.create_finding(
                    severity=Severity.WARNING,
                    title="Suspicious Deauth Reason Code Pattern",
                    description=f"High frequency of reason code {reason}: {count} occurrences ({percentage:.1f}%)",
                    details={
                        "reason_code": reason,
                        "reason_description": self.suspicious_reasons[reason],
                        "count": count,
                        "percentage_of_total": percentage,
                        "total_deauths": total_deauths,
                        "reason_distribution": dict(self.reason_stats)
                    },
                    recommendations=[
                        f"Investigate the high frequency of reason code {reason}",
                        "Review 802.11 standard for legitimate uses of this reason",
                        "Check for attack tools using this specific reason code",
                        "Consider pattern as potential attack indicator"
                    ],
                    confidence=0.6
                )
                
                findings.append(finding)
                
        return findings
        
    def _detect_broadcast_attacks(self) -> List[Finding]:
        """Detect broadcast deauthentication attacks."""
        findings = []
        
        broadcast_count = sum(1 for p in self.deauth_packets if p['is_broadcast'])
        
        if broadcast_count > 5:  # Threshold for broadcast attacks
            total_deauths = len(self.deauth_packets)
            broadcast_percentage = (broadcast_count / total_deauths) * 100
            
            # Find sources of broadcast deauths
            broadcast_sources = []
            for packet_info in self.deauth_packets:
                if packet_info['is_broadcast']:
                    broadcast_sources.append(packet_info['src_mac'])
                    
            unique_sources = len(set(broadcast_sources))
            
            finding = self.create_finding(
                severity=Severity.CRITICAL,
                title="Broadcast Deauthentication Attack",
                description=f"Broadcast deauth attack detected: {broadcast_count} frames ({broadcast_percentage:.1f}%)",
                details={
                    "broadcast_deauth_count": broadcast_count,
                    "total_deauth_count": total_deauths,
                    "broadcast_percentage": broadcast_percentage,
                    "attacking_sources": list(set(broadcast_sources)),
                    "unique_sources": unique_sources
                },
                recommendations=[
                    "This indicates a network disruption attack",
                    "Immediately investigate broadcast deauth sources",
                    "Enable 802.11w (Management Frame Protection) on all devices",
                    "Consider emergency network isolation if attack is ongoing",
                    "Block or investigate suspicious source MACs"
                ],
                confidence=0.9
            )
            
            findings.append(finding)
            
        return findings
        
    def _detect_temporal_patterns(self) -> List[Finding]:
        """Detect temporal patterns in deauth attacks."""
        findings = []
        
        if len(self.deauth_timeline) < 10:  # Need enough data points
            return findings
            
        # Sort timeline
        timeline = sorted(self.deauth_timeline)
        
        # Calculate inter-frame intervals
        intervals = []
        for i in range(1, len(timeline)):
            interval = timeline[i] - timeline[i-1]
            intervals.append(interval)
            
        if not intervals:
            return findings
            
        # Analyze interval patterns
        avg_interval = statistics.mean(intervals)
        interval_stddev = statistics.stdev(intervals) if len(intervals) > 1 else 0
        
        # Detect very regular patterns (potential automated attacks)
        if interval_stddev < 0.1 and avg_interval < 1.0:  # Very regular, fast intervals
            finding = self.create_finding(
                severity=Severity.WARNING,
                title="Regular Deauth Pattern Detected",
                description=f"Highly regular deauth timing detected (avg={avg_interval:.3f}s, σ={interval_stddev:.3f}s)",
                details={
                    "average_interval_seconds": avg_interval,
                    "interval_standard_deviation": interval_stddev,
                    "regularity_score": 1.0 - (interval_stddev / max(avg_interval, 0.001)),
                    "total_intervals": len(intervals),
                    "pattern_type": "automated_attack"
                },
                recommendations=[
                    "Regular timing suggests automated attack tool",
                    "Look for attack software or rogue devices",
                    "Check for periodic patterns in source MAC addresses",
                    "Consider rate limiting or traffic shaping defenses"
                ],
                confidence=0.7
            )
            
            findings.append(finding)
            
        # Detect burst patterns
        burst_analysis = self._analyze_burst_patterns()
        if burst_analysis['burst_count'] > 3:
            finding = self.create_finding(
                severity=Severity.WARNING,
                title="Burst Pattern Deauth Attack",
                description=f"Bursty deauth pattern detected: {burst_analysis['burst_count']} bursts",
                details=burst_analysis,
                recommendations=[
                    "Bursty patterns may indicate intermittent attacks",
                    "Check for correlation with network events or user activity",
                    "Monitor for recurring burst patterns",
                    "Investigate potential triggering events"
                ],
                confidence=0.6
            )
            
            findings.append(finding)
            
        return findings
        
    def _detect_source_anomalies(self) -> List[Finding]:
        """Detect anomalies in deauth source behavior."""
        findings = []
        
        if not self.source_stats:
            return findings
            
        # Analyze source distribution
        total_sources = len(self.source_stats)
        total_deauths = sum(self.source_stats.values())
        
        # Check for single dominant source
        max_from_single = max(self.source_stats.values())
        dominant_percentage = (max_from_single / total_deauths) * 100
        
        if dominant_percentage > 80 and max_from_single > 20:
            dominant_source = self.source_stats.most_common(1)[0][0]
            
            finding = self.create_finding(
                severity=Severity.CRITICAL,
                title="Single Source Deauth Flood",
                description=f"One source ({dominant_source}) responsible for {dominant_percentage:.1f}% of deauths",
                details={
                    "dominant_source": dominant_source,
                    "dominant_percentage": dominant_percentage,
                    "deauth_count": max_from_single,
                    "total_sources": total_sources,
                    "total_deauths": total_deauths
                },
                recommendations=[
                    f"Immediately investigate source MAC {dominant_source}",
                    "Check if source is legitimate AP or rogue device",
                    "Consider blocking this MAC address",
                    "Verify source is not a compromised device"
                ],
                confidence=0.9
            )
            
            findings.append(finding)
            
        # Check for unusual MAC patterns
        suspicious_macs = self._detect_suspicious_mac_patterns()
        if suspicious_macs:
            finding = self.create_finding(
                severity=Severity.WARNING,
                title="Suspicious MAC Address Patterns",
                description=f"Detected {len(suspicious_macs)} potentially spoofed or unusual MAC addresses",
                details={
                    "suspicious_macs": suspicious_macs,
                    "total_sources": total_sources,
                    "analysis": "MACs may be randomized, spoofed, or from unknown vendors"
                },
                recommendations=[
                    "Verify legitimacy of suspicious MAC addresses",
                    "Check OUI database for vendor information",
                    "Look for MAC randomization or spoofing patterns",
                    "Cross-reference with legitimate device inventory"
                ],
                confidence=0.5
            )
            
            findings.append(finding)
            
        return findings
        
    def _analyze_burst_patterns(self) -> Dict[str, Any]:
        """Analyze burst patterns in deauth timeline."""
        if not self.deauth_timeline:
            return {"burst_count": 0, "bursts": []}
            
        timeline = sorted(self.deauth_timeline)
        bursts = []
        current_burst = [timeline[0]]
        burst_threshold = 2.0  # seconds
        
        for i in range(1, len(timeline)):
            if timeline[i] - timeline[i-1] <= burst_threshold:
                current_burst.append(timeline[i])
            else:
                if len(current_burst) > 1:
                    bursts.append({
                        "start_time": current_burst[0],
                        "end_time": current_burst[-1],
                        "duration": current_burst[-1] - current_burst[0],
                        "frame_count": len(current_burst),
                        "rate": len(current_burst) / max(current_burst[-1] - current_burst[0], 0.001)
                    })
                current_burst = [timeline[i]]
                
        # Don't forget the last burst
        if len(current_burst) > 1:
            bursts.append({
                "start_time": current_burst[0],
                "end_time": current_burst[-1], 
                "duration": current_burst[-1] - current_burst[0],
                "frame_count": len(current_burst),
                "rate": len(current_burst) / max(current_burst[-1] - current_burst[0], 0.001)
            })
            
        return {
            "burst_count": len(bursts),
            "bursts": bursts,
            "max_burst_size": max((b["frame_count"] for b in bursts), default=0),
            "max_burst_rate": max((b["rate"] for b in bursts), default=0)
        }
        
    def _detect_suspicious_mac_patterns(self) -> List[Dict[str, Any]]:
        """Detect suspicious MAC address patterns."""
        suspicious = []
        
        for mac, count in self.source_stats.items():
            if not mac or mac == '00:00:00:00:00:00':
                continue
                
            suspicion_reasons = []
            
            # Check for common spoofed patterns
            if mac.startswith('00:00:00'):
                suspicion_reasons.append("Starts with 00:00:00 (common spoofed pattern)")
            if mac.startswith('ff:ff:ff'):
                suspicion_reasons.append("Starts with ff:ff:ff (invalid unicast)")
            if mac.count('00') >= 3:
                suspicion_reasons.append("Contains many zero octets")
            if mac.count('ff') >= 3:
                suspicion_reasons.append("Contains many ff octets")
                
            # Check for sequential patterns
            octets = mac.split(':')
            if len(octets) == 6:
                try:
                    # Check if last few octets are sequential
                    last_three = [int(octet, 16) for octet in octets[-3:]]
                    if last_three == [last_three[0] + i for i in range(3)]:
                        suspicion_reasons.append("Sequential pattern in MAC address")
                except ValueError:
                    pass
                    
            if suspicion_reasons:
                suspicious.append({
                    "mac": mac,
                    "deauth_count": count,
                    "suspicion_reasons": suspicion_reasons
                })
                
        return suspicious
        
    def _get_flood_recommendations(self, rate: float) -> List[str]:
        """Get recommendations based on flood rate."""
        base_recommendations = [
            "Enable 802.11w (Management Frame Protection) on all capable devices",
            "Investigate source MAC addresses for potential rogue devices",
            "Consider emergency network isolation if attack is ongoing",
            "Review wireless IDS/IPS logs for correlated events"
        ]
        
        if rate > self.critical_rate_threshold:
            base_recommendations.extend([
                "IMMEDIATE ACTION REQUIRED - Critical flood rate detected",
                "Consider shutting down affected APs temporarily",
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
        
    def post_analysis_cleanup(self, context: AnalysisContext) -> None:
        """Cleanup after analysis."""
        self.logger.info(f"Processed {len(self.deauth_packets)} deauth packets")
        self.logger.info(f"Found {len(self.source_stats)} unique sources")
        self.logger.info(f"Found {len(self.target_stats)} unique targets")
        
        # Store summary in context for other analyzers
        context.security_context['deauth_summary'] = {
            'total_deauths': len(self.deauth_packets),
            'unique_sources': len(self.source_stats),
            'unique_targets': len(self.target_stats),
            'reason_codes': dict(self.reason_stats),
            'top_sources': dict(self.source_stats.most_common(10))
        }
