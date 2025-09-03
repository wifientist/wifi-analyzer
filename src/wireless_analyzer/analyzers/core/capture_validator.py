"""
Capture quality analysis and validation for wireless PCAP data.

This analyzer validates the quality and completeness of wireless packet captures:
- Monitor mode detection and validation
- Timing accuracy and consistency checks
- FCS (Frame Check Sequence) inclusion validation
- Hardware/driver capability assessment
- Capture completeness and integrity analysis
- RadioTap header presence and quality
"""

import statistics
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import List, Dict, Any, Set, Tuple, Optional

from scapy.all import Packet
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeResp, Dot11ProbeReq, Dot11Auth, Dot11Deauth
from scapy.layers.dot11 import Dot11AssoReq, Dot11AssoResp, Dot11ReassoReq, Dot11ReassoResp, Dot11Disas
from scapy.layers.dot11 import Dot11QoS, Dot11CCMP, Dot11WEP

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


class CaptureQualityAnalyzer(BaseAnalyzer):
    """
    Comprehensive capture quality and validation analyzer.
    
    This analyzer assesses the quality and completeness of wireless packet captures
    to ensure reliable analysis results. It validates:
    - Monitor mode operation
    - Timing accuracy and consistency
    - FCS inclusion and validation
    - Hardware/driver capabilities
    - Capture setup and configuration
    - RadioTap header quality
    """
    
    def __init__(self):
        super().__init__(
            name="Capture Quality Validator",
            category=AnalysisCategory.CAPTURE_QUALITY,
            version="1.0"
        )
        self.description = "Validates monitor mode, timing, FCS inclusion, and capture integrity"
        self.analysis_order = 50  # Run early to validate capture quality
        
        # Quality thresholds
        self.min_management_frames_ratio = 0.05  # 5% minimum for monitor mode
        self.max_timing_jitter_ms = 100  # Maximum acceptable timing jitter
        self.min_fcs_inclusion_ratio = 0.8  # 80% minimum FCS inclusion
        self.max_duplicate_ratio = 0.05  # 5% maximum duplicate frames
        self.min_capture_duration = 1.0  # 1 second minimum
        
        # Reset analysis state
        self.reset_analysis_state()
        
    def reset_analysis_state(self):
        """Reset analysis state for new capture."""
        # Frame type counters
        self.frame_type_stats = Counter()
        self.frame_subtype_stats = defaultdict(Counter)
        
        # Timing analysis
        self.timestamps = []
        self.timestamp_intervals = []
        self.timestamp_quality = []
        
        # FCS and validation
        self.fcs_present_count = 0
        self.fcs_valid_count = 0
        self.fcs_invalid_count = 0
        self.total_packets_with_fcs = 0
        
        # RadioTap analysis
        self.radiotap_present_count = 0
        self.radiotap_features = Counter()
        self.antenna_info = Counter()
        
        # Hardware/driver indicators
        self.driver_indicators = set()
        self.hardware_indicators = set()
        self.capture_interfaces = set()
        
        # Duplicate detection
        self.packet_hashes = set()
        self.duplicate_count = 0
        
        # Monitor mode indicators
        self.management_frame_count = 0
        self.monitor_mode_indicators = []
        
        # Capture metadata
        self.first_timestamp = None
        self.last_timestamp = None
        self.capture_duration = 0
        self.total_packets = 0
        
    def pre_analysis_setup(self, context: AnalysisContext) -> None:
        """Setup before analysis begins."""
        self.reset_analysis_state()
        self.logger.info(f"Starting {self.name} analysis")
        
    def is_applicable(self, packet: Packet) -> bool:
        """All packets are applicable for quality analysis."""
        return True
        
    def analyze(self, packets: List[Packet], context: AnalysisContext) -> List[Finding]:
        """
        Analyze packets for capture quality and integrity.
        
        Args:
            packets: List of packets to analyze
            context: Analysis context
            
        Returns:
            List of findings
        """
        findings = []
        
        if not packets:
            findings.append(self.create_finding(
                severity=Severity.ERROR,
                title="Empty Capture",
                description="No packets found in capture file",
                recommendations=["Verify capture file is valid and not corrupted",
                              "Check capture tool configuration",
                              "Ensure network interface was properly configured"]
            ))
            return findings
            
        self.logger.info(f"Analyzing capture quality of {len(packets)} packets")
        self.total_packets = len(packets)
        
        # Collect quality metrics
        self._collect_quality_metrics(packets)
        
        # Perform quality analysis
        findings.extend(self._analyze_monitor_mode())
        findings.extend(self._analyze_timing_quality())
        findings.extend(self._analyze_fcs_inclusion())
        findings.extend(self._analyze_radiotap_quality())
        findings.extend(self._analyze_capture_completeness())
        findings.extend(self._analyze_hardware_capabilities())
        findings.extend(self._analyze_duplicate_frames())
        findings.extend(self._analyze_capture_setup())
        
        self.logger.info(f"Generated {len(findings)} capture quality findings")
        return findings
        
    def _collect_quality_metrics(self, packets: List[Packet]) -> None:
        """Collect quality metrics from all packets."""
        packet_signatures = []
        
        for i, packet in enumerate(packets):
            try:
                # Extract timestamp
                timestamp = self._extract_timestamp(packet)
                if timestamp > 0:
                    self.timestamps.append(timestamp)
                    if self.first_timestamp is None:
                        self.first_timestamp = timestamp
                    self.last_timestamp = timestamp
                    
                # Check for RadioTap header
                self._analyze_radiotap_header(packet)
                
                # Analyze 802.11 frame if present
                if packet_has_layer(packet, Dot11):
                    self._analyze_dot11_frame(packet, i)
                    
                # Check for duplicates (simple hash-based)
                packet_sig = self._create_packet_signature(packet)
                if packet_sig in packet_signatures:
                    self.duplicate_count += 1
                else:
                    packet_signatures.append(packet_sig)
                    
                # Collect hardware/driver indicators
                self._collect_hardware_indicators(packet)
                
            except Exception as e:
                self.logger.debug(f"Error processing packet {i}: {e}")
                continue
                
        # Calculate derived metrics
        if len(self.timestamps) >= 2:
            self.timestamps.sort()
            self.capture_duration = self.last_timestamp - self.first_timestamp
            
            # Calculate timing intervals
            for i in range(1, len(self.timestamps)):
                interval = self.timestamps[i] - self.timestamps[i-1]
                self.timestamp_intervals.append(interval)
                
    def _analyze_radiotap_header(self, packet: Packet) -> None:
        """Analyze RadioTap header presence and quality."""
        # Check if packet has RadioTap-like attributes
        radiotap_fields = [
            'dBm_AntSignal', 'dBm_AntNoise', 'Channel', 'Rate', 'Antenna',
            'present', 'len', 'datarate', 'MCS_index', 'VHT_NSS'
        ]
        
        has_radiotap = False
        for field in radiotap_fields:
            if hasattr(packet, field):
                has_radiotap = True
                self.radiotap_features[field] += 1
                
        if has_radiotap:
            self.radiotap_present_count += 1
            
        # Collect antenna information
        if hasattr(packet, 'Antenna'):
            try:
                antenna_id = int(packet.Antenna)
                self.antenna_info[antenna_id] += 1
            except (ValueError, TypeError):
                pass
                
    def _analyze_dot11_frame(self, packet: Packet, packet_index: int) -> None:
        """Analyze 802.11 frame for quality indicators."""
        dot11 = get_packet_layer(packet, "Dot11")
        
        # Count frame types
        frame_type = dot11.type
        frame_subtype = dot11.subtype
        
        self.frame_type_stats[frame_type] += 1
        self.frame_subtype_stats[frame_type][frame_subtype] += 1
        
        # Count management frames for monitor mode detection
        if frame_type == 0:  # Management frame
            self.management_frame_count += 1
            
        # Check for FCS
        self._check_fcs_presence(packet)
        
        # Monitor mode indicators
        self._check_monitor_mode_indicators(packet)
        
    def _check_fcs_presence(self, packet: Packet) -> None:
        """Check for FCS presence and validity."""
        # Look for FCS-related attributes
        has_fcs = False
        fcs_valid = False
        
        # Common FCS indicators in different capture formats
        fcs_fields = ['fcs', 'fcs_good', 'fcs_bad', 'FCS']
        
        for field in fcs_fields:
            if hasattr(packet, field):
                has_fcs = True
                self.total_packets_with_fcs += 1
                break
                
        if has_fcs:
            self.fcs_present_count += 1
            
            # Check FCS validity if information is available
            if hasattr(packet, 'fcs_good') and packet.fcs_good:
                fcs_valid = True
                self.fcs_valid_count += 1
            elif hasattr(packet, 'fcs_bad') and packet.fcs_bad:
                self.fcs_invalid_count += 1
            elif hasattr(packet, 'fcs'):
                # FCS present but validity unknown
                self.fcs_valid_count += 1  # Assume valid if present
                
    def _check_monitor_mode_indicators(self, packet: Packet) -> None:
        """Check for indicators that suggest monitor mode operation."""
        if not packet_has_layer(packet, Dot11):
            return
            
        dot11 = get_packet_layer(packet, "Dot11")
        
        # Strong monitor mode indicators
        if dot11.type == 0:  # Management frames
            if dot11.subtype == 8:  # Beacon
                self.monitor_mode_indicators.append("beacon_frames_present")
            elif dot11.subtype == 4:  # Probe request
                self.monitor_mode_indicators.append("probe_requests_present")
            elif dot11.subtype == 11:  # Authentication
                self.monitor_mode_indicators.append("auth_frames_present")
            elif dot11.subtype == 12:  # Deauthentication
                self.monitor_mode_indicators.append("deauth_frames_present")
                
        # Check for promiscuous capture indicators
        if hasattr(dot11, 'addr1') and str(dot11.addr1).lower() != 'ff:ff:ff:ff:ff:ff':
            # Non-broadcast frames captured suggest monitor mode
            self.monitor_mode_indicators.append("unicast_frames_captured")
            
    def _collect_hardware_indicators(self, packet: Packet) -> None:
        """Collect hardware and driver capability indicators."""
        # Check for specific driver indicators in RadioTap
        if hasattr(packet, 'present'):
            self.driver_indicators.add("radiotap_present")
            
        # Look for specific hardware capabilities
        if hasattr(packet, 'MCS_index'):
            self.hardware_indicators.add("802.11n_capable")
        if hasattr(packet, 'VHT_NSS'):
            self.hardware_indicators.add("802.11ac_capable")
        if hasattr(packet, 'HE_MU'):
            self.hardware_indicators.add("802.11ax_capable")
            
        # Interface indicators (if available in metadata)
        # This would typically come from capture file metadata
        
    def _analyze_monitor_mode(self) -> List[Finding]:
        """Analyze monitor mode detection and quality."""
        findings = []
        
        if self.total_packets == 0:
            return findings
            
        management_ratio = self.management_frame_count / self.total_packets
        
        # Check if monitor mode is properly configured
        if management_ratio < self.min_management_frames_ratio:
            findings.append(self.create_finding(
                severity=Severity.CRITICAL,
                title="Monitor Mode Not Detected",
                description=f"Only {management_ratio:.1%} management frames detected, suggesting non-monitor mode capture",
                details={
                    "management_frame_ratio": management_ratio,
                    "management_frame_count": self.management_frame_count,
                    "total_packets": self.total_packets,
                    "minimum_expected_ratio": self.min_management_frames_ratio,
                    "frame_type_distribution": dict(self.frame_type_stats)
                },
                recommendations=[
                    "Verify interface is in monitor mode during capture",
                    "Check if capture tool supports monitor mode",
                    "Ensure proper permissions for monitor mode operation",
                    "Verify wireless adapter supports monitor mode",
                    "Consider using airmon-ng or similar tools to enable monitor mode"
                ],
                confidence=0.9
            ))
        elif management_ratio < 0.15:  # Less than 15% but above minimum
            findings.append(self.create_finding(
                severity=Severity.WARNING,
                title="Low Management Frame Ratio",
                description=f"{management_ratio:.1%} management frames may indicate limited monitor mode capture",
                details={
                    "management_frame_ratio": management_ratio,
                    "management_frame_count": self.management_frame_count,
                    "monitor_mode_indicators": list(set(self.monitor_mode_indicators))
                },
                recommendations=[
                    "Verify monitor mode is fully operational",
                    "Check for hardware/driver limitations",
                    "Consider capture duration and network activity"
                ],
                confidence=0.7
            ))
            
        # Positive confirmation of monitor mode
        unique_indicators = set(self.monitor_mode_indicators)
        if len(unique_indicators) >= 3:
            findings.append(self.create_finding(
                severity=Severity.INFO,
                title="Monitor Mode Confirmed",
                description=f"Strong monitor mode indicators detected: {len(unique_indicators)} types",
                details={
                    "monitor_mode_indicators": list(unique_indicators),
                    "management_frame_ratio": management_ratio,
                    "confidence_level": "high"
                },
                recommendations=[
                    "Monitor mode appears to be working correctly",
                    "Capture quality is suitable for wireless analysis"
                ],
                confidence=0.9
            ))
            
        return findings
        
    def _analyze_timing_quality(self) -> List[Finding]:
        """Analyze timing accuracy and consistency."""
        findings = []
        
        if len(self.timestamps) < 10:
            findings.append(self.create_finding(
                severity=Severity.WARNING,
                title="Insufficient Timing Data",
                description=f"Only {len(self.timestamps)} timestamped packets available for timing analysis",
                recommendations=["Verify capture tool preserves packet timestamps",
                              "Check for capture tool configuration issues"]
            ))
            return findings
            
        if not self.timestamp_intervals:
            return findings
            
        # Analyze timing intervals
        avg_interval = statistics.mean(self.timestamp_intervals)
        interval_std = statistics.stdev(self.timestamp_intervals) if len(self.timestamp_intervals) > 1 else 0
        min_interval = min(self.timestamp_intervals)
        max_interval = max(self.timestamp_intervals)
        
        # Check for timing issues
        if max_interval > 10.0:  # Gaps > 10 seconds
            findings.append(self.create_finding(
                severity=Severity.WARNING,
                title="Large Timing Gaps Detected",
                description=f"Maximum interval between packets is {max_interval:.2f} seconds",
                details={
                    "max_interval_seconds": max_interval,
                    "average_interval_seconds": avg_interval,
                    "interval_std_dev": interval_std,
                    "total_intervals": len(self.timestamp_intervals)
                },
                recommendations=[
                    "Check for capture interruptions or pauses",
                    "Verify consistent capture operation",
                    "Consider impact on time-based analysis"
                ],
                confidence=0.8
            ))
            
        # Check for microsecond precision
        microsecond_timestamps = [t for t in self.timestamps if (t * 1000000) % 1000 != 0]
        if len(microsecond_timestamps) / len(self.timestamps) > 0.8:
            findings.append(self.create_finding(
                severity=Severity.INFO,
                title="High-Precision Timestamps Detected",
                description=f"{len(microsecond_timestamps)/len(self.timestamps):.1%} of timestamps have microsecond precision",
                details={
                    "precision_ratio": len(microsecond_timestamps)/len(self.timestamps),
                    "total_timestamps": len(self.timestamps)
                },
                recommendations=[
                    "High-precision timestamps improve analysis accuracy",
                    "Hardware timestamping may be available"
                ],
                confidence=0.8
            ))
            
        # Check timing consistency
        if interval_std > avg_interval * 2 and avg_interval > 0:
            findings.append(self.create_finding(
                severity=Severity.WARNING,
                title="Inconsistent Packet Timing",
                description=f"High timing variance detected (σ={interval_std:.3f}s, avg={avg_interval:.3f}s)",
                details={
                    "timing_variance": interval_std,
                    "average_interval": avg_interval,
                    "variance_ratio": interval_std / avg_interval if avg_interval > 0 else 0
                },
                recommendations=[
                    "Check for system load during capture",
                    "Verify capture buffer settings",
                    "Consider dedicated capture hardware"
                ],
                confidence=0.6
            ))
            
        return findings
        
    def _analyze_fcs_inclusion(self) -> List[Finding]:
        """Analyze FCS inclusion and validation."""
        findings = []
        
        if self.total_packets == 0:
            return findings
            
        fcs_ratio = self.fcs_present_count / self.total_packets
        
        if fcs_ratio < self.min_fcs_inclusion_ratio:
            findings.append(self.create_finding(
                severity=Severity.WARNING,
                title="Low FCS Inclusion Rate",
                description=f"Only {fcs_ratio:.1%} of packets include FCS information",
                details={
                    "fcs_inclusion_ratio": fcs_ratio,
                    "fcs_present_count": self.fcs_present_count,
                    "total_packets": self.total_packets,
                    "minimum_expected_ratio": self.min_fcs_inclusion_ratio
                },
                recommendations=[
                    "Enable FCS inclusion in capture tool settings",
                    "Check wireless adapter FCS support",
                    "FCS is important for frame integrity validation",
                    "Consider hardware with better FCS support"
                ],
                confidence=0.8
            ))
        elif fcs_ratio > 0.9:
            # High FCS inclusion is good
            findings.append(self.create_finding(
                severity=Severity.INFO,
                title="High FCS Inclusion Rate",
                description=f"{fcs_ratio:.1%} of packets include FCS information",
                details={
                    "fcs_inclusion_ratio": fcs_ratio,
                    "fcs_valid_count": self.fcs_valid_count,
                    "fcs_invalid_count": self.fcs_invalid_count
                },
                recommendations=[
                    "Excellent FCS inclusion rate for frame integrity analysis",
                    "FCS validation can help identify corrupted frames"
                ],
                confidence=0.9
            ))
            
        # Analyze FCS validity if available
        if self.fcs_valid_count + self.fcs_invalid_count > 0:
            error_rate = self.fcs_invalid_count / (self.fcs_valid_count + self.fcs_invalid_count)
            
            if error_rate > 0.05:  # > 5% FCS errors
                findings.append(self.create_finding(
                    severity=Severity.WARNING,
                    title="High FCS Error Rate",
                    description=f"{error_rate:.1%} of frames have FCS errors",
                    details={
                        "fcs_error_rate": error_rate,
                        "fcs_valid_count": self.fcs_valid_count,
                        "fcs_invalid_count": self.fcs_invalid_count
                    },
                    recommendations=[
                        "High FCS error rate may indicate RF issues",
                        "Check for interference or poor signal quality",
                        "Consider capture environment and positioning"
                    ],
                    confidence=0.8
                ))
                
        return findings
        
    def _analyze_radiotap_quality(self) -> List[Finding]:
        """Analyze RadioTap header presence and quality."""
        findings = []
        
        if self.total_packets == 0:
            return findings
            
        radiotap_ratio = self.radiotap_present_count / self.total_packets
        
        if radiotap_ratio < 0.1:  # Less than 10% have RadioTap
            findings.append(self.create_finding(
                severity=Severity.WARNING,
                title="Limited RadioTap Information",
                description=f"Only {radiotap_ratio:.1%} of packets contain RadioTap metadata",
                details={
                    "radiotap_ratio": radiotap_ratio,
                    "radiotap_present_count": self.radiotap_present_count,
                    "available_features": dict(self.radiotap_features)
                },
                recommendations=[
                    "RadioTap headers provide valuable RF metadata",
                    "Check capture tool RadioTap support",
                    "Verify wireless driver RadioTap capabilities",
                    "Some analysis features may be limited without RadioTap"
                ],
                confidence=0.7
            ))
        elif radiotap_ratio > 0.8:
            findings.append(self.create_finding(
                severity=Severity.INFO,
                title="Rich RadioTap Metadata Available",
                description=f"{radiotap_ratio:.1%} of packets contain RadioTap information",
                details={
                    "radiotap_ratio": radiotap_ratio,
                    "available_features": dict(self.radiotap_features),
                    "antenna_diversity": len(self.antenna_info)
                },
                recommendations=[
                    "Excellent RadioTap coverage enables advanced RF analysis",
                    "Signal strength, channel, and rate information available"
                ],
                confidence=0.9
            ))
            
        return findings
        
    def _analyze_capture_completeness(self) -> List[Finding]:
        """Analyze capture completeness and duration."""
        findings = []
        
        if self.capture_duration < self.min_capture_duration:
            findings.append(self.create_finding(
                severity=Severity.WARNING,
                title="Very Short Capture Duration",
                description=f"Capture duration is only {self.capture_duration:.2f} seconds",
                details={
                    "capture_duration_seconds": self.capture_duration,
                    "minimum_recommended": self.min_capture_duration,
                    "total_packets": self.total_packets
                },
                recommendations=[
                    "Short captures may not represent typical network behavior",
                    "Consider longer capture duration for comprehensive analysis",
                    "Some analysis patterns require extended observation periods"
                ],
                confidence=0.8
            ))
            
        # Check packet rate
        if self.capture_duration > 0:
            packet_rate = self.total_packets / self.capture_duration
            
            if packet_rate < 1:  # Less than 1 packet per second
                findings.append(self.create_finding(
                    severity=Severity.WARNING,
                    title="Low Packet Capture Rate",
                    description=f"Average packet rate is {packet_rate:.2f} packets/second",
                    details={
                        "packet_rate_per_second": packet_rate,
                        "total_packets": self.total_packets,
                        "capture_duration": self.capture_duration
                    },
                    recommendations=[
                        "Low packet rate may indicate inactive network",
                        "Verify capture location and timing",
                        "Check for capture filtering that might limit packets"
                    ],
                    confidence=0.6
                ))
            elif packet_rate > 1000:  # Very high rate
                findings.append(self.create_finding(
                    severity=Severity.INFO,
                    title="High Packet Capture Rate",
                    description=f"High packet rate detected: {packet_rate:.0f} packets/second",
                    details={
                        "packet_rate_per_second": packet_rate,
                        "total_packets": self.total_packets
                    },
                    recommendations=[
                        "High packet rate indicates active network environment",
                        "Ensure capture system can handle sustained high rates",
                        "Monitor for packet drops during capture"
                    ],
                    confidence=0.8
                ))
                
        return findings
        
    def _analyze_hardware_capabilities(self) -> List[Finding]:
        """Analyze hardware and driver capabilities."""
        findings = []
        
        if self.hardware_indicators:
            findings.append(self.create_finding(
                severity=Severity.INFO,
                title="Advanced Hardware Capabilities Detected",
                description=f"Hardware supports: {', '.join(self.hardware_indicators)}",
                details={
                    "hardware_capabilities": list(self.hardware_indicators),
                    "driver_indicators": list(self.driver_indicators)
                },
                recommendations=[
                    "Advanced hardware enables comprehensive analysis",
                    "Modern wireless standards support available"
                ],
                confidence=0.8
            ))
            
        # Check for antenna diversity
        if len(self.antenna_info) > 1:
            findings.append(self.create_finding(
                severity=Severity.INFO,
                title="Multiple Antenna Support Detected",
                description=f"Detected {len(self.antenna_info)} different antennas",
                details={
                    "antenna_count": len(self.antenna_info),
                    "antenna_usage": dict(self.antenna_info)
                },
                recommendations=[
                    "Multiple antennas can improve signal diversity",
                    "Antenna diversity may enhance capture quality",
                    "MIMO analysis capabilities available"
                ],
                confidence=0.8
            ))
            
        return findings
        
    def _analyze_duplicate_frames(self) -> List[Finding]:
        """Analyze duplicate frame detection."""
        findings = []
        
        if self.total_packets == 0:
            return findings
            
        duplicate_ratio = self.duplicate_count / self.total_packets
        
        if duplicate_ratio > self.max_duplicate_ratio:
            findings.append(self.create_finding(
                severity=Severity.WARNING,
                title="High Duplicate Frame Rate",
                description=f"{duplicate_ratio:.1%} of frames appear to be duplicates",
                details={
                    "duplicate_ratio": duplicate_ratio,
                    "duplicate_count": self.duplicate_count,
                    "total_packets": self.total_packets,
                    "max_expected_ratio": self.max_duplicate_ratio
                },
                recommendations=[
                    "High duplicate rate may indicate capture issues",
                    "Check for multiple capture interfaces",
                    "Verify capture tool configuration",
                    "Consider deduplication during analysis"
                ],
                confidence=0.7
            ))
            
        return findings
        
    def _analyze_capture_setup(self) -> List[Finding]:
        """Analyze overall capture setup and configuration."""
        findings = []
        
        # Summary finding about capture quality
        quality_score = self._calculate_quality_score()
        
        if quality_score < 0.6:
            findings.append(self.create_finding(
                severity=Severity.CRITICAL,
                title="Poor Capture Quality Detected",
                description=f"Overall capture quality score: {quality_score:.2f}/1.00",
                details=self._get_quality_summary(),
                recommendations=[
                    "Review and improve capture setup",
                    "Check monitor mode configuration",
                    "Verify hardware and driver capabilities",
                    "Consider professional wireless capture tools"
                ],
                confidence=0.9
            ))
        elif quality_score < 0.8:
            findings.append(self.create_finding(
                severity=Severity.WARNING,
                title="Suboptimal Capture Quality",
                description=f"Capture quality score: {quality_score:.2f}/1.00",
                details=self._get_quality_summary(),
                recommendations=[
                    "Some capture quality issues detected",
                    "Review specific findings for improvement areas",
                    "Consider optimizing capture configuration"
                ],
                confidence=0.8
            ))
        else:
            findings.append(self.create_finding(
                severity=Severity.INFO,
                title="Good Capture Quality",
                description=f"High capture quality score: {quality_score:.2f}/1.00",
                details=self._get_quality_summary(),
                recommendations=[
                    "Capture quality is suitable for comprehensive analysis",
                    "All major quality indicators are acceptable"
                ],
                confidence=0.9
            ))
            
        return findings
        
    def _calculate_quality_score(self) -> float:
        """Calculate overall capture quality score (0.0 to 1.0)."""
        score = 0.0
        factors = 0
        
        # Monitor mode factor
        if self.total_packets > 0:
            management_ratio = self.management_frame_count / self.total_packets
            monitor_score = min(1.0, management_ratio / self.min_management_frames_ratio)
            score += monitor_score
            factors += 1
            
        # FCS inclusion factor
        if self.total_packets > 0:
            fcs_ratio = self.fcs_present_count / self.total_packets
            fcs_score = min(1.0, fcs_ratio / self.min_fcs_inclusion_ratio)
            score += fcs_score
            factors += 1
            
        # RadioTap presence factor
        if self.total_packets > 0:
            radiotap_ratio = self.radiotap_present_count / self.total_packets
            radiotap_score = min(1.0, radiotap_ratio)
            score += radiotap_score * 0.5  # Lower weight
            factors += 0.5
            
        # Duplicate factor (inverse - fewer duplicates is better)
        if self.total_packets > 0:
            duplicate_ratio = self.duplicate_count / self.total_packets
            duplicate_score = 1.0 - min(1.0, duplicate_ratio / self.max_duplicate_ratio)
            score += duplicate_score
            factors += 1
            
        # Timing quality factor
        if len(self.timestamp_intervals) > 0:
            # Simple timing quality based on consistency
            timing_score = 1.0  # Assume good by default
            score += timing_score * 0.5  # Lower weight
            factors += 0.5
            
        return score / factors if factors > 0 else 0.0
        
    def _get_quality_summary(self) -> Dict[str, Any]:
        """Get comprehensive quality summary."""
        return {
            "total_packets": self.total_packets,
            "capture_duration_seconds": self.capture_duration,
            "management_frame_ratio": self.management_frame_count / max(self.total_packets, 1),
            "fcs_inclusion_ratio": self.fcs_present_count / max(self.total_packets, 1),
            "radiotap_presence_ratio": self.radiotap_present_count / max(self.total_packets, 1),
            "duplicate_frame_ratio": self.duplicate_count / max(self.total_packets, 1),
            "frame_type_distribution": dict(self.frame_type_stats),
            "hardware_capabilities": list(self.hardware_indicators),
            "timing_intervals_count": len(self.timestamp_intervals),
            "antenna_diversity": len(self.antenna_info)
        }
        
    def _create_packet_signature(self, packet: Packet) -> str:
        """Create a simple signature for duplicate detection."""
        try:
            if packet_has_layer(packet, Dot11):
                dot11 = get_packet_layer(packet, "Dot11")
                # Simple signature based on key fields
                sig_parts = [
                    str(dot11.type),
                    str(dot11.subtype),
                    str(dot11.addr1) if hasattr(dot11, 'addr1') else "",
                    str(dot11.addr2) if hasattr(dot11, 'addr2') else "",
                    str(len(packet))
                ]
                return "|".join(sig_parts)
        except:
            pass
        return str(len(packet))
        
    def _extract_timestamp(self, packet: Packet) -> float:
        """Extract timestamp from packet."""
        if hasattr(packet, 'time'):
            try:
                time_val = get_timestamp(packet)
                if hasattr(time_val, '__float__'):
                    return float(time_val)
                elif hasattr(time_val, 'val'):
                    return float(time_val.val)
                else:
                    return float(time_val)
            except (ValueError, TypeError, AttributeError):
                return 0.0
        return 0.0
        
    def get_display_filters(self) -> List[str]:
        """Get Wireshark display filters for capture quality analysis."""
        return [
            "radiotap",
            "wlan.fc.type == 0",  # Management frames
            "wlan.fcs_good",
            "wlan.fcs_bad", 
            "frame.time_delta",
            "wlan_radio"
        ]
        
    def get_dependencies(self) -> List[str]:
        """Get analyzer dependencies."""
        return []  # No dependencies - should run first
        
    def post_analysis_cleanup(self, context: AnalysisContext) -> None:
        """Cleanup after analysis."""
        self.logger.info(f"Analyzed {self.total_packets} packets over {self.capture_duration:.2f} seconds")
        self.logger.info(f"Management frames: {self.management_frame_count} ({self.management_frame_count/max(self.total_packets,1):.1%})")
        self.logger.info(f"RadioTap present: {self.radiotap_present_count} ({self.radiotap_present_count/max(self.total_packets,1):.1%})")
        self.logger.info(f"FCS included: {self.fcs_present_count} ({self.fcs_present_count/max(self.total_packets,1):.1%})")
        
        # Store summary in context for other analyzers
        context.security_context['capture_quality'] = self._get_quality_summary()