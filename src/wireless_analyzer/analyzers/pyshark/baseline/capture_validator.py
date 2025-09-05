"""
PyShark-based capture quality analysis and validation for wireless PCAP data.

This analyzer validates the quality and completeness of wireless packet captures using
native PyShark packet parsing:
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


class PySharkCaptureQualityAnalyzer(BasePySharkAnalyzer):
    """
    PyShark-based comprehensive capture quality and validation analyzer.
    
    This analyzer assesses the quality and completeness of wireless packet captures
    using native PyShark packet parsing to ensure reliable analysis results. It validates:
    - Monitor mode operation
    - Timing accuracy and consistency
    - FCS inclusion and validation
    - Hardware/driver capabilities
    - Capture setup and configuration
    - RadioTap header presence and quality
    """
    
    def __init__(self):
        super().__init__(
            name="PyShark Capture Quality Validator",
            category=AnalysisCategory.CAPTURE_QUALITY,
            version="1.0"
        )
        self.description = "Validates monitor mode, timing, FCS inclusion, and capture integrity using PyShark"
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
        
    def is_applicable(self, packet: PySharkPacket) -> bool:
        """All packets are applicable for quality analysis."""
        return PYSHARK_AVAILABLE and packet is not None
        
    def analyze(self, packets: List[PySharkPacket], context: AnalysisContext) -> List[Finding]:
        """
        Analyze packets for capture quality and integrity using PyShark.
        
        Args:
            packets: List of packets to analyze
            context: Analysis context
            
        Returns:
            List of findings
        """
        if not PYSHARK_AVAILABLE:
            self.logger.warning("PyShark is not available, skipping analysis")
            return []
            
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
            
        self.logger.info(f"Analyzing capture quality of {len(packets)} packets using PyShark")
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
        
    def _collect_quality_metrics(self, packets: List[PySharkPacket]) -> None:
        """Collect quality metrics from all packets using PyShark."""
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
                if hasattr(packet, 'wlan') and packet.wlan:
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
                
    def _analyze_radiotap_header(self, packet: PySharkPacket) -> None:
        """Analyze RadioTap header presence and quality using PyShark."""
        if hasattr(packet, 'radiotap') and packet.radiotap:
            self.radiotap_present_count += 1
            radiotap = packet.radiotap
            
            # Check available RadioTap fields
            radiotap_fields = [
                'dbm_antsignal', 'dbm_antnoise', 'channel', 'datarate', 'antenna',
                'present', 'length', 'mcs_index', 'vht_nss'
            ]
            
            for field in radiotap_fields:
                if hasattr(radiotap, field):
                    self.radiotap_features[field] += 1
                    
            # Collect antenna information
            if hasattr(radiotap, 'antenna'):
                try:
                    antenna_id = int(radiotap.antenna)
                    self.antenna_info[antenna_id] += 1
                except (ValueError, TypeError):
                    pass
                
    def _analyze_dot11_frame(self, packet: PySharkPacket, packet_index: int) -> None:
        """Analyze 802.11 frame for quality indicators using PyShark."""
        if not hasattr(packet, 'wlan') or not packet.wlan:
            return
            
        wlan = packet.wlan
        
        # Count frame types
        if hasattr(wlan, 'fc_type'):
            frame_type = int(wlan.fc_type)
            self.frame_type_stats[frame_type] += 1
            
            if hasattr(wlan, 'fc_subtype'):
                frame_subtype = int(wlan.fc_subtype)
                self.frame_subtype_stats[frame_type][frame_subtype] += 1
            
            # Count management frames for monitor mode detection
            if frame_type == 0:  # Management frame
                self.management_frame_count += 1
            
        # Check for FCS
        self._check_fcs_presence(packet)
        
        # Monitor mode indicators
        self._check_monitor_mode_indicators(packet)
        
    def _check_fcs_presence(self, packet: PySharkPacket) -> None:
        """Check for FCS presence and validity using PyShark."""
        # Look for FCS-related attributes in PyShark packet
        has_fcs = False
        fcs_valid = False
        
        # Check for FCS fields in WLAN layer
        if hasattr(packet, 'wlan') and packet.wlan:
            wlan = packet.wlan
            fcs_fields = ['fcs', 'fcs_good', 'fcs_bad']
            
            for field in fcs_fields:
                if hasattr(wlan, field):
                    has_fcs = True
                    self.total_packets_with_fcs += 1
                    break
                    
        if has_fcs:
            self.fcs_present_count += 1
            
            # Check FCS validity if information is available
            if hasattr(packet.wlan, 'fcs_good') and packet.wlan.fcs_good == '1':
                self.fcs_valid_count += 1
            elif hasattr(packet.wlan, 'fcs_bad') and packet.wlan.fcs_bad == '1':
                self.fcs_invalid_count += 1
            elif hasattr(packet.wlan, 'fcs'):
                # FCS present but validity unknown
                self.fcs_valid_count += 1  # Assume valid if present
                
    def _check_monitor_mode_indicators(self, packet: PySharkPacket) -> None:
        """Check for indicators that suggest monitor mode operation using PyShark."""
        if not hasattr(packet, 'wlan') or not packet.wlan:
            return
            
        wlan = packet.wlan
        
        # Strong monitor mode indicators
        if hasattr(wlan, 'fc_type') and hasattr(wlan, 'fc_subtype'):
            frame_type = int(wlan.fc_type)
            frame_subtype = int(wlan.fc_subtype)
            
            if frame_type == 0:  # Management frames
                if frame_subtype == 8:  # Beacon
                    self.monitor_mode_indicators.append("beacon_frames_present")
                elif frame_subtype == 4:  # Probe request
                    self.monitor_mode_indicators.append("probe_requests_present")
                elif frame_subtype == 11:  # Authentication
                    self.monitor_mode_indicators.append("auth_frames_present")
                elif frame_subtype == 12:  # Deauthentication
                    self.monitor_mode_indicators.append("deauth_frames_present")
                    
        # Check for promiscuous capture indicators
        if hasattr(wlan, 'da') and str(wlan.da).lower() != 'ff:ff:ff:ff:ff:ff':
            # Non-broadcast frames captured suggest monitor mode
            self.monitor_mode_indicators.append("unicast_frames_captured")
            
    def _collect_hardware_indicators(self, packet: PySharkPacket) -> None:
        """Collect hardware and driver capability indicators using PyShark."""
        # Check for RadioTap indicators
        if hasattr(packet, 'radiotap') and packet.radiotap:
            self.driver_indicators.add("radiotap_present")
            radiotap = packet.radiotap
            
            # Look for specific hardware capabilities
            if hasattr(radiotap, 'mcs_index'):
                self.hardware_indicators.add("802.11n_capable")
            if hasattr(radiotap, 'vht_nss'):
                self.hardware_indicators.add("802.11ac_capable")
            if hasattr(radiotap, 'he_mu'):
                self.hardware_indicators.add("802.11ax_capable")
            
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
                title="Monitor Mode Not Detected (PyShark)",
                description=f"Only {management_ratio:.1%} management frames detected, suggesting non-monitor mode capture",
                details={
                    "management_frame_ratio": management_ratio,
                    "management_frame_count": self.management_frame_count,
                    "total_packets": self.total_packets,
                    "minimum_expected_ratio": self.min_management_frames_ratio,
                    "frame_type_distribution": dict(self.frame_type_stats),
                    "parser": "pyshark"
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
                title="Low Management Frame Ratio (PyShark)",
                description=f"{management_ratio:.1%} management frames may indicate limited monitor mode capture",
                details={
                    "management_frame_ratio": management_ratio,
                    "management_frame_count": self.management_frame_count,
                    "monitor_mode_indicators": list(set(self.monitor_mode_indicators)),
                    "parser": "pyshark"
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
                title="Monitor Mode Confirmed (PyShark)",
                description=f"Strong monitor mode indicators detected: {len(unique_indicators)} types",
                details={
                    "monitor_mode_indicators": list(unique_indicators),
                    "management_frame_ratio": management_ratio,
                    "confidence_level": "high",
                    "parser": "pyshark"
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
                title="Insufficient Timing Data (PyShark)",
                description=f"Only {len(self.timestamps)} timestamped packets available for timing analysis",
                details={"parser": "pyshark"},
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
                title="Large Timing Gaps Detected (PyShark)",
                description=f"Maximum interval between packets is {max_interval:.2f} seconds",
                details={
                    "max_interval_seconds": max_interval,
                    "average_interval_seconds": avg_interval,
                    "interval_std_dev": interval_std,
                    "total_intervals": len(self.timestamp_intervals),
                    "parser": "pyshark"
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
                title="High-Precision Timestamps Detected (PyShark)",
                description=f"{len(microsecond_timestamps)/len(self.timestamps):.1%} of timestamps have microsecond precision",
                details={
                    "precision_ratio": len(microsecond_timestamps)/len(self.timestamps),
                    "total_timestamps": len(self.timestamps),
                    "parser": "pyshark"
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
                title="Inconsistent Packet Timing (PyShark)",
                description=f"High timing variance detected (σ={interval_std:.3f}s, avg={avg_interval:.3f}s)",
                details={
                    "timing_variance": interval_std,
                    "average_interval": avg_interval,
                    "variance_ratio": interval_std / avg_interval if avg_interval > 0 else 0,
                    "parser": "pyshark"
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
                title="Low FCS Inclusion Rate (PyShark)",
                description=f"Only {fcs_ratio:.1%} of packets include FCS information",
                details={
                    "fcs_inclusion_ratio": fcs_ratio,
                    "fcs_present_count": self.fcs_present_count,
                    "total_packets": self.total_packets,
                    "minimum_expected_ratio": self.min_fcs_inclusion_ratio,
                    "parser": "pyshark"
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
                title="High FCS Inclusion Rate (PyShark)",
                description=f"{fcs_ratio:.1%} of packets include FCS information",
                details={
                    "fcs_inclusion_ratio": fcs_ratio,
                    "fcs_valid_count": self.fcs_valid_count,
                    "fcs_invalid_count": self.fcs_invalid_count,
                    "parser": "pyshark"
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
                    title="High FCS Error Rate (PyShark)",
                    description=f"{error_rate:.1%} of frames have FCS errors",
                    details={
                        "fcs_error_rate": error_rate,
                        "fcs_valid_count": self.fcs_valid_count,
                        "fcs_invalid_count": self.fcs_invalid_count,
                        "parser": "pyshark"
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
                title="Limited RadioTap Information (PyShark)",
                description=f"Only {radiotap_ratio:.1%} of packets contain RadioTap metadata",
                details={
                    "radiotap_ratio": radiotap_ratio,
                    "radiotap_present_count": self.radiotap_present_count,
                    "available_features": dict(self.radiotap_features),
                    "parser": "pyshark"
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
                title="Rich RadioTap Metadata Available (PyShark)",
                description=f"{radiotap_ratio:.1%} of packets contain RadioTap information",
                details={
                    "radiotap_ratio": radiotap_ratio,
                    "available_features": dict(self.radiotap_features),
                    "antenna_diversity": len(self.antenna_info),
                    "parser": "pyshark"
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
                title="Very Short Capture Duration (PyShark)",
                description=f"Capture duration is only {self.capture_duration:.2f} seconds",
                details={
                    "capture_duration_seconds": self.capture_duration,
                    "minimum_recommended": self.min_capture_duration,
                    "total_packets": self.total_packets,
                    "parser": "pyshark"
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
                    title="Low Packet Capture Rate (PyShark)",
                    description=f"Average packet rate is {packet_rate:.2f} packets/second",
                    details={
                        "packet_rate_per_second": packet_rate,
                        "total_packets": self.total_packets,
                        "capture_duration": self.capture_duration,
                        "parser": "pyshark"
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
                    title="High Packet Capture Rate (PyShark)",
                    description=f"High packet rate detected: {packet_rate:.0f} packets/second",
                    details={
                        "packet_rate_per_second": packet_rate,
                        "total_packets": self.total_packets,
                        "parser": "pyshark"
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
                title="Advanced Hardware Capabilities Detected (PyShark)",
                description=f"Hardware supports: {', '.join(self.hardware_indicators)}",
                details={
                    "hardware_capabilities": list(self.hardware_indicators),
                    "driver_indicators": list(self.driver_indicators),
                    "parser": "pyshark"
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
                title="Multiple Antenna Support Detected (PyShark)",
                description=f"Detected {len(self.antenna_info)} different antennas",
                details={
                    "antenna_count": len(self.antenna_info),
                    "antenna_usage": dict(self.antenna_info),
                    "parser": "pyshark"
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
                title="High Duplicate Frame Rate (PyShark)",
                description=f"{duplicate_ratio:.1%} of frames appear to be duplicates",
                details={
                    "duplicate_ratio": duplicate_ratio,
                    "duplicate_count": self.duplicate_count,
                    "total_packets": self.total_packets,
                    "max_expected_ratio": self.max_duplicate_ratio,
                    "parser": "pyshark"
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
                title="Poor Capture Quality Detected (PyShark)",
                description=f"Overall capture quality score: {quality_score:.2f}/1.00",
                details=dict(self._get_quality_summary(), parser="pyshark"),
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
                title="Suboptimal Capture Quality (PyShark)",
                description=f"Capture quality score: {quality_score:.2f}/1.00",
                details=dict(self._get_quality_summary(), parser="pyshark"),
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
                title="Good Capture Quality (PyShark)",
                description=f"High capture quality score: {quality_score:.2f}/1.00",
                details=dict(self._get_quality_summary(), parser="pyshark"),
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
        
    def _create_packet_signature(self, packet: PySharkPacket) -> str:
        """Create a simple signature for duplicate detection using PyShark."""
        try:
            if hasattr(packet, 'wlan') and packet.wlan:
                wlan = packet.wlan
                # Simple signature based on key fields
                sig_parts = [
                    str(getattr(wlan, 'fc_type', '')),
                    str(getattr(wlan, 'fc_subtype', '')),
                    str(getattr(wlan, 'da', '')),
                    str(getattr(wlan, 'sa', '')),
                    str(len(str(packet)))
                ]
                return "|".join(sig_parts)
        except:
            pass
        return str(len(str(packet)))
        
    def _extract_timestamp(self, packet: PySharkPacket) -> float:
        """Extract timestamp from packet using PyShark."""
        try:
            if hasattr(packet, 'sniff_timestamp'):
                return float(packet.sniff_timestamp)
            elif hasattr(packet, 'frame_info') and hasattr(packet.frame_info, 'time_epoch'):
                return float(packet.frame_info.time_epoch)
        except (ValueError, TypeError, AttributeError):
            pass
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