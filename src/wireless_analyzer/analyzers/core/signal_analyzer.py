"""
RF/PHY signal analysis for wireless PCAP data.

This analyzer provides comprehensive RF and PHY layer analysis including:
- Signal strength analysis (RSSI, SNR, signal quality)
- MCS rate analysis and statistics
- Channel utilization and distribution
- Frequency band analysis
- PHY rate capabilities and usage patterns
- RF environment quality assessment
"""

import statistics
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import List, Dict, Any, Set, Tuple, Optional

from scapy.all import Packet
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeResp, Dot11ProbeReq, Dot11AssoReq, Dot11ReassoReq

from ...core.base_analyzer import BaseAnalyzer
from ...core.models import (
    Finding, 
    Severity, 
    AnalysisContext,
    AnalysisCategory,
    PacketReference
)


class RFPHYSignalAnalyzer(BaseAnalyzer):
    """
    Comprehensive RF/PHY layer analyzer for wireless networks.
    
    This analyzer examines:
    - Signal strength patterns and quality
    - MCS rates and modulation schemes
    - Channel usage and distribution
    - Frequency band utilization
    - PHY capabilities and performance
    - RF environment health
    """
    
    def __init__(self):
        super().__init__(
            name="RF/PHY Signal Analyzer",
            category=AnalysisCategory.RF_PHY,
            version="1.0"
        )
        self.description = "Analyzes RF/PHY layer metrics including signal strength, MCS rates, and channel utilization"
        self.analysis_order = 200  # Run after basic analyzers
        
        # Configuration thresholds
        self.low_rssi_threshold = -70  # dBm
        self.critical_rssi_threshold = -85  # dBm
        self.high_noise_threshold = -70  # dBm
        self.low_snr_threshold = 15  # dB
        self.critical_snr_threshold = 5  # dB
        
        # Channel information
        self.channel_frequencies_2_4 = {
            1: 2412, 2: 2417, 3: 2422, 4: 2427, 5: 2432, 6: 2437,
            7: 2442, 8: 2447, 9: 2452, 10: 2457, 11: 2462, 12: 2467, 13: 2472, 14: 2484
        }
        
        self.channel_frequencies_5 = {
            36: 5180, 40: 5200, 44: 5220, 48: 5240, 52: 5260, 56: 5280,
            60: 5300, 64: 5320, 100: 5500, 104: 5520, 108: 5540, 112: 5560,
            116: 5580, 120: 5600, 124: 5620, 128: 5640, 132: 5660, 136: 5680,
            140: 5700, 144: 5720, 149: 5745, 153: 5765, 157: 5785, 161: 5805,
            165: 5825, 169: 5845, 173: 5865
        }
        
        # Reset analysis state
        self.reset_analysis_state()
        
    def reset_analysis_state(self):
        """Reset analysis state for new capture."""
        self.signal_stats = []
        self.rssi_readings = []
        self.snr_readings = []
        self.noise_readings = []
        
        self.mcs_stats = Counter()
        self.rate_stats = Counter()
        self.channel_stats = Counter()
        self.frequency_stats = Counter()
        self.bandwidth_stats = Counter()
        
        self.phy_type_stats = Counter()  # 802.11a/b/g/n/ac/ax
        self.spatial_stream_stats = Counter()
        
        self.per_station_stats = defaultdict(dict)
        self.per_ap_stats = defaultdict(dict)
        
        self.channel_utilization = defaultdict(list)  # channel -> [timestamps]
        self.band_distribution = Counter()  # 2.4GHz, 5GHz, 6GHz
        
    def pre_analysis_setup(self, context: AnalysisContext) -> None:
        """Setup before analysis begins."""
        self.reset_analysis_state()
        self.logger.info(f"Starting {self.name} analysis")
        
    def is_applicable(self, packet: Packet) -> bool:
        """Check if packet has RF/PHY information worth analyzing."""
        return packet.haslayer(Dot11)
        
    def analyze(self, packets: List[Packet], context: AnalysisContext) -> List[Finding]:
        """
        Analyze packets for RF/PHY characteristics.
        
        Args:
            packets: List of packets to analyze
            context: Analysis context
            
        Returns:
            List of findings
        """
        findings = []
        
        if not packets:
            self.logger.debug("No packets to analyze")
            return findings
            
        self.logger.info(f"Analyzing RF/PHY characteristics of {len(packets)} packets")
        
        # Collect RF/PHY metrics from packets
        self._collect_rf_phy_metrics(packets)
        
        # Analyze different RF/PHY aspects
        findings.extend(self._analyze_signal_strength())
        findings.extend(self._analyze_channel_utilization())
        findings.extend(self._analyze_mcs_rates())
        findings.extend(self._analyze_frequency_bands())
        findings.extend(self._analyze_phy_capabilities())
        findings.extend(self._analyze_rf_environment())
        findings.extend(self._analyze_performance_issues())
        
        self.logger.info(f"Generated {len(findings)} RF/PHY findings")
        return findings
        
    def _collect_rf_phy_metrics(self, packets: List[Packet]) -> None:
        """Collect RF/PHY metrics from packets."""
        for i, packet in enumerate(packets):
            try:
                if not packet.haslayer(Dot11):
                    continue
                    
                dot11 = packet[Dot11]
                
                # Extract basic addressing
                src_mac = self._normalize_mac(str(dot11.addr2)) if hasattr(dot11, 'addr2') and dot11.addr2 else None
                dst_mac = self._normalize_mac(str(dot11.addr1)) if hasattr(dot11, 'addr1') and dot11.addr1 else None
                bssid = self._normalize_mac(str(dot11.addr3)) if hasattr(dot11, 'addr3') and dot11.addr3 else None
                
                # Extract timestamp
                timestamp = self._extract_timestamp(packet)
                
                # Extract RadioTap information if available
                rf_info = self._extract_radiotap_info(packet)
                
                # Extract channel and frequency
                channel_info = self._extract_channel_info(packet, rf_info)
                
                # Extract rate and MCS information
                rate_info = self._extract_rate_info(packet, rf_info)
                
                # Store metrics
                packet_metrics = {
                    'packet_index': i,
                    'timestamp': timestamp,
                    'src_mac': src_mac,
                    'dst_mac': dst_mac,
                    'bssid': bssid,
                    'frame_type': dot11.type,
                    'frame_subtype': dot11.subtype,
                    **rf_info,
                    **channel_info,
                    **rate_info
                }
                
                self.signal_stats.append(packet_metrics)
                
                # Update statistics
                self._update_statistics(packet_metrics)
                
            except Exception as e:
                self.logger.debug(f"Error processing packet {i}: {e}")
                continue
                
    def _extract_radiotap_info(self, packet: Packet) -> Dict[str, Any]:
        """Extract RadioTap header information."""
        rf_info = {
            'rssi': None,
            'noise': None,
            'snr': None,
            'signal_quality': None,
            'antenna': None,
            'tx_power': None
        }
        
        # Check for RadioTap header
        if hasattr(packet, 'dBm_AntSignal'):
            rf_info['rssi'] = int(packet.dBm_AntSignal)
            self.rssi_readings.append(rf_info['rssi'])
            
        if hasattr(packet, 'dBm_AntNoise'):
            rf_info['noise'] = int(packet.dBm_AntNoise)
            self.noise_readings.append(rf_info['noise'])
            
        # Calculate SNR if we have both signal and noise
        if rf_info['rssi'] is not None and rf_info['noise'] is not None:
            rf_info['snr'] = rf_info['rssi'] - rf_info['noise']
            self.snr_readings.append(rf_info['snr'])
            
        if hasattr(packet, 'Antenna'):
            rf_info['antenna'] = int(packet.Antenna)
            
        if hasattr(packet, 'dBm_TX_Power'):
            rf_info['tx_power'] = int(packet.dBm_TX_Power)
            
        return rf_info
        
    def _extract_channel_info(self, packet: Packet, rf_info: Dict[str, Any]) -> Dict[str, Any]:
        """Extract channel and frequency information."""
        channel_info = {
            'channel': None,
            'frequency': None,
            'bandwidth': None,
            'band': None
        }
        
        # Try RadioTap first
        if hasattr(packet, 'Channel'):
            channel_info['frequency'] = int(packet.Channel)
            channel_info['channel'] = self._frequency_to_channel(channel_info['frequency'])
            
        if hasattr(packet, 'ChannelFlags'):
            flags = int(packet.ChannelFlags)
            # Determine bandwidth and other characteristics from flags
            if flags & 0x0010:  # CCK
                channel_info['bandwidth'] = 20
            elif flags & 0x0020:  # OFDM
                channel_info['bandwidth'] = 20
                
        # Determine band
        if channel_info['frequency']:
            if 2400 <= channel_info['frequency'] <= 2500:
                channel_info['band'] = '2.4GHz'
                self.band_distribution['2.4GHz'] += 1
            elif 5000 <= channel_info['frequency'] <= 6000:
                channel_info['band'] = '5GHz'
                self.band_distribution['5GHz'] += 1
            elif 6000 <= channel_info['frequency'] <= 7000:
                channel_info['band'] = '6GHz'
                self.band_distribution['6GHz'] += 1
                
        # Update channel statistics
        if channel_info['channel']:
            self.channel_stats[channel_info['channel']] += 1
            
        if channel_info['frequency']:
            self.frequency_stats[channel_info['frequency']] += 1
            
        return channel_info
        
    def _extract_rate_info(self, packet: Packet, rf_info: Dict[str, Any]) -> Dict[str, Any]:
        """Extract data rate and MCS information."""
        rate_info = {
            'data_rate': None,
            'mcs_index': None,
            'spatial_streams': None,
            'phy_type': None,
            'guard_interval': None,
            'bandwidth_mhz': None
        }
        
        # Try RadioTap rate information
        if hasattr(packet, 'Rate'):
            # Rate in 500kbps units
            rate_info['data_rate'] = float(packet.Rate) * 0.5
            self.rate_stats[rate_info['data_rate']] += 1
            
        # Check for 802.11n MCS information
        if hasattr(packet, 'MCS_index'):
            rate_info['mcs_index'] = int(packet.MCS_index)
            self.mcs_stats[rate_info['mcs_index']] += 1
            rate_info['phy_type'] = '802.11n'
            
        if hasattr(packet, 'MCS_bandwidth'):
            rate_info['bandwidth_mhz'] = 20 if packet.MCS_bandwidth == 0 else 40
            
        if hasattr(packet, 'MCS_gi'):
            rate_info['guard_interval'] = 'short' if packet.MCS_gi else 'long'
            
        # Check for 802.11ac VHT information
        if hasattr(packet, 'VHT_NSS'):
            rate_info['spatial_streams'] = int(packet.VHT_NSS)
            rate_info['phy_type'] = '802.11ac'
            self.spatial_stream_stats[rate_info['spatial_streams']] += 1
            
        if hasattr(packet, 'VHT_MCS'):
            rate_info['mcs_index'] = int(packet.VHT_MCS)
            self.mcs_stats[rate_info['mcs_index']] += 1
            
        # Determine PHY type from other indicators
        if not rate_info['phy_type']:
            if rate_info['data_rate']:
                if rate_info['data_rate'] <= 11:
                    rate_info['phy_type'] = '802.11b'
                elif rate_info['data_rate'] <= 54:
                    rate_info['phy_type'] = '802.11g'
                else:
                    rate_info['phy_type'] = '802.11n+'
                    
        if rate_info['phy_type']:
            self.phy_type_stats[rate_info['phy_type']] += 1
            
        return rate_info
        
    def _update_statistics(self, metrics: Dict[str, Any]) -> None:
        """Update running statistics with packet metrics."""
        # Update per-station statistics
        if metrics['src_mac']:
            if metrics['src_mac'] not in self.per_station_stats:
                self.per_station_stats[metrics['src_mac']] = {
                    'rssi_readings': [],
                    'rates': [],
                    'channels': set(),
                    'packet_count': 0
                }
                
            station_stats = self.per_station_stats[metrics['src_mac']]
            station_stats['packet_count'] += 1
            
            if metrics['rssi']:
                station_stats['rssi_readings'].append(metrics['rssi'])
            if metrics['data_rate']:
                station_stats['rates'].append(metrics['data_rate'])
            if metrics['channel']:
                station_stats['channels'].add(metrics['channel'])
                
        # Update channel utilization timeline
        if metrics['channel'] and metrics['timestamp']:
            self.channel_utilization[metrics['channel']].append(metrics['timestamp'])
            
    def _analyze_signal_strength(self) -> List[Finding]:
        """Analyze signal strength patterns and issues."""
        findings = []
        
        if not self.rssi_readings:
            return findings
            
        avg_rssi = statistics.mean(self.rssi_readings)
        rssi_std = statistics.stdev(self.rssi_readings) if len(self.rssi_readings) > 1 else 0
        min_rssi = min(self.rssi_readings)
        max_rssi = max(self.rssi_readings)
        
        # Check for poor signal strength
        if avg_rssi < self.critical_rssi_threshold:
            findings.append(self.create_finding(
                severity=Severity.CRITICAL,
                title="Poor Signal Strength Detected",
                description=f"Average RSSI is {avg_rssi:.1f} dBm, below critical threshold",
                details={
                    "average_rssi": avg_rssi,
                    "min_rssi": min_rssi,
                    "max_rssi": max_rssi,
                    "rssi_std_dev": rssi_std,
                    "critical_threshold": self.critical_rssi_threshold,
                    "samples": len(self.rssi_readings)
                },
                recommendations=[
                    "Check AP placement and coverage areas",
                    "Verify antenna orientation and gain",
                    "Look for physical obstructions or interference",
                    "Consider adding additional APs for better coverage"
                ],
                confidence=0.9
            ))
        elif avg_rssi < self.low_rssi_threshold:
            findings.append(self.create_finding(
                severity=Severity.WARNING,
                title="Suboptimal Signal Strength",
                description=f"Average RSSI is {avg_rssi:.1f} dBm, below optimal threshold",
                details={
                    "average_rssi": avg_rssi,
                    "min_rssi": min_rssi,
                    "max_rssi": max_rssi,
                    "rssi_std_dev": rssi_std,
                    "low_threshold": self.low_rssi_threshold,
                    "samples": len(self.rssi_readings)
                },
                recommendations=[
                    "Monitor for connectivity issues",
                    "Consider optimizing AP placement",
                    "Check for intermittent interference sources"
                ],
                confidence=0.7
            ))
            
        # Check for high RSSI variance (unstable signal)
        if rssi_std > 10:
            findings.append(self.create_finding(
                severity=Severity.WARNING,
                title="High Signal Variance Detected",
                description=f"RSSI standard deviation is {rssi_std:.1f} dB, indicating unstable signal",
                details={
                    "rssi_std_dev": rssi_std,
                    "average_rssi": avg_rssi,
                    "variance_threshold": 10,
                    "possible_causes": [
                        "Mobile devices moving during capture",
                        "Interference sources",
                        "Multipath propagation",
                        "Environmental changes"
                    ]
                },
                recommendations=[
                    "Investigate potential interference sources",
                    "Check for mobile devices in the capture",
                    "Consider environmental factors (people movement, etc.)",
                    "Analyze spatial diversity if multiple antennas available"
                ],
                confidence=0.6
            ))
            
        return findings
        
    def _analyze_channel_utilization(self) -> List[Finding]:
        """Analyze channel usage patterns and distribution."""
        findings = []
        
        if not self.channel_stats:
            return findings
            
        total_packets = sum(self.channel_stats.values())
        channel_percentages = {
            ch: (count / total_packets) * 100 
            for ch, count in self.channel_stats.items()
        }
        
        # Check for channel concentration
        max_channel = max(self.channel_stats.keys(), key=lambda x: self.channel_stats[x])
        max_percentage = channel_percentages[max_channel]
        
        if max_percentage > 80:
            findings.append(self.create_finding(
                severity=Severity.INFO,
                title="Single Channel Dominance",
                description=f"Channel {max_channel} accounts for {max_percentage:.1f}% of all traffic",
                details={
                    "dominant_channel": max_channel,
                    "percentage": max_percentage,
                    "channel_distribution": dict(self.channel_stats.most_common()),
                    "total_channels": len(self.channel_stats)
                },
                recommendations=[
                    "This may indicate a single-AP capture",
                    "Consider multi-channel capture for comprehensive analysis",
                    "Verify capture setup covers intended channels"
                ],
                confidence=0.8
            ))
            
        # Check for overlapping 2.4GHz channels
        channels_24 = [ch for ch in self.channel_stats.keys() if ch <= 14]
        if len(channels_24) > 1:
            overlapping = self._check_overlapping_channels(channels_24)
            if overlapping:
                findings.append(self.create_finding(
                    severity=Severity.WARNING,
                    title="Overlapping 2.4GHz Channels Detected",
                    description=f"Found {len(overlapping)} sets of overlapping channels in use",
                    details={
                        "overlapping_channels": overlapping,
                        "channels_24ghz": channels_24,
                        "recommended_channels": [1, 6, 11],
                        "channel_usage": {ch: self.channel_stats[ch] for ch in channels_24}
                    },
                    recommendations=[
                        "Use only channels 1, 6, and 11 in 2.4GHz for optimal performance",
                        "Avoid overlapping channels to reduce interference",
                        "Consider moving some APs to 5GHz if supported",
                        "Implement proper channel planning"
                    ],
                    confidence=0.9
                ))
                
        return findings
        
    def _analyze_mcs_rates(self) -> List[Finding]:
        """Analyze MCS rate usage and performance."""
        findings = []
        
        if not self.mcs_stats and not self.rate_stats:
            return findings
            
        # Analyze legacy rates vs MCS usage
        legacy_rates = [r for r in self.rate_stats.keys() if r <= 54]
        modern_mcs = list(self.mcs_stats.keys())
        
        if legacy_rates and not modern_mcs:
            total_legacy = sum(self.rate_stats[r] for r in legacy_rates)
            findings.append(self.create_finding(
                severity=Severity.WARNING,
                title="Only Legacy Rates Detected",
                description=f"No modern MCS rates found, only legacy rates up to {max(legacy_rates)} Mbps",
                details={
                    "legacy_rates": dict(Counter({r: self.rate_stats[r] for r in legacy_rates})),
                    "total_legacy_packets": total_legacy,
                    "max_legacy_rate": max(legacy_rates),
                    "phy_types": dict(self.phy_type_stats)
                },
                recommendations=[
                    "Check if devices support 802.11n or newer standards",
                    "Verify AP configuration supports modern rates",
                    "Consider upgrading older devices",
                    "Check for compatibility issues"
                ],
                confidence=0.8
            ))
            
        # Analyze MCS distribution
        if modern_mcs:
            avg_mcs = statistics.mean(modern_mcs) if modern_mcs else 0
            max_mcs = max(modern_mcs)
            
            if max_mcs < 7:  # Low MCS rates suggest performance issues
                findings.append(self.create_finding(
                    severity=Severity.WARNING,
                    title="Low MCS Rates Detected",
                    description=f"Maximum MCS index is {max_mcs}, suggesting suboptimal performance",
                    details={
                        "max_mcs": max_mcs,
                        "average_mcs": avg_mcs,
                        "mcs_distribution": dict(self.mcs_stats.most_common()),
                        "spatial_streams": dict(self.spatial_stream_stats)
                    },
                    recommendations=[
                        "Check signal strength and quality",
                        "Verify channel conditions and interference",
                        "Consider device capabilities and positioning",
                        "Look for rate adaptation issues"
                    ],
                    confidence=0.7
                ))
                
        return findings
        
    def _analyze_frequency_bands(self) -> List[Finding]:
        """Analyze frequency band distribution and usage."""
        findings = []
        
        if not self.band_distribution:
            return findings
            
        total_packets = sum(self.band_distribution.values())
        band_percentages = {
            band: (count / total_packets) * 100 
            for band, count in self.band_distribution.items()
        }
        
        # Check for band imbalance
        if '2.4GHz' in band_percentages and '5GHz' in band_percentages:
            ratio_24_to_5 = band_percentages['2.4GHz'] / band_percentages['5GHz']
            
            if ratio_24_to_5 > 4:  # Heavy 2.4GHz usage
                findings.append(self.create_finding(
                    severity=Severity.WARNING,
                    title="Heavy 2.4GHz Band Usage",
                    description=f"2.4GHz band accounts for {band_percentages['2.4GHz']:.1f}% of traffic vs {band_percentages['5GHz']:.1f}% on 5GHz",
                    details={
                        "band_distribution": dict(self.band_distribution),
                        "band_percentages": band_percentages,
                        "ratio_24_to_5": ratio_24_to_5
                    },
                    recommendations=[
                        "Consider band steering to 5GHz for capable devices",
                        "Check if 5GHz coverage is adequate",
                        "Investigate why devices prefer 2.4GHz",
                        "Optimize dual-band configuration"
                    ],
                    confidence=0.7
                ))
                
        # Check for 6GHz usage
        if '6GHz' in band_percentages:
            findings.append(self.create_finding(
                severity=Severity.INFO,
                title="6GHz Band Activity Detected",
                description=f"Found {band_percentages['6GHz']:.1f}% of traffic on 6GHz band",
                details={
                    "band_6ghz_percentage": band_percentages['6GHz'],
                    "band_distribution": dict(self.band_distribution)
                },
                recommendations=[
                    "6GHz represents next-generation WiFi capabilities",
                    "Monitor performance and client compatibility",
                    "Consider 6GHz-specific optimizations"
                ],
                confidence=0.9
            ))
            
        return findings
        
    def _analyze_phy_capabilities(self) -> List[Finding]:
        """Analyze PHY layer capabilities and standards."""
        findings = []
        
        if not self.phy_type_stats:
            return findings
            
        # Check for mixed PHY standards
        phy_types = list(self.phy_type_stats.keys())
        if len(phy_types) > 2:
            findings.append(self.create_finding(
                severity=Severity.INFO,
                title="Multiple PHY Standards Detected",
                description=f"Found {len(phy_types)} different PHY standards in use",
                details={
                    "phy_standards": dict(self.phy_type_stats),
                    "standard_count": len(phy_types),
                    "most_common": self.phy_type_stats.most_common(1)[0] if phy_types else None
                },
                recommendations=[
                    "Mixed standards are normal in enterprise environments",
                    "Consider device upgrade strategy for older standards",
                    "Monitor for compatibility issues between standards"
                ],
                confidence=0.8
            ))
            
        # Check for spatial stream usage
        if self.spatial_stream_stats:
            max_streams = max(self.spatial_stream_stats.keys())
            avg_streams = statistics.mean([
                s for s, count in self.spatial_stream_stats.items() 
                for _ in range(count)
            ])
            
            findings.append(self.create_finding(
                severity=Severity.INFO,
                title="Spatial Stream Analysis",
                description=f"Maximum {max_streams} spatial streams detected, average {avg_streams:.1f}",
                details={
                    "max_spatial_streams": max_streams,
                    "average_spatial_streams": avg_streams,
                    "stream_distribution": dict(self.spatial_stream_stats),
                    "total_mimo_packets": sum(self.spatial_stream_stats.values())
                },
                recommendations=[
                    "Higher spatial streams indicate MIMO capability",
                    "Monitor for MIMO performance optimization",
                    "Consider antenna configuration and positioning"
                ],
                confidence=0.8
            ))
            
        return findings
        
    def _analyze_rf_environment(self) -> List[Finding]:
        """Analyze overall RF environment quality."""
        findings = []
        
        # Analyze SNR if available
        if self.snr_readings:
            avg_snr = statistics.mean(self.snr_readings)
            min_snr = min(self.snr_readings)
            
            if avg_snr < self.critical_snr_threshold:
                findings.append(self.create_finding(
                    severity=Severity.CRITICAL,
                    title="Poor SNR Environment",
                    description=f"Average SNR is {avg_snr:.1f} dB, below critical threshold",
                    details={
                        "average_snr": avg_snr,
                        "min_snr": min_snr,
                        "max_snr": max(self.snr_readings),
                        "snr_std_dev": statistics.stdev(self.snr_readings) if len(self.snr_readings) > 1 else 0,
                        "critical_threshold": self.critical_snr_threshold
                    },
                    recommendations=[
                        "Investigate noise sources in the environment",
                        "Check for interference from non-WiFi devices",
                        "Consider RF shielding or filtering",
                        "Optimize AP power levels and positioning"
                    ],
                    confidence=0.9
                ))
            elif avg_snr < self.low_snr_threshold:
                findings.append(self.create_finding(
                    severity=Severity.WARNING,
                    title="Suboptimal SNR Environment",
                    description=f"Average SNR is {avg_snr:.1f} dB, below optimal threshold",
                    details={
                        "average_snr": avg_snr,
                        "min_snr": min_snr,
                        "low_threshold": self.low_snr_threshold,
                        "samples": len(self.snr_readings)
                    },
                    recommendations=[
                        "Monitor for performance degradation",
                        "Check for potential interference sources",
                        "Consider environmental noise assessment"
                    ],
                    confidence=0.7
                ))
                
        # Analyze noise floor if available
        if self.noise_readings:
            avg_noise = statistics.mean(self.noise_readings)
            if avg_noise > self.high_noise_threshold:
                findings.append(self.create_finding(
                    severity=Severity.WARNING,
                    title="High Noise Floor Detected",
                    description=f"Average noise floor is {avg_noise:.1f} dBm, indicating noisy RF environment",
                    details={
                        "average_noise": avg_noise,
                        "min_noise": min(self.noise_readings),
                        "max_noise": max(self.noise_readings),
                        "high_threshold": self.high_noise_threshold,
                        "samples": len(self.noise_readings)
                    },
                    recommendations=[
                        "Identify and eliminate noise sources",
                        "Check for non-WiFi interference (microwaves, Bluetooth, etc.)",
                        "Consider frequency planning to avoid noisy channels",
                        "Implement interference mitigation techniques"
                    ],
                    confidence=0.8
                ))
                
        return findings
        
    def _analyze_performance_issues(self) -> List[Finding]:
        """Analyze for RF-related performance issues."""
        findings = []
        
        # Check for rate adaptation issues
        if self.rate_stats:
            rates = list(self.rate_stats.keys())
            if rates:
                rate_variance = statistics.stdev(rates) if len(rates) > 1 else 0
                avg_rate = statistics.mean(rates)
                
                # High rate variance might indicate rate adaptation problems
                if rate_variance > 20 and avg_rate > 10:
                    findings.append(self.create_finding(
                        severity=Severity.WARNING,
                        title="High Rate Variance Detected",
                        description=f"Data rate variance is {rate_variance:.1f}, suggesting rate adaptation issues",
                        details={
                            "rate_variance": rate_variance,
                            "average_rate": avg_rate,
                            "min_rate": min(rates),
                            "max_rate": max(rates),
                            "rate_distribution": dict(Counter(rates).most_common(10))
                        },
                        recommendations=[
                            "Check for signal strength variations",
                            "Investigate interference patterns",
                            "Monitor for device mobility during capture",
                            "Consider rate adaptation algorithm tuning"
                        ],
                        confidence=0.6
                    ))
                    
        return findings
        
    def _check_overlapping_channels(self, channels: List[int]) -> List[List[int]]:
        """Check for overlapping 2.4GHz channels."""
        overlapping_sets = []
        
        # 2.4GHz channels overlap if they are within 4 channels of each other
        for i, ch1 in enumerate(channels):
            for ch2 in channels[i+1:]:
                if abs(ch1 - ch2) < 5 and abs(ch1 - ch2) != 5:  # Overlapping but not exactly 5 apart
                    overlapping_sets.append([ch1, ch2])
                    
        return overlapping_sets
        
    def _frequency_to_channel(self, frequency: int) -> Optional[int]:
        """Convert frequency to channel number."""
        # Check 2.4GHz channels
        for channel, freq in self.channel_frequencies_2_4.items():
            if freq == frequency:
                return channel
                
        # Check 5GHz channels
        for channel, freq in self.channel_frequencies_5.items():
            if freq == frequency:
                return channel
                
        return None
        
    def _extract_timestamp(self, packet: Packet) -> float:
        """Extract timestamp from packet."""
        if hasattr(packet, 'time'):
            try:
                time_val = packet.time
                if hasattr(time_val, '__float__'):
                    return float(time_val)
                elif hasattr(time_val, 'val'):
                    return float(time_val.val)
                else:
                    return float(time_val)
            except (ValueError, TypeError, AttributeError):
                return 0.0
        return 0.0
        
    def _normalize_mac(self, mac: str) -> str:
        """Normalize MAC address format."""
        if not mac:
            return ""
        return mac.lower().replace('-', ':')
        
    def get_display_filters(self) -> List[str]:
        """Get Wireshark display filters for RF/PHY analysis."""
        return [
            "radiotap",
            "wlan.fc.type == 0",  # Management frames
            "wlan.fc.type == 1",  # Control frames  
            "wlan.fc.type == 2",  # Data frames
            "radiotap.dbm_antsignal",
            "radiotap.dbm_antnoise",
            "radiotap.mcs"
        ]
        
    def get_dependencies(self) -> List[str]:
        """Get analyzer dependencies."""
        return []  # No dependencies on other analyzers
        
    def post_analysis_cleanup(self, context: AnalysisContext) -> None:
        """Cleanup after analysis."""
        self.logger.info(f"Processed {len(self.signal_stats)} packets with RF/PHY data")
        self.logger.info(f"Found {len(self.channel_stats)} unique channels")
        self.logger.info(f"Found {len(self.band_distribution)} frequency bands")
        
        # Store summary in context for other analyzers
        context.security_context['rf_phy_summary'] = {
            'total_rf_packets': len(self.signal_stats),
            'channels': dict(self.channel_stats),
            'bands': dict(self.band_distribution),
            'phy_types': dict(self.phy_type_stats),
            'avg_rssi': statistics.mean(self.rssi_readings) if self.rssi_readings else None,
            'avg_snr': statistics.mean(self.snr_readings) if self.snr_readings else None
        }