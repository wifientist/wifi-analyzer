"""
Scapy-specific Signal Quality Analyzer

RF/PHY signal analysis for wireless PCAP data using Scapy's native packet parsing.
Provides comprehensive RF and PHY layer analysis including signal strength, MCS rates,
channel utilization, and frequency band analysis.
"""

import statistics
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import List, Dict, Any, Set, Tuple, Optional

from scapy.all import Packet, RadioTap
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeResp, Dot11ProbeReq, Dot11AssoReq, Dot11ReassoReq, Dot11Elt

from ....core.base_analyzer import BaseScapyAnalyzer
from ....core.models import Finding, AnalysisCategory, Severity


class ScapySignalQualityAnalyzer(BaseScapyAnalyzer):
    """
    Scapy-based RF/PHY layer analyzer for wireless networks.
    
    This analyzer examines:
    - Signal strength patterns and quality
    - MCS rates and modulation schemes
    - Channel usage and distribution
    - Frequency band utilization
    - PHY capabilities and performance
    - RF environment health
    """
    
    def __init__(self):
        super().__init__()
        self.name = "Scapy Signal Quality Analyzer"
        self.category = AnalysisCategory.RF_PHY
        self.description = "Analyzes RF/PHY layer metrics using Scapy parsing"
        self.version = "1.0.0"
        
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

    def analyze_packet(self, packet, metadata: Dict[str, Any] = None) -> List[Finding]:
        """Analyze a single packet for RF/PHY characteristics."""
        findings = []
        
        try:
            if not packet.haslayer(Dot11):
                return findings
            
            # Extract RF/PHY metrics
            rf_info = self._extract_radiotap_info(packet)
            channel_info = self._extract_channel_info(packet, rf_info)
            rate_info = self._extract_rate_info(packet, rf_info)
            
            # Get basic packet info
            dot11 = packet[Dot11]
            timestamp = float(packet.time) if hasattr(packet, 'time') else 0.0
            
            # Store metrics
            packet_metrics = {
                'timestamp': timestamp,
                'src_mac': self._normalize_mac(str(dot11.addr2)) if hasattr(dot11, 'addr2') and dot11.addr2 else None,
                'dst_mac': self._normalize_mac(str(dot11.addr1)) if hasattr(dot11, 'addr1') and dot11.addr1 else None,
                'bssid': self._normalize_mac(str(dot11.addr3)) if hasattr(dot11, 'addr3') and dot11.addr3 else None,
                'frame_type': dot11.type,
                'frame_subtype': dot11.subtype,
                **rf_info,
                **channel_info,
                **rate_info
            }
            
            self.signal_stats.append(packet_metrics)
            self._update_statistics(packet_metrics)
            
            # Perform real-time analysis for significant issues
            if rf_info.get('rssi') and rf_info['rssi'] < self.critical_rssi_threshold:
                findings.append(self.create_finding(
                    severity=Severity.CRITICAL,
                    title="Critical Signal Strength",
                    description=f"RSSI {rf_info['rssi']} dBm below critical threshold",
                    details={
                        "rssi": rf_info['rssi'],
                        "src_mac": packet_metrics['src_mac'],
                        "timestamp": timestamp,
                        "parser": "scapy"
                    },
                    recommendations=[
                        "Check device positioning and coverage",
                        "Investigate physical obstructions",
                        "Consider AP placement optimization"
                    ]
                ))
            
            if rf_info.get('snr') and rf_info['snr'] < self.critical_snr_threshold:
                findings.append(self.create_finding(
                    severity=Severity.CRITICAL,
                    title="Critical SNR Level",
                    description=f"SNR {rf_info['snr']} dB below critical threshold",
                    details={
                        "snr": rf_info['snr'],
                        "rssi": rf_info.get('rssi'),
                        "noise": rf_info.get('noise'),
                        "src_mac": packet_metrics['src_mac'],
                        "timestamp": timestamp,
                        "parser": "scapy"
                    },
                    recommendations=[
                        "Investigate RF interference sources",
                        "Check noise floor in environment",
                        "Consider frequency planning adjustments"
                    ]
                ))
        
        except Exception as e:
            self.logger.error(f"Error analyzing signal quality: {e}")
        
        return findings
    
    def _extract_radiotap_info(self, packet) -> Dict[str, Any]:
        """Extract RadioTap header information using Scapy."""
        rf_info = {
            'rssi': None,
            'noise': None,
            'snr': None,
            'signal_quality': None,
            'antenna': None,
            'tx_power': None
        }
        
        if packet.haslayer(RadioTap):
            radiotap = packet[RadioTap]
            
            # Extract signal strength
            if hasattr(radiotap, 'dBm_AntSignal') and radiotap.dBm_AntSignal is not None:
                rf_info['rssi'] = int(radiotap.dBm_AntSignal)
                self.rssi_readings.append(rf_info['rssi'])
                
            if hasattr(radiotap, 'dBm_AntNoise') and radiotap.dBm_AntNoise is not None:
                rf_info['noise'] = int(radiotap.dBm_AntNoise)
                self.noise_readings.append(rf_info['noise'])
                
            # Calculate SNR if we have both signal and noise
            if rf_info['rssi'] is not None and rf_info['noise'] is not None:
                rf_info['snr'] = rf_info['rssi'] - rf_info['noise']
                self.snr_readings.append(rf_info['snr'])
                
            if hasattr(radiotap, 'Antenna') and radiotap.Antenna is not None:
                rf_info['antenna'] = int(radiotap.Antenna)
                
            if hasattr(radiotap, 'dBm_TX_Power') and radiotap.dBm_TX_Power is not None:
                rf_info['tx_power'] = int(radiotap.dBm_TX_Power)
        
        return rf_info
    
    def _extract_channel_info(self, packet, rf_info: Dict[str, Any]) -> Dict[str, Any]:
        """Extract channel and frequency information using Scapy."""
        channel_info = {
            'channel': None,
            'frequency': None,
            'bandwidth': None,
            'band': None
        }
        
        if packet.haslayer(RadioTap):
            radiotap = packet[RadioTap]
            
            # Extract frequency from RadioTap
            if hasattr(radiotap, 'Channel') and radiotap.Channel is not None:
                channel_info['frequency'] = int(radiotap.Channel)
                channel_info['channel'] = self._frequency_to_channel(channel_info['frequency'])
                
            if hasattr(radiotap, 'ChannelFlags') and radiotap.ChannelFlags is not None:
                flags = int(radiotap.ChannelFlags)
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
    
    def _extract_rate_info(self, packet, rf_info: Dict[str, Any]) -> Dict[str, Any]:
        """Extract data rate and MCS information using Scapy."""
        rate_info = {
            'data_rate': None,
            'mcs_index': None,
            'spatial_streams': None,
            'phy_type': None,
            'guard_interval': None,
            'bandwidth_mhz': None
        }
        
        if packet.haslayer(RadioTap):
            radiotap = packet[RadioTap]
            
            # Extract basic rate information
            if hasattr(radiotap, 'Rate') and radiotap.Rate is not None:
                # Rate in 500kbps units
                rate_info['data_rate'] = float(radiotap.Rate) * 0.5
                self.rate_stats[rate_info['data_rate']] += 1
                
            # Check for 802.11n MCS information
            if hasattr(radiotap, 'MCS_index') and radiotap.MCS_index is not None:
                rate_info['mcs_index'] = int(radiotap.MCS_index)
                self.mcs_stats[rate_info['mcs_index']] += 1
                rate_info['phy_type'] = '802.11n'
                
            if hasattr(radiotap, 'MCS_bandwidth'):
                rate_info['bandwidth_mhz'] = 20 if radiotap.MCS_bandwidth == 0 else 40
                
            if hasattr(radiotap, 'MCS_gi'):
                rate_info['guard_interval'] = 'short' if radiotap.MCS_gi else 'long'
                
            # Check for 802.11ac VHT information
            if hasattr(radiotap, 'VHT_NSS') and radiotap.VHT_NSS is not None:
                rate_info['spatial_streams'] = int(radiotap.VHT_NSS)
                rate_info['phy_type'] = '802.11ac'
                self.spatial_stream_stats[rate_info['spatial_streams']] += 1
                
            if hasattr(radiotap, 'VHT_MCS') and radiotap.VHT_MCS is not None:
                rate_info['mcs_index'] = int(radiotap.VHT_MCS)
                self.mcs_stats[rate_info['mcs_index']] += 1
        
        # Determine PHY type from other indicators
        if not rate_info['phy_type'] and rate_info['data_rate']:
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
    
    def _normalize_mac(self, mac: str) -> str:
        """Normalize MAC address format."""
        if not mac:
            return ""
        return mac.lower().replace('-', ':')
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get comprehensive analysis summary."""
        total_packets = len(self.signal_stats)
        
        summary = {
            "analyzer": self.name,
            "parser": "scapy",
            "total_packets": total_packets,
            "total_stations": len(self.per_station_stats),
            "channels_observed": dict(self.channel_stats),
            "band_distribution": dict(self.band_distribution),
            "phy_types": dict(self.phy_type_stats)
        }
        
        if self.rssi_readings:
            summary.update({
                "average_rssi": statistics.mean(self.rssi_readings),
                "min_rssi": min(self.rssi_readings),
                "max_rssi": max(self.rssi_readings),
                "rssi_std_dev": statistics.stdev(self.rssi_readings) if len(self.rssi_readings) > 1 else 0
            })
        
        if self.snr_readings:
            summary.update({
                "average_snr": statistics.mean(self.snr_readings),
                "min_snr": min(self.snr_readings),
                "max_snr": max(self.snr_readings)
            })
        
        if self.mcs_stats:
            summary["mcs_distribution"] = dict(self.mcs_stats.most_common(10))
        
        if self.rate_stats:
            rates = list(self.rate_stats.keys())
            summary.update({
                "average_rate": statistics.mean(rates),
                "max_rate": max(rates),
                "rate_distribution": dict(self.rate_stats.most_common(10))
            })
        
        return summary

    def analyze_channel_utilization(self) -> List[Finding]:
        """Analyze channel usage patterns and generate findings."""
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
                finding_type="channel_usage",
                severity="info",
                title="Single Channel Dominance",
                description=f"Channel {max_channel} accounts for {max_percentage:.1f}% of all traffic",
                evidence={
                    "dominant_channel": max_channel,
                    "percentage": max_percentage,
                    "channel_distribution": dict(self.channel_stats.most_common()),
                    "total_channels": len(self.channel_stats),
                    "parser": "scapy"
                },
                recommendations=[
                    "Consider multi-channel capture for comprehensive analysis",
                    "Verify capture setup covers intended channels"
                ]
            ))
        
        # Check for overlapping 2.4GHz channels
        channels_24 = [ch for ch in self.channel_stats.keys() if ch <= 14]
        if len(channels_24) > 1:
            overlapping = self._check_overlapping_channels(channels_24)
            if overlapping:
                findings.append(self.create_finding(
                    finding_type="channel_interference",
                    severity="warning",
                    title="Overlapping 2.4GHz Channels Detected",
                    description=f"Found {len(overlapping)} sets of overlapping channels in use",
                    evidence={
                        "overlapping_channels": overlapping,
                        "channels_24ghz": channels_24,
                        "recommended_channels": [1, 6, 11],
                        "channel_usage": {ch: self.channel_stats[ch] for ch in channels_24},
                        "parser": "scapy"
                    },
                    recommendations=[
                        "Use only channels 1, 6, and 11 in 2.4GHz for optimal performance",
                        "Avoid overlapping channels to reduce interference",
                        "Consider moving some APs to 5GHz if supported"
                    ]
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