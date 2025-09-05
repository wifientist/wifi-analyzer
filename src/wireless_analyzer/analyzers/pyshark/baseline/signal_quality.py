"""
PyShark-specific Signal Quality Analyzer

RF/PHY signal analysis for wireless PCAP data using PyShark's native packet parsing.
Provides comprehensive RF and PHY layer analysis including signal strength, MCS rates,
channel utilization, and frequency band analysis.
"""

import statistics
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import List, Dict, Any, Set, Tuple, Optional

try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False

from ....core.base_analyzer import BasePySharkAnalyzer
from ....core.models import Finding


class PySharkSignalQualityAnalyzer(BasePySharkAnalyzer):
    """
    PyShark-based RF/PHY layer analyzer for wireless networks.
    
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
        self.name = "PyShark Signal Quality Analyzer"
        self.description = "Analyzes RF/PHY layer metrics using PyShark parsing"
        self.version = "1.0.0"
        
        if not PYSHARK_AVAILABLE:
            self.logger.warning("PyShark not available - analyzer will not function")
        
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
        if not PYSHARK_AVAILABLE:
            return []
        
        findings = []
        
        try:
            if not hasattr(packet, 'wlan'):
                return findings
            
            # Extract RF/PHY metrics
            rf_info = self._extract_radiotap_info(packet)
            channel_info = self._extract_channel_info(packet, rf_info)
            rate_info = self._extract_rate_info(packet, rf_info)
            
            # Get basic packet info
            timestamp = float(packet.sniff_timestamp)
            src_mac = packet.wlan.sa if hasattr(packet.wlan, 'sa') else None
            dst_mac = packet.wlan.da if hasattr(packet.wlan, 'da') else None
            bssid = packet.wlan.bssid if hasattr(packet.wlan, 'bssid') else None
            
            # Store metrics
            packet_metrics = {
                'timestamp': timestamp,
                'src_mac': self._normalize_mac(src_mac) if src_mac else None,
                'dst_mac': self._normalize_mac(dst_mac) if dst_mac else None,
                'bssid': self._normalize_mac(bssid) if bssid else None,
                'frame_type': int(packet.wlan.fc_type) if hasattr(packet.wlan, 'fc_type') else None,
                'frame_subtype': int(packet.wlan.fc_subtype) if hasattr(packet.wlan, 'fc_subtype') else None,
                **rf_info,
                **channel_info,
                **rate_info
            }
            
            self.signal_stats.append(packet_metrics)
            self._update_statistics(packet_metrics)
            
            # Perform real-time analysis for significant issues
            if rf_info.get('rssi') and rf_info['rssi'] < self.critical_rssi_threshold:
                findings.append(Finding(
                    analyzer_name=self.name,
                    finding_type="signal_quality",
                    severity="critical",
                    title="Critical Signal Strength",
                    description=f"RSSI {rf_info['rssi']} dBm below critical threshold",
                    evidence={
                        "rssi": rf_info['rssi'],
                        "src_mac": packet_metrics['src_mac'],
                        "timestamp": timestamp,
                        "parser": "pyshark"
                    },
                    recommendations=[
                        "Check device positioning and coverage",
                        "Investigate physical obstructions",
                        "Consider AP placement optimization"
                    ]
                ))
            
            if rf_info.get('snr') and rf_info['snr'] < self.critical_snr_threshold:
                findings.append(Finding(
                    analyzer_name=self.name,
                    finding_type="signal_quality",
                    severity="critical",
                    title="Critical SNR Level",
                    description=f"SNR {rf_info['snr']} dB below critical threshold",
                    evidence={
                        "snr": rf_info['snr'],
                        "rssi": rf_info.get('rssi'),
                        "noise": rf_info.get('noise'),
                        "src_mac": packet_metrics['src_mac'],
                        "timestamp": timestamp,
                        "parser": "pyshark"
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
        """Extract RadioTap header information using PyShark."""
        rf_info = {
            'rssi': None,
            'noise': None,
            'snr': None,
            'signal_quality': None,
            'antenna': None,
            'tx_power': None
        }
        
        if hasattr(packet, 'radiotap'):
            radiotap = packet.radiotap
            
            # Extract signal strength
            if hasattr(radiotap, 'dbm_antsignal'):
                rf_info['rssi'] = int(radiotap.dbm_antsignal)
                self.rssi_readings.append(rf_info['rssi'])
                
            if hasattr(radiotap, 'dbm_antnoise'):
                rf_info['noise'] = int(radiotap.dbm_antnoise)
                self.noise_readings.append(rf_info['noise'])
                
            # Calculate SNR if we have both signal and noise
            if rf_info['rssi'] is not None and rf_info['noise'] is not None:
                rf_info['snr'] = rf_info['rssi'] - rf_info['noise']
                self.snr_readings.append(rf_info['snr'])
                
            if hasattr(radiotap, 'antenna'):
                try:
                    rf_info['antenna'] = int(radiotap.antenna)
                except (ValueError, TypeError):
                    pass
                    
            if hasattr(radiotap, 'dbm_tx_power'):
                try:
                    rf_info['tx_power'] = int(radiotap.dbm_tx_power)
                except (ValueError, TypeError):
                    pass
        
        return rf_info
    
    def _extract_channel_info(self, packet, rf_info: Dict[str, Any]) -> Dict[str, Any]:
        """Extract channel and frequency information using PyShark."""
        channel_info = {
            'channel': None,
            'frequency': None,
            'bandwidth': None,
            'band': None
        }
        
        if hasattr(packet, 'radiotap'):
            radiotap = packet.radiotap
            
            # Extract frequency from RadioTap
            if hasattr(radiotap, 'channel_freq'):
                try:
                    channel_info['frequency'] = int(radiotap.channel_freq)
                    channel_info['channel'] = self._frequency_to_channel(channel_info['frequency'])
                except (ValueError, TypeError):
                    pass
                    
            if hasattr(radiotap, 'channel_flags'):
                try:
                    flags = int(radiotap.channel_flags, 16) if isinstance(radiotap.channel_flags, str) else int(radiotap.channel_flags)
                    # Determine bandwidth and other characteristics from flags
                    if flags & 0x0010:  # CCK
                        channel_info['bandwidth'] = 20
                    elif flags & 0x0020:  # OFDM
                        channel_info['bandwidth'] = 20
                except (ValueError, TypeError):
                    pass
        
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
        """Extract data rate and MCS information using PyShark."""
        rate_info = {
            'data_rate': None,
            'mcs_index': None,
            'spatial_streams': None,
            'phy_type': None,
            'guard_interval': None,
            'bandwidth_mhz': None
        }
        
        if hasattr(packet, 'radiotap'):
            radiotap = packet.radiotap
            
            # Extract basic rate information
            if hasattr(radiotap, 'datarate'):
                try:
                    # Rate typically in Mbps for PyShark
                    rate_info['data_rate'] = float(radiotap.datarate)
                    self.rate_stats[rate_info['data_rate']] += 1
                except (ValueError, TypeError):
                    pass
                    
            # Check for 802.11n MCS information
            if hasattr(radiotap, 'mcs_index'):
                try:
                    rate_info['mcs_index'] = int(radiotap.mcs_index)
                    self.mcs_stats[rate_info['mcs_index']] += 1
                    rate_info['phy_type'] = '802.11n'
                except (ValueError, TypeError):
                    pass
                    
            if hasattr(radiotap, 'mcs_bandwidth'):
                try:
                    bw_val = int(radiotap.mcs_bandwidth)
                    rate_info['bandwidth_mhz'] = 20 if bw_val == 0 else 40
                except (ValueError, TypeError):
                    pass
                    
            if hasattr(radiotap, 'mcs_gi'):
                try:
                    gi_val = int(radiotap.mcs_gi)
                    rate_info['guard_interval'] = 'short' if gi_val else 'long'
                except (ValueError, TypeError):
                    pass
                    
            # Check for 802.11ac VHT information
            if hasattr(radiotap, 'vht_nss'):
                try:
                    rate_info['spatial_streams'] = int(radiotap.vht_nss)
                    rate_info['phy_type'] = '802.11ac'
                    self.spatial_stream_stats[rate_info['spatial_streams']] += 1
                except (ValueError, TypeError):
                    pass
                    
            if hasattr(radiotap, 'vht_mcs'):
                try:
                    rate_info['mcs_index'] = int(radiotap.vht_mcs)
                    self.mcs_stats[rate_info['mcs_index']] += 1
                except (ValueError, TypeError):
                    pass
        
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
        if not PYSHARK_AVAILABLE:
            return {"error": "PyShark not available"}
        
        total_packets = len(self.signal_stats)
        
        summary = {
            "analyzer": self.name,
            "parser": "pyshark",
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
            findings.append(Finding(
                analyzer_name=self.name,
                finding_type="channel_usage",
                severity="info",
                title="Single Channel Dominance",
                description=f"Channel {max_channel} accounts for {max_percentage:.1f}% of all traffic",
                evidence={
                    "dominant_channel": max_channel,
                    "percentage": max_percentage,
                    "channel_distribution": dict(self.channel_stats.most_common()),
                    "total_channels": len(self.channel_stats),
                    "parser": "pyshark"
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
                findings.append(Finding(
                    analyzer_name=self.name,
                    finding_type="channel_interference",
                    severity="warning",
                    title="Overlapping 2.4GHz Channels Detected",
                    description=f"Found {len(overlapping)} sets of overlapping channels in use",
                    evidence={
                        "overlapping_channels": overlapping,
                        "channels_24ghz": channels_24,
                        "recommended_channels": [1, 6, 11],
                        "channel_usage": {ch: self.channel_stats[ch] for ch in channels_24},
                        "parser": "pyshark"
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