"""
Packet parsing and analysis utilities for wireless frames.

This module provides utilities for parsing 802.11 frames,
extracting metadata, and performing common packet analysis tasks.
"""

import logging
from datetime import datetime
from typing import List, Dict, Any, Optional, Set, Tuple
from collections import Counter, defaultdict

from scapy.all import Packet
from scapy.layers.dot11 import (
    Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp,
    Dot11Auth, Dot11AssoReq, Dot11AssoResp, Dot11ReassoReq, Dot11ReassoResp,
    Dot11Deauth, Dot11Disas, Dot11QoS
)
from scapy.layers.eap import EAPOL

from ..core.models import NetworkEntity, FrameType


class PacketAnalyzer:
    """Utility class for packet analysis and metadata extraction."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # OUI database for vendor identification (partial)
        self.oui_database = {
            '00:1b:63': 'Apple',
            '00:23:12': 'Apple', 
            '00:26:bb': 'Apple',
            '3c:15:c2': 'Apple',
            '40:83:de': 'Apple',
            '00:0c:42': 'Cisco',
            '00:40:96': 'Cisco',
            '00:d0:97': 'Cisco',
            '00:26:08': 'Cisco',
            '00:50:56': 'Intel',
            '00:1f:3c': 'Intel',
            '00:15:00': 'Intel',
            '00:0e:35': 'Intel'
        }
        
    def analyze_packet_distribution(self, packets: List[Packet]) -> Dict[str, Any]:
        """
        Analyze distribution of packet types and extract basic statistics.
        
        Args:
            packets: List of packets to analyze
            
        Returns:
            Dictionary with packet distribution statistics
        """
        stats = {
            'total_packets': len(packets),
            'management_frames': 0,
            'control_frames': 0,
            'data_frames': 0,
            'extension_frames': 0,
            'beacon_frames': 0,
            'probe_requests': 0,
            'probe_responses': 0,
            'auth_frames': 0,
            'assoc_frames': 0,
            'reassoc_frames': 0,
            'deauth_frames': 0,
            'disassoc_frames': 0,
            'eapol_frames': 0,
            'fcs_errors': 0,
            'retry_frames': 0,
            'duplicate_frames': 0,
            'channels': set(),
            'bands': set(),
            'ssids': set(),
            'bssids': set(),
            'stations': set(),
            'rssi_values': []
        }
        
        seen_packets = set()  # For duplicate detection
        
        for packet in packets:
            # Check for duplicates using a simple hash
            packet_hash = self._get_packet_hash(packet)
            if packet_hash in seen_packets:
                stats['duplicate_frames'] += 1
            else:
                seen_packets.add(packet_hash)
                
            # Check FCS errors
            if hasattr(packet, 'fcs_bad') and packet.fcs_bad:
                stats['fcs_errors'] += 1
                
            # Analyze 802.11 frames
            if packet.haslayer(Dot11):
                dot11 = packet[Dot11]
                
                # Check retry flag
                if dot11.FCfield & 0x08:
                    stats['retry_frames'] += 1
                    
                # Frame type analysis
                frame_type = dot11.type
                if frame_type == 0:  # Management
                    stats['management_frames'] += 1
                    self._analyze_management_frame(packet, stats)
                elif frame_type == 1:  # Control
                    stats['control_frames'] += 1
                elif frame_type == 2:  # Data
                    stats['data_frames'] += 1
                else:  # Extension
                    stats['extension_frames'] += 1
                    
                # Collect addresses
                if dot11.addr1:
                    stats['stations'].add(self._normalize_mac(dot11.addr1))
                if dot11.addr2:
                    stats['stations'].add(self._normalize_mac(dot11.addr2))
                if dot11.addr3:
                    stats['bssids'].add(self._normalize_mac(dot11.addr3))
                    
            # Extract PHY information
            self._extract_phy_info(packet, stats)
            
            # Check for EAPOL
            if packet.haslayer(EAPOL):
                stats['eapol_frames'] += 1
                
        # Convert sets to lists for JSON serialization
        stats['channels'] = list(stats['channels'])
        stats['bands'] = list(stats['bands'])
        stats['ssids'] = list(stats['ssids'])
        stats['bssids'] = list(stats['bssids'])
        stats['stations'] = list(stats['stations'])
        
        return stats
        
    def _analyze_management_frame(self, packet: Packet, stats: Dict[str, Any]) -> None:
        """Analyze management frame subtypes."""
        if packet.haslayer(Dot11Beacon):
            stats['beacon_frames'] += 1
            # Extract SSID
            if hasattr(packet, 'info') and packet.info:
                try:
                    ssid = packet.info.decode('utf-8', errors='ignore')
                    if ssid:  # Non-empty SSID
                        stats['ssids'].add(ssid)
                except:
                    pass
                    
        elif packet.haslayer(Dot11ProbeReq):
            stats['probe_requests'] += 1
            # Extract requested SSID
            if hasattr(packet, 'info') and packet.info:
                try:
                    ssid = packet.info.decode('utf-8', errors='ignore')
                    if ssid:
                        stats['ssids'].add(ssid)
                except:
                    pass
                    
        elif packet.haslayer(Dot11ProbeResp):
            stats['probe_responses'] += 1
            
        elif packet.haslayer(Dot11Auth):
            stats['auth_frames'] += 1
            
        elif packet.haslayer(Dot11AssoReq) or packet.haslayer(Dot11AssoResp):
            stats['assoc_frames'] += 1
            
        elif packet.haslayer(Dot11ReassoReq) or packet.haslayer(Dot11ReassoResp):
            stats['reassoc_frames'] += 1
            
        elif packet.haslayer(Dot11Deauth):
            stats['deauth_frames'] += 1
            
        elif packet.haslayer(Dot11Disas):
            stats['disassoc_frames'] += 1
            
    def _extract_phy_info(self, packet: Packet, stats: Dict[str, Any]) -> None:
        """Extract PHY layer information from packet."""
        # Channel information
        if hasattr(packet, 'Channel'):
            stats['channels'].add(packet.Channel)
            
        # Frequency information
        if hasattr(packet, 'ChannelFrequency'):
            freq = packet.ChannelFrequency
            if freq < 2500:
                stats['bands'].add('2.4GHz')
            elif freq < 6000:
                stats['bands'].add('5GHz')
            else:
                stats['bands'].add('6GHz')
                
        # RSSI information
        if hasattr(packet, 'dBm_AntSignal'):
            stats['rssi_values'].append(packet.dBm_AntSignal)
            
    def extract_network_entities(self, packets: List[Packet]) -> List[NetworkEntity]:
        """
        Extract network entities (APs, STAs) from packets.
        
        Args:
            packets: List of packets to analyze
            
        Returns:
            List of network entities
        """
        entities = {}
        
        for packet in packets:
            if not packet.haslayer(Dot11):
                continue
                
            dot11 = packet[Dot11]
            timestamp = datetime.fromtimestamp(getattr(packet, 'time', 0))
            
            # Extract MAC addresses
            src_mac = self._normalize_mac(dot11.addr2) if dot11.addr2 else None
            dst_mac = self._normalize_mac(dot11.addr1) if dot11.addr1 else None  
            bssid = self._normalize_mac(dot11.addr3) if dot11.addr3 else None
            
            # Determine entity types based on frame patterns
            if packet.haslayer(Dot11Beacon) and src_mac:
                # Beacon sender is an AP
                if src_mac not in entities:
                    entities[src_mac] = NetworkEntity(
                        mac_address=src_mac,
                        entity_type='ap',
                        vendor_oui=self._get_vendor_oui(src_mac),
                        first_seen=timestamp
                    )
                entities[src_mac].last_seen = timestamp
                
                # Extract AP capabilities from beacon
                self._extract_ap_capabilities(packet, entities[src_mac])
                
            elif packet.haslayer(Dot11ProbeReq) and src_mac:
                # Probe request sender is likely a STA
                if src_mac not in entities:
                    entities[src_mac] = NetworkEntity(
                        mac_address=src_mac,
                        entity_type='sta',
                        vendor_oui=self._get_vendor_oui(src_mac),
                        first_seen=timestamp
                    )
                entities[src_mac].last_seen = timestamp
                
                # Extract STA capabilities
                self._extract_sta_capabilities(packet, entities[src_mac])
                
            elif packet.haslayer(Dot11AssoReq) and src_mac:
                # Association request sender is a STA
                if src_mac not in entities:
                    entities[src_mac] = NetworkEntity(
                        mac_address=src_mac,
                        entity_type='sta',
                        vendor_oui=self._get_vendor_oui(src_mac),
                        first_seen=timestamp
                    )
                entities[src_mac].last_seen = timestamp
                
        return list(entities.values())
        
    def _extract_ap_capabilities(self, packet: Packet, entity: NetworkEntity) -> None:
        """Extract AP capabilities from beacon/probe response."""
        if not packet.haslayer(Dot11Beacon):
            return
            
        capabilities = entity.capabilities
        
        # Extract basic information
        if hasattr(packet, 'info') and packet.info:
            try:
                capabilities['ssid'] = packet.info.decode('utf-8', errors='ignore')
            except:
                pass
                
        # Beacon interval
        if hasattr(packet, 'beacon_int'):
            capabilities['beacon_interval'] = packet.beacon_int
            
        # TODO: Extract more detailed capabilities from information elements
        # This would include supported rates, HT/VHT/HE capabilities, etc.
        
    def _extract_sta_capabilities(self, packet: Packet, entity: NetworkEntity) -> None:
        """Extract STA capabilities from probe request/association request."""
        capabilities = entity.capabilities
        
        # TODO: Extract STA capabilities from probe requests and association requests
        # This would include supported rates, power management, etc.
        pass
        
    def get_frame_type_name(self, packet: Packet) -> str:
        """
        Get human-readable frame type name.
        
        Args:
            packet: 802.11 packet
            
        Returns:
            Frame type name
        """
        if not packet.haslayer(Dot11):
            return "Non-802.11"
            
        dot11 = packet[Dot11]
        type_subtype = (dot11.type << 4) | dot11.subtype
        
        frame_types = {
            # Management frames
            0x00: "Association Request",
            0x10: "Association Response", 
            0x20: "Reassociation Request",
            0x30: "Reassociation Response",
            0x40: "Probe Request",
            0x50: "Probe Response",
            0x80: "Beacon",
            0x90: "ATIM",
            0xA0: "Disassociation",
            0xB0: "Authentication",
            0xC0: "Deauthentication",
            0xD0: "Action",
            
            # Control frames
            0x84: "Block Ack Request",
            0x94: "Block Ack",
            0xA4: "PS-Poll",
            0xB4: "RTS",
            0xC4: "CTS", 
            0xD4: "ACK",
            0xE4: "CF-End",
            0xF4: "CF-End+CF-Ack",
            
            # Data frames
            0x08: "Data",
            0x18: "Data+CF-Ack",
            0x28: "Data+CF-Poll",
            0x38: "Data+CF-Ack+CF-Poll",
            0x48: "Null",
            0x58: "CF-Ack",
            0x68: "CF-Poll",
            0x78: "CF-Ack+CF-Poll",
            0x88: "QoS Data",
            0x98: "QoS Data+CF-Ack",
            0xA8: "QoS Data+CF-Poll",
            0xB8: "QoS Data+CF-Ack+CF-Poll",
            0xC8: "QoS Null",
            0xE8: "QoS CF-Poll",
            0xF8: "QoS CF-Ack+CF-Poll"
        }
        
        return frame_types.get(type_subtype, f"Type{dot11.type}Subtype{dot11.subtype}")
        
    def extract_packet_timing_info(self, packets: List[Packet]) -> Dict[str, Any]:
        """
        Extract timing information from packets.
        
        Args:
            packets: List of packets
            
        Returns:
            Timing information dictionary
        """
        if not packets:
            return {}
            
        timestamps = [getattr(p, 'time', 0) for p in packets if hasattr(p, 'time')]
        
        if not timestamps:
            return {}
            
        timestamps.sort()
        
        # Calculate inter-frame intervals
        intervals = []
        for i in range(1, len(timestamps)):
            intervals.append(timestamps[i] - timestamps[i-1])
            
        timing_info = {
            'start_time': timestamps[0],
            'end_time': timestamps[-1],
            'duration': timestamps[-1] - timestamps[0],
            'packet_count': len(packets),
            'packets_with_timestamps': len(timestamps)
        }
        
        if intervals:
            import statistics
            timing_info.update({
                'average_interval': statistics.mean(intervals),
                'median_interval': statistics.median(intervals),
                'min_interval': min(intervals),
                'max_interval': max(intervals),
                'interval_stddev': statistics.stdev(intervals) if len(intervals) > 1 else 0
            })
            
        return timing_info
        
    def analyze_rssi_distribution(self, packets: List[Packet]) -> Dict[str, Any]:
        """
        Analyze RSSI distribution in packets.
        
        Args:
            packets: List of packets
            
        Returns:
            RSSI analysis dictionary
        """
        rssi_values = []
        rssi_by_mac = defaultdict(list)
        
        for packet in packets:
            if hasattr(packet, 'dBm_AntSignal') and packet.haslayer(Dot11):
                rssi = packet.dBm_AntSignal
                rssi_values.append(rssi)
                
                # Group by source MAC
                src_mac = self._normalize_mac(packet[Dot11].addr2)
                if src_mac:
                    rssi_by_mac[src_mac].append(rssi)
                    
        if not rssi_values:
            return {'rssi_available': False}
            
        import statistics
        
        analysis = {
            'rssi_available': True,
            'sample_count': len(rssi_values),
            'min_rssi': min(rssi_values),
            'max_rssi': max(rssi_values),
            'average_rssi': statistics.mean(rssi_values),
            'median_rssi': statistics.median(rssi_values),
            'rssi_stddev': statistics.stdev(rssi_values) if len(rssi_values) > 1 else 0
        }
        
        # Analyze per-MAC statistics
        mac_stats = {}
        for mac, values in rssi_by_mac.items():
            if len(values) >= 3:  # Need minimum samples
                mac_stats[mac] = {
                    'sample_count': len(values),
                    'average_rssi': statistics.mean(values),
                    'min_rssi': min(values),
                    'max_rssi': max(values),
                    'rssi_range': max(values) - min(values)
                }
                
        analysis['per_mac_stats'] = mac_stats
        
        return analysis
        
    def _get_packet_hash(self, packet: Packet) -> str:
        """Generate a simple hash for duplicate detection."""
        if packet.haslayer(Dot11):
            dot11 = packet[Dot11]
            # Simple hash based on addresses and sequence number
            hash_components = [
                dot11.addr1 or "",
                dot11.addr2 or "",
                dot11.addr3 or "",
                str(getattr(dot11, 'SC', 0))  # Sequence control
            ]
            return "|".join(hash_components)
        return str(hash(bytes(packet)))
        
    def _normalize_mac(self, mac: str) -> str:
        """Normalize MAC address format."""
        if not mac:
            return ""
        return mac.lower().replace('-', ':')
        
    def _get_vendor_oui(self, mac: str) -> Optional[str]:
        """Get vendor from MAC address OUI."""
        if not mac or len(mac) < 8:
            return None
            
        oui = mac[:8].lower()  # First 3 octets
        return self.oui_database.get(oui)
        
    def extract_channel_utilization(self, packets: List[Packet]) -> Dict[str, Any]:
        """
        Calculate approximate channel utilization metrics.
        
        Args:
            packets: List of packets
            
        Returns:
            Channel utilization analysis
        """
        timing_info = self.extract_packet_timing_info(packets)
        
        if not timing_info or timing_info.get('duration', 0) <= 0:
            return {'utilization_available': False}
            
        duration = timing_info['duration']
        
        # Estimate airtime usage (very approximate)
        # This is a simplified calculation - real airtime depends on
        # data rates, frame sizes, inter-frame spacing, etc.
        
        frame_counts_by_type = {}
        total_estimated_airtime = 0
        
        for packet in packets:
            if packet.haslayer(Dot11):
                frame_type = self.get_frame_type_name(packet)
                frame_counts_by_type[frame_type] = frame_counts_by_type.get(frame_type, 0) + 1
                
                # Rough airtime estimates (microseconds)
                if "Beacon" in frame_type:
                    total_estimated_airtime += 500  # ~500μs for beacon
                elif "Data" in frame_type:
                    # Depends on size and rate, use rough average
                    total_estimated_airtime += 200  # ~200μs average
                else:
                    total_estimated_airtime += 50   # ~50μs for mgmt/ctrl
                    
        # Convert to percentage
        total_time_us = duration * 1000000  # Convert seconds to microseconds
        utilization_percent = (total_estimated_airtime / total_time_us) * 100
        
        return {
            'utilization_available': True,
            'estimated_utilization_percent': min(utilization_percent, 100),  # Cap at 100%
            'total_estimated_airtime_us': total_estimated_airtime,
            'capture_duration_s': duration,
            'frame_counts_by_type': frame_counts_by_type,
            'note': 'This is a rough estimation based on typical frame durations'
        }
