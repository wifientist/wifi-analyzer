"""
Scapy-specific packet loader.

This loader uses Scapy to parse PCAP files and returns native Scapy packet objects.
"""

import time
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

from scapy.all import rdpcap, Packet
from scapy.error import Scapy_Exception


class ScapyPacketLoader:
    """Dedicated Scapy packet loader."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.stats = {
            'files_loaded': 0,
            'total_packets_loaded': 0,
            'total_loading_time': 0.0,
            'errors': []
        }
    
    def load_packets(
        self, 
        pcap_file: str, 
        max_packets: Optional[int] = None
    ) -> tuple[List[Packet], Dict[str, Any]]:
        """
        Load packets from PCAP file using Scapy.
        
        Args:
            pcap_file: Path to PCAP file
            max_packets: Maximum number of packets to load (None = all)
            
        Returns:
            Tuple of (packet_list, metadata)
            
        Raises:
            FileNotFoundError: If PCAP file doesn't exist
            ValueError: If file is not a valid PCAP
        """
        start_time = time.time()
        
        # Validate file
        pcap_path = Path(pcap_file)
        if not pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_file}")
        
        self.logger.info(f"Loading packets from {pcap_file} with Scapy")
        
        try:
            # Load packets with Scapy
            if max_packets:
                # Scapy doesn't have a direct limit parameter, so we'll load all and slice
                packets = rdpcap(str(pcap_path))[:max_packets]
            else:
                packets = rdpcap(str(pcap_path))
            
            loading_time = time.time() - start_time
            
            # Update stats
            self.stats['files_loaded'] += 1
            self.stats['total_packets_loaded'] += len(packets)
            self.stats['total_loading_time'] += loading_time
            
            # Create metadata
            metadata = {
                'library_used': 'scapy',
                'loading_time': loading_time,
                'total_packets': len(packets),
                'file_size_bytes': pcap_path.stat().st_size,
                'scapy_info': {
                    'packet_types': self._analyze_packet_types(packets),
                    'has_radiotap': self._check_for_radiotap(packets),
                    'has_dot11': self._check_for_dot11(packets),
                }
            }
            
            self.logger.info(
                f"Successfully loaded {len(packets)} packets "
                f"from {pcap_file} in {loading_time:.2f}s"
            )
            
            return packets, metadata
            
        except Scapy_Exception as e:
            error_msg = f"Scapy parsing error: {e}"
            self.logger.error(error_msg)
            self.stats['errors'].append(error_msg)
            raise ValueError(error_msg) from e
            
        except Exception as e:
            error_msg = f"Unexpected error loading PCAP: {e}"
            self.logger.error(error_msg)
            self.stats['errors'].append(error_msg)
            raise ValueError(error_msg) from e
    
    def _analyze_packet_types(self, packets: List[Packet]) -> Dict[str, int]:
        """Analyze packet types in the loaded packets."""
        type_counts = {}
        
        for packet in packets[:100]:  # Sample first 100 packets
            packet_type = packet.__class__.__name__
            type_counts[packet_type] = type_counts.get(packet_type, 0) + 1
        
        return type_counts
    
    def _check_for_radiotap(self, packets: List[Packet]) -> bool:
        """Check if packets have RadioTap headers."""
        from scapy.layers.dot11 import RadioTap
        
        for packet in packets[:10]:  # Check first 10 packets
            if packet.haslayer(RadioTap):
                return True
        return False
    
    def _check_for_dot11(self, packets: List[Packet]) -> bool:
        """Check if packets have 802.11 layers."""
        from scapy.layers.dot11 import Dot11
        
        for packet in packets[:10]:  # Check first 10 packets
            if packet.haslayer(Dot11):
                return True
        return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get loader statistics."""
        stats = dict(self.stats)
        
        if stats['files_loaded'] > 0:
            stats['average_loading_time'] = stats['total_loading_time'] / stats['files_loaded']
            stats['average_packets_per_file'] = stats['total_packets_loaded'] / stats['files_loaded']
        
        return stats
    
    def reset_stats(self) -> None:
        """Reset loader statistics."""
        self.stats = {
            'files_loaded': 0,
            'total_packets_loaded': 0,
            'total_loading_time': 0.0,
            'errors': []
        }