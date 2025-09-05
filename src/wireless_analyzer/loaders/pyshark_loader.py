"""
PyShark-specific packet loader.

This loader uses PyShark to parse PCAP files and returns native PyShark packet objects.
"""

import time
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

try:
    import pyshark
    from pyshark.packet.packet import Packet as PySharkPacket
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False
    PySharkPacket = None


class PySharkPacketLoader:
    """Dedicated PyShark packet loader."""
    
    def __init__(self):
        if not PYSHARK_AVAILABLE:
            raise ImportError("PyShark is not available. Install with: pip install pyshark")
        
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
    ) -> tuple[List[PySharkPacket], Dict[str, Any]]:
        """
        Load packets from PCAP file using PyShark.
        
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
        
        self.logger.info(f"Loading packets from {pcap_file} with PyShark")
        
        try:
            # Load packets with PyShark
            cap = pyshark.FileCapture(str(pcap_path))
            
            packets = []
            packet_count = 0
            
            for packet in cap:
                packets.append(packet)
                packet_count += 1
                
                if max_packets and packet_count >= max_packets:
                    break
            
            cap.close()
            
            loading_time = time.time() - start_time
            
            # Update stats
            self.stats['files_loaded'] += 1
            self.stats['total_packets_loaded'] += len(packets)
            self.stats['total_loading_time'] += loading_time
            
            # Create metadata
            metadata = {
                'library_used': 'pyshark',
                'loading_time': loading_time,
                'total_packets': len(packets),
                'file_size_bytes': pcap_path.stat().st_size,
                'pyshark_info': {
                    'packet_analysis': self._analyze_packets(packets),
                    'layer_analysis': self._analyze_layers(packets),
                    'frame_types': self._analyze_frame_types(packets),
                }
            }
            
            self.logger.info(
                f"Successfully loaded {len(packets)} packets "
                f"from {pcap_file} in {loading_time:.2f}s"
            )
            
            return packets, metadata
            
        except Exception as e:
            error_msg = f"PyShark parsing error: {e}"
            self.logger.error(error_msg)
            self.stats['errors'].append(error_msg)
            raise ValueError(error_msg) from e
    
    def _analyze_packets(self, packets: List[PySharkPacket]) -> Dict[str, Any]:
        """Analyze packet characteristics."""
        analysis = {
            'total_packets': len(packets),
            'has_wlan': 0,
            'has_radiotap': 0,
            'average_length': 0
        }
        
        total_length = 0
        sample_size = min(100, len(packets))  # Sample first 100 packets
        
        for packet in packets[:sample_size]:
            try:
                if hasattr(packet, 'wlan'):
                    analysis['has_wlan'] += 1
                if hasattr(packet, 'radiotap'):
                    analysis['has_radiotap'] += 1
                
                total_length += int(packet.length)
                
            except Exception:
                continue
        
        if sample_size > 0:
            analysis['average_length'] = total_length / sample_size
            analysis['wlan_percentage'] = (analysis['has_wlan'] / sample_size) * 100
            analysis['radiotap_percentage'] = (analysis['has_radiotap'] / sample_size) * 100
        
        return analysis
    
    def _analyze_layers(self, packets: List[PySharkPacket]) -> Dict[str, int]:
        """Analyze layer distribution in packets."""
        layer_counts = {}
        sample_size = min(50, len(packets))  # Sample first 50 packets
        
        for packet in packets[:sample_size]:
            try:
                for layer in packet.layers:
                    layer_name = layer.layer_name
                    layer_counts[layer_name] = layer_counts.get(layer_name, 0) + 1
            except Exception:
                continue
        
        return layer_counts
    
    def _analyze_frame_types(self, packets: List[PySharkPacket]) -> Dict[str, int]:
        """Analyze 802.11 frame types."""
        frame_types = {}
        sample_size = min(100, len(packets))  # Sample first 100 packets
        
        for packet in packets[:sample_size]:
            try:
                if hasattr(packet, 'wlan_mgt'):
                    # Management frame
                    if hasattr(packet.wlan_mgt, 'fc_type_subtype'):
                        subtype = packet.wlan_mgt.fc_type_subtype
                        frame_name = self._get_frame_name(0, int(subtype))
                        frame_types[frame_name] = frame_types.get(frame_name, 0) + 1
                elif hasattr(packet, 'wlan'):
                    # Other 802.11 frame
                    if hasattr(packet.wlan, 'fc_type'):
                        frame_type = int(packet.wlan.fc_type)
                        subtype = int(packet.wlan.fc_subtype) if hasattr(packet.wlan, 'fc_subtype') else 0
                        frame_name = self._get_frame_name(frame_type, subtype)
                        frame_types[frame_name] = frame_types.get(frame_name, 0) + 1
            except Exception:
                continue
        
        return frame_types
    
    def _get_frame_name(self, frame_type: int, subtype: int) -> str:
        """Get human-readable frame name from type/subtype."""
        if frame_type == 0:  # Management
            management_subtypes = {
                0: 'association_request',
                1: 'association_response',
                2: 'reassociation_request',
                3: 'reassociation_response',
                4: 'probe_request',
                5: 'probe_response',
                8: 'beacon',
                9: 'atim',
                10: 'disassociation',
                11: 'authentication',
                12: 'deauthentication',
                13: 'action',
                14: 'action_no_ack'
            }
            return management_subtypes.get(subtype, f'management_{subtype}')
        elif frame_type == 1:  # Control
            control_subtypes = {
                7: 'control_wrapper',
                8: 'block_ack_request',
                9: 'block_ack',
                10: 'ps_poll',
                11: 'rts',
                12: 'cts',
                13: 'ack',
                14: 'cf_end',
                15: 'cf_end_cf_ack'
            }
            return control_subtypes.get(subtype, f'control_{subtype}')
        elif frame_type == 2:  # Data
            data_subtypes = {
                0: 'data',
                1: 'data_cf_ack',
                2: 'data_cf_poll',
                3: 'data_cf_ack_cf_poll',
                4: 'null',
                5: 'cf_ack',
                6: 'cf_poll',
                7: 'cf_ack_cf_poll',
                8: 'qos_data',
                9: 'qos_data_cf_ack',
                10: 'qos_data_cf_poll',
                11: 'qos_data_cf_ack_cf_poll',
                12: 'qos_null',
                14: 'qos_cf_poll',
                15: 'qos_cf_ack_cf_poll'
            }
            return data_subtypes.get(subtype, f'data_{subtype}')
        else:
            return f'unknown_{frame_type}_{subtype}'
    
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