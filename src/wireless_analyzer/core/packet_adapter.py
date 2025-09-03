"""
Universal Packet Adapter for Multi-Parser Support

This module provides a unified interface for analyzing packets from different parsers
(Scapy, PyShark, dpkt) so that analyzers can work with any packet type transparently.
"""

from typing import Any, Optional, Dict, List, Union
from abc import ABC, abstractmethod
import logging

# Import all parser types conditionally
try:
    from scapy.all import Packet as ScapyPacket
    from scapy.layers.dot11 import Dot11, RadioTap, Dot11Beacon, Dot11ProbeReq, Dot11Auth, Dot11Deauth
    from scapy.layers.eap import EAPOL, EAP
    SCAPY_AVAILABLE = True
except ImportError:
    ScapyPacket = None
    SCAPY_AVAILABLE = False

try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False

try:
    import dpkt
    DPKT_AVAILABLE = True
except ImportError:
    DPKT_AVAILABLE = False


class PacketAdapter(ABC):
    """
    Abstract base class for packet adapters.
    Provides unified interface for different packet types.
    """
    
    def __init__(self, raw_packet: Any):
        self.raw_packet = raw_packet
        self._cache = {}  # Cache expensive operations
        self.logger = logging.getLogger(__name__)
        
    @abstractmethod
    def haslayer(self, layer_name: str) -> bool:
        """Check if packet has specified layer."""
        pass
        
    @abstractmethod
    def get_layer(self, layer_name: str) -> Optional[Any]:
        """Get specified layer from packet."""
        pass
        
    @abstractmethod
    def get_field(self, layer_name: str, field_name: str) -> Optional[Any]:
        """Get field value from specified layer."""
        pass
        
    @abstractmethod 
    def get_packet_type(self) -> str:
        """Get packet parser type (scapy, pyshark, dpkt)."""
        pass
        
    # Common 802.11 field accessors
    def get_src_mac(self) -> Optional[str]:
        """Get source MAC address."""
        if 'src_mac' not in self._cache:
            self._cache['src_mac'] = self._extract_src_mac()
        return self._cache['src_mac']
        
    def get_dst_mac(self) -> Optional[str]:
        """Get destination MAC address."""
        if 'dst_mac' not in self._cache:
            self._cache['dst_mac'] = self._extract_dst_mac()
        return self._cache['dst_mac']
        
    def get_bssid(self) -> Optional[str]:
        """Get BSSID."""
        if 'bssid' not in self._cache:
            self._cache['bssid'] = self._extract_bssid()
        return self._cache['bssid']
        
    def get_frame_type(self) -> Optional[int]:
        """Get 802.11 frame type."""
        if 'frame_type' not in self._cache:
            self._cache['frame_type'] = self._extract_frame_type()
        return self._cache['frame_type']
        
    def get_frame_subtype(self) -> Optional[int]:
        """Get 802.11 frame subtype.""" 
        if 'frame_subtype' not in self._cache:
            self._cache['frame_subtype'] = self._extract_frame_subtype()
        return self._cache['frame_subtype']
        
    def get_ssid(self) -> Optional[str]:
        """Get SSID from management frames."""
        if 'ssid' not in self._cache:
            self._cache['ssid'] = self._extract_ssid()
        return self._cache['ssid']
        
    def get_rssi(self) -> Optional[int]:
        """Get RSSI from RadioTap."""
        if 'rssi' not in self._cache:
            self._cache['rssi'] = self._extract_rssi()
        return self._cache['rssi']
        
    def get_channel(self) -> Optional[int]:
        """Get channel from RadioTap."""
        if 'channel' not in self._cache:
            self._cache['channel'] = self._extract_channel()
        return self._cache['channel']
        
    def get_timestamp(self) -> Optional[float]:
        """Get packet timestamp."""
        if 'timestamp' not in self._cache:
            self._cache['timestamp'] = self._extract_timestamp()
        return self._cache['timestamp']
        
    # Abstract methods for field extraction (implemented by subclasses)
    @abstractmethod
    def _extract_src_mac(self) -> Optional[str]:
        pass
        
    @abstractmethod
    def _extract_dst_mac(self) -> Optional[str]:
        pass
        
    @abstractmethod
    def _extract_bssid(self) -> Optional[str]:
        pass
        
    @abstractmethod
    def _extract_frame_type(self) -> Optional[int]:
        pass
        
    @abstractmethod
    def _extract_frame_subtype(self) -> Optional[int]:
        pass
        
    @abstractmethod
    def _extract_ssid(self) -> Optional[str]:
        pass
        
    @abstractmethod
    def _extract_rssi(self) -> Optional[int]:
        pass
        
    @abstractmethod
    def _extract_channel(self) -> Optional[int]:
        pass
        
    @abstractmethod
    def _extract_timestamp(self) -> Optional[float]:
        pass


class ScapyPacketAdapter(PacketAdapter):
    """Adapter for Scapy packets."""
    
    def haslayer(self, layer_name: str) -> bool:
        """Check if packet has specified layer."""
        try:
            if layer_name == "Dot11":
                return self.raw_packet.haslayer(Dot11)
            elif layer_name == "RadioTap":
                return self.raw_packet.haslayer(RadioTap)
            elif layer_name == "EAPOL":
                return self.raw_packet.haslayer(EAPOL)
            elif layer_name == "EAP":
                return self.raw_packet.haslayer(EAP)
            elif layer_name == "Dot11Beacon":
                return self.raw_packet.haslayer(Dot11Beacon)
            elif layer_name == "Dot11ProbeReq":
                return self.raw_packet.haslayer(Dot11ProbeReq)
            elif layer_name == "Dot11Auth":
                return self.raw_packet.haslayer(Dot11Auth)
            elif layer_name == "Dot11Deauth":
                return self.raw_packet.haslayer(Dot11Deauth)
            else:
                # Generic layer check
                return hasattr(self.raw_packet, 'haslayer') and self.raw_packet.haslayer(layer_name)
        except Exception:
            return False
            
    def get_layer(self, layer_name: str) -> Optional[Any]:
        """Get specified layer from packet."""
        try:
            if self.haslayer(layer_name):
                if layer_name == "Dot11":
                    return self.raw_packet[Dot11]
                elif layer_name == "RadioTap":
                    return self.raw_packet[RadioTap]
                elif layer_name == "EAPOL":
                    return self.raw_packet[EAPOL]
                elif layer_name == "EAP":
                    return self.raw_packet[EAP]
                else:
                    return self.raw_packet[layer_name]
        except Exception:
            return None
            
    def get_field(self, layer_name: str, field_name: str) -> Optional[Any]:
        """Get field value from specified layer."""
        try:
            layer = self.get_layer(layer_name)
            if layer and hasattr(layer, field_name):
                return getattr(layer, field_name)
        except Exception:
            pass
        return None
        
    def get_packet_type(self) -> str:
        return "scapy"
        
    def _extract_src_mac(self) -> Optional[str]:
        try:
            if self.haslayer("Dot11"):
                dot11 = self.get_layer("Dot11")
                if hasattr(dot11, 'addr2') and dot11.addr2:
                    return str(dot11.addr2).lower()
        except Exception:
            pass
        return None
        
    def _extract_dst_mac(self) -> Optional[str]:
        try:
            if self.haslayer("Dot11"):
                dot11 = self.get_layer("Dot11")
                if hasattr(dot11, 'addr1') and dot11.addr1:
                    return str(dot11.addr1).lower()
        except Exception:
            pass
        return None
        
    def _extract_bssid(self) -> Optional[str]:
        try:
            if self.haslayer("Dot11"):
                dot11 = self.get_layer("Dot11")
                if hasattr(dot11, 'addr3') and dot11.addr3:
                    return str(dot11.addr3).lower()
        except Exception:
            pass
        return None
        
    def _extract_frame_type(self) -> Optional[int]:
        return self.get_field("Dot11", "type")
        
    def _extract_frame_subtype(self) -> Optional[int]:
        return self.get_field("Dot11", "subtype")
        
    def _extract_ssid(self) -> Optional[str]:
        try:
            if hasattr(self.raw_packet, 'info') and self.raw_packet.info:
                ssid_bytes = self.raw_packet.info
                if isinstance(ssid_bytes, bytes):
                    return ssid_bytes.decode('utf-8', errors='ignore')
                return str(ssid_bytes)
        except Exception:
            pass
        return None
        
    def _extract_rssi(self) -> Optional[int]:
        try:
            if self.haslayer("RadioTap"):
                radiotap = self.get_layer("RadioTap")
                if hasattr(radiotap, 'dBm_AntSignal'):
                    return int(radiotap.dBm_AntSignal)
                elif hasattr(radiotap, 'dbm_antsignal'):
                    return int(radiotap.dbm_antsignal)
        except Exception:
            pass
        return None
        
    def _extract_channel(self) -> Optional[int]:
        try:
            if self.haslayer("RadioTap"):
                radiotap = self.get_layer("RadioTap")
                if hasattr(radiotap, 'Channel'):
                    return int(radiotap.Channel)
                elif hasattr(radiotap, 'ChannelFrequency'):
                    freq = int(radiotap.ChannelFrequency)
                    return self._freq_to_channel(freq)
        except Exception:
            pass
        return None
        
    def _extract_timestamp(self) -> Optional[float]:
        try:
            if hasattr(self.raw_packet, 'time'):
                return float(self.raw_packet.time)
        except Exception:
            pass
        return None
        
    def _freq_to_channel(self, frequency: int) -> Optional[int]:
        """Convert frequency to 802.11 channel number."""
        if 2412 <= frequency <= 2484:
            if frequency == 2484:
                return 14
            return (frequency - 2407) // 5
        elif 5000 <= frequency <= 6000:
            return (frequency - 5000) // 5
        return None


class PySharkPacketAdapter(PacketAdapter):
    """Adapter for PyShark packets."""
    
    def haslayer(self, layer_name: str) -> bool:
        """Check if packet has specified layer."""
        try:
            layer_map = {
                "Dot11": "wlan",
                "RadioTap": "radiotap", 
                "EAPOL": "eapol",
                "EAP": "eap",
                "Dot11Beacon": "wlan",  # Check frame type separately
                "Dot11ProbeReq": "wlan",
                "Dot11Auth": "wlan",
                "Dot11Deauth": "wlan"
            }
            
            mapped_layer = layer_map.get(layer_name, layer_name.lower())
            has_layer = hasattr(self.raw_packet, mapped_layer)
            
            # For specific frame types, check subtype
            if has_layer and layer_name in ["Dot11Beacon", "Dot11ProbeReq", "Dot11Auth", "Dot11Deauth"]:
                return self._check_frame_subtype(layer_name)
                
            return has_layer
        except Exception:
            return False
            
    def _check_frame_subtype(self, frame_type: str) -> bool:
        """Check if WLAN frame matches specific subtype."""
        try:
            if not hasattr(self.raw_packet, 'wlan'):
                return False
                
            wlan = self.raw_packet.wlan
            fc_type = getattr(wlan, 'fc_type', None)
            fc_subtype = getattr(wlan, 'fc_subtype', None)
            
            if fc_type == '0':  # Management frame
                if frame_type == "Dot11Beacon" and fc_subtype == '8':
                    return True
                elif frame_type == "Dot11ProbeReq" and fc_subtype == '4':
                    return True
                elif frame_type == "Dot11Auth" and fc_subtype == '11':
                    return True
                elif frame_type == "Dot11Deauth" and fc_subtype == '12':
                    return True
                    
        except Exception:
            pass
        return False
            
    def get_layer(self, layer_name: str) -> Optional[Any]:
        """Get specified layer from packet."""
        try:
            layer_map = {
                "Dot11": "wlan",
                "RadioTap": "radiotap",
                "EAPOL": "eapol", 
                "EAP": "eap"
            }
            
            mapped_layer = layer_map.get(layer_name, layer_name.lower())
            if hasattr(self.raw_packet, mapped_layer):
                return getattr(self.raw_packet, mapped_layer)
        except Exception:
            pass
        return None
        
    def get_field(self, layer_name: str, field_name: str) -> Optional[Any]:
        """Get field value from specified layer."""
        try:
            layer = self.get_layer(layer_name)
            if layer and hasattr(layer, field_name):
                return getattr(layer, field_name)
        except Exception:
            pass
        return None
        
    def get_packet_type(self) -> str:
        return "pyshark"
        
    def _extract_src_mac(self) -> Optional[str]:
        try:
            if hasattr(self.raw_packet, 'wlan'):
                return getattr(self.raw_packet.wlan, 'sa', None)
        except Exception:
            pass
        return None
        
    def _extract_dst_mac(self) -> Optional[str]:
        try:
            if hasattr(self.raw_packet, 'wlan'):
                return getattr(self.raw_packet.wlan, 'da', None)
        except Exception:
            pass
        return None
        
    def _extract_bssid(self) -> Optional[str]:
        try:
            if hasattr(self.raw_packet, 'wlan'):
                return getattr(self.raw_packet.wlan, 'bssid', None)
        except Exception:
            pass
        return None
        
    def _extract_frame_type(self) -> Optional[int]:
        try:
            if hasattr(self.raw_packet, 'wlan'):
                fc_type = getattr(self.raw_packet.wlan, 'fc_type', None)
                return int(fc_type) if fc_type is not None else None
        except Exception:
            pass
        return None
        
    def _extract_frame_subtype(self) -> Optional[int]:
        try:
            if hasattr(self.raw_packet, 'wlan'):
                fc_subtype = getattr(self.raw_packet.wlan, 'fc_subtype', None)
                return int(fc_subtype) if fc_subtype is not None else None
        except Exception:
            pass
        return None
        
    def _extract_ssid(self) -> Optional[str]:
        try:
            if hasattr(self.raw_packet, 'wlan'):
                return getattr(self.raw_packet.wlan, 'ssid', None)
        except Exception:
            pass
        return None
        
    def _extract_rssi(self) -> Optional[int]:
        try:
            if hasattr(self.raw_packet, 'radiotap'):
                rssi = getattr(self.raw_packet.radiotap, 'dbm_antsignal', None)
                return int(rssi) if rssi is not None else None
        except Exception:
            pass
        return None
        
    def _extract_channel(self) -> Optional[int]:
        try:
            if hasattr(self.raw_packet, 'wlan'):
                channel = getattr(self.raw_packet.wlan, 'channel', None)
                if channel:
                    return int(channel)
            # Fallback to RadioTap frequency conversion
            if hasattr(self.raw_packet, 'radiotap'):
                freq = getattr(self.raw_packet.radiotap, 'channel_freq', None)
                if freq:
                    return self._freq_to_channel(int(freq))
        except Exception:
            pass
        return None
        
    def _extract_timestamp(self) -> Optional[float]:
        try:
            if hasattr(self.raw_packet, 'sniff_time'):
                return float(self.raw_packet.sniff_time.timestamp())
        except Exception:
            pass
        return None
        
    def _freq_to_channel(self, frequency: int) -> Optional[int]:
        """Convert frequency to 802.11 channel number."""
        if 2412 <= frequency <= 2484:
            if frequency == 2484:
                return 14
            return (frequency - 2407) // 5
        elif 5000 <= frequency <= 6000:
            return (frequency - 5000) // 5
        return None


class DpktPacketAdapter(PacketAdapter):
    """Adapter for dpkt packets (basic implementation)."""
    
    def haslayer(self, layer_name: str) -> bool:
        """Check if packet has specified layer (basic dpkt implementation)."""
        # dpkt implementation would be more complex and specific
        # For now, return False for most layers
        return False
        
    def get_layer(self, layer_name: str) -> Optional[Any]:
        """Get specified layer from packet."""
        return None
        
    def get_field(self, layer_name: str, field_name: str) -> Optional[Any]:
        """Get field value from specified layer."""
        return None
        
    def get_packet_type(self) -> str:
        return "dpkt"
        
    # Basic dpkt implementations (would need full 802.11 parsing)
    def _extract_src_mac(self) -> Optional[str]:
        return None
        
    def _extract_dst_mac(self) -> Optional[str]:
        return None
        
    def _extract_bssid(self) -> Optional[str]:
        return None
        
    def _extract_frame_type(self) -> Optional[int]:
        return None
        
    def _extract_frame_subtype(self) -> Optional[int]:
        return None
        
    def _extract_ssid(self) -> Optional[str]:
        return None
        
    def _extract_rssi(self) -> Optional[int]:
        return None
        
    def _extract_channel(self) -> Optional[int]:
        return None
        
    def _extract_timestamp(self) -> Optional[float]:
        return None


def create_packet_adapter(packet: Any) -> PacketAdapter:
    """
    Factory function to create appropriate packet adapter.
    
    Args:
        packet: Raw packet from any parser
        
    Returns:
        Appropriate PacketAdapter subclass
    """
    # Detect packet type and create appropriate adapter
    if SCAPY_AVAILABLE and isinstance(packet, ScapyPacket):
        return ScapyPacketAdapter(packet)
    elif PYSHARK_AVAILABLE and hasattr(packet, '__class__') and 'pyshark' in str(packet.__class__):
        return PySharkPacketAdapter(packet)
    elif DPKT_AVAILABLE and isinstance(packet, (bytes, bytearray)):
        return DpktPacketAdapter(packet)
    else:
        # Try to detect by available methods
        if hasattr(packet, 'haslayer'):
            return ScapyPacketAdapter(packet)
        elif hasattr(packet, 'wlan') or hasattr(packet, 'radiotap'):
            return PySharkPacketAdapter(packet)
        else:
            # Default to Scapy adapter with error handling
            return ScapyPacketAdapter(packet)


def adapt_packet(packet: Any) -> PacketAdapter:
    """
    Convenience function to create packet adapter.
    
    Args:
        packet: Raw packet from any parser
        
    Returns:
        PacketAdapter instance
    """
    return create_packet_adapter(packet)