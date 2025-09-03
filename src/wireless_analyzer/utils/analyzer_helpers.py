"""
Helper functions for analyzers to work with multi-parser packet support.

This module provides convenience functions that allow existing analyzers
to work with packets from any parser (Scapy, PyShark, dpkt) with minimal changes.
"""

from typing import Any, List, Optional
from ..core.packet_adapter import adapt_packet, PacketAdapter


def packet_has_layer(packet: Any, layer_name: str) -> bool:
    """
    Check if packet has specified layer, works with any packet type.
    
    Args:
        packet: Raw packet from any parser
        layer_name: Layer name to check for
        
    Returns:
        True if packet has the layer
        
    Example:
        # Instead of: packet.haslayer(Dot11)
        # Use: packet_has_layer(packet, "Dot11") 
    """
    try:
        adapter = adapt_packet(packet)
        return adapter.haslayer(layer_name)
    except Exception:
        return False


def get_packet_layer(packet: Any, layer_name: str) -> Optional[Any]:
    """
    Get layer from packet, works with any packet type.
    
    Args:
        packet: Raw packet from any parser
        layer_name: Layer name to get
        
    Returns:
        Layer object or None
        
    Example:
        # Instead of: dot11 = packet[Dot11]
        # Use: dot11 = get_packet_layer(packet, "Dot11")
    """
    try:
        adapter = adapt_packet(packet)
        return adapter.get_layer(layer_name)
    except Exception:
        return None


def get_packet_field(packet: Any, layer_name: str, field_name: str) -> Optional[Any]:
    """
    Get field value from packet layer, works with any packet type.
    
    Args:
        packet: Raw packet from any parser
        layer_name: Layer name
        field_name: Field name within layer
        
    Returns:
        Field value or None
        
    Example:
        # Instead of: frame_type = packet[Dot11].type
        # Use: frame_type = get_packet_field(packet, "Dot11", "type")
    """
    try:
        adapter = adapt_packet(packet)
        return adapter.get_field(layer_name, field_name)
    except Exception:
        return None


def get_src_mac(packet: Any) -> Optional[str]:
    """Get source MAC address from any packet type."""
    try:
        adapter = adapt_packet(packet)
        return adapter.get_src_mac()
    except Exception:
        return None


def get_dst_mac(packet: Any) -> Optional[str]:
    """Get destination MAC address from any packet type."""
    try:
        adapter = adapt_packet(packet)
        return adapter.get_dst_mac()
    except Exception:
        return None


def get_bssid(packet: Any) -> Optional[str]:
    """Get BSSID from any packet type."""
    try:
        adapter = adapt_packet(packet)
        return adapter.get_bssid()
    except Exception:
        return None


def get_frame_type(packet: Any) -> Optional[int]:
    """Get 802.11 frame type from any packet type."""
    try:
        adapter = adapt_packet(packet)
        return adapter.get_frame_type()
    except Exception:
        return None


def get_frame_subtype(packet: Any) -> Optional[int]:
    """Get 802.11 frame subtype from any packet type."""
    try:
        adapter = adapt_packet(packet)
        return adapter.get_frame_subtype()
    except Exception:
        return None


def get_ssid(packet: Any) -> Optional[str]:
    """Get SSID from any packet type."""
    try:
        adapter = adapt_packet(packet)
        return adapter.get_ssid()
    except Exception:
        return None


def get_rssi(packet: Any) -> Optional[int]:
    """Get RSSI from any packet type."""
    try:
        adapter = adapt_packet(packet)
        return adapter.get_rssi()
    except Exception:
        return None


def get_channel(packet: Any) -> Optional[int]:
    """Get channel from any packet type."""
    try:
        adapter = adapt_packet(packet)
        return adapter.get_channel()
    except Exception:
        return None


def get_timestamp(packet: Any) -> Optional[float]:
    """Get timestamp from any packet type."""
    try:
        adapter = adapt_packet(packet)
        return adapter.get_timestamp()
    except Exception:
        return None


def get_packet_type(packet: Any) -> str:
    """Get packet parser type (scapy, pyshark, dpkt)."""
    try:
        adapter = adapt_packet(packet)
        return adapter.get_packet_type()
    except Exception:
        return "unknown"


def filter_packets_by_layer(packets: List[Any], layer_name: str) -> List[Any]:
    """
    Filter packets that have specified layer.
    
    Args:
        packets: List of packets from any parser
        layer_name: Layer to filter by
        
    Returns:
        List of packets that have the specified layer
        
    Example:
        # Instead of: [p for p in packets if p.haslayer(Dot11)]
        # Use: filter_packets_by_layer(packets, "Dot11")
    """
    filtered = []
    for packet in packets:
        if packet_has_layer(packet, layer_name):
            filtered.append(packet)
    return filtered


# Convenience functions for common layer checks
def is_dot11_packet(packet: Any) -> bool:
    """Check if packet is 802.11."""
    return packet_has_layer(packet, "Dot11")


def is_beacon_packet(packet: Any) -> bool:
    """Check if packet is beacon frame."""
    return packet_has_layer(packet, "Dot11Beacon")


def is_probe_request_packet(packet: Any) -> bool:
    """Check if packet is probe request."""
    return packet_has_layer(packet, "Dot11ProbeReq")


def is_deauth_packet(packet: Any) -> bool:
    """Check if packet is deauth frame."""
    return packet_has_layer(packet, "Dot11Deauth")


def is_eapol_packet(packet: Any) -> bool:
    """Check if packet contains EAPOL."""
    return packet_has_layer(packet, "EAPOL")


def is_eap_packet(packet: Any) -> bool:
    """Check if packet contains EAP."""
    return packet_has_layer(packet, "EAP")


def has_radiotap(packet: Any) -> bool:
    """Check if packet has RadioTap header."""
    return packet_has_layer(packet, "RadioTap")


# Migration helper for existing analyzers
class CompatibilityHelper:
    """
    Helper class to make existing analyzers work with new packet system.
    Provides backward compatibility for analyzers written for Scapy.
    """
    
    @staticmethod
    def make_packet_compatible(packet: Any) -> Any:
        """
        Add compatibility methods to packet for existing analyzers.
        
        This dynamically adds haslayer() and other methods to non-Scapy packets
        so existing analyzer code continues to work.
        """
        if hasattr(packet, 'haslayer'):
            # Already a Scapy packet, return as-is
            return packet
            
        # Create adapter and add compatibility methods
        adapter = adapt_packet(packet)
        
        # Add haslayer method
        packet.haslayer = lambda layer_name: adapter.haslayer(layer_name)
        
        # Add layer access methods
        def get_layer_method(layer_name):
            return adapter.get_layer(layer_name)
        packet.__getitem__ = lambda layer_name: get_layer_method(layer_name)
        
        # Add common field access
        packet._adapter = adapter
        
        return packet
        
    @staticmethod
    def adapt_packet_list(packets: List[Any]) -> List[Any]:
        """
        Make a list of packets compatible with existing analyzer code.
        
        Args:
            packets: List of packets from any parser
            
        Returns:
            List of packets with compatibility methods added
        """
        return [CompatibilityHelper.make_packet_compatible(p) for p in packets]


# Quick migration functions for common patterns
def migrate_haslayer_check(packet: Any, layer_name: str) -> bool:
    """
    Drop-in replacement for packet.haslayer() calls.
    
    Usage:
        # Old: if packet.haslayer(Dot11):
        # New: if migrate_haslayer_check(packet, "Dot11"):
    """
    return packet_has_layer(packet, layer_name)


def migrate_layer_access(packet: Any, layer_name: str) -> Optional[Any]:
    """
    Drop-in replacement for packet[Layer] access.
    
    Usage:
        # Old: dot11 = packet[Dot11]
        # New: dot11 = migrate_layer_access(packet, "Dot11")
    """
    return get_packet_layer(packet, layer_name)