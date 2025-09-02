"""
Base analyzer classes for the wireless PCAP analysis framework.

This module defines the abstract base analyzer class and category-specific
base classes that all concrete analyzers must inherit from.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Type
from datetime import datetime
import logging

from .models import (
    Finding, 
    AnalysisCategory, 
    AnalysisContext,
    Severity,
    PacketReference,
    FrameType,
    AnalysisError
)

# Scapy imports with error handling
try:
    from scapy.all import Packet
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp
    from scapy.layers.dot11 import Dot11Auth, Dot11AssoReq, Dot11AssoResp
    from scapy.layers.dot11 import Dot11Deauth, Dot11Disas
    from scapy.layers.eap import EAPOL
except ImportError as e:
    raise ImportError(f"Scapy is required for wireless analysis: {e}")


class BaseAnalyzer(ABC):
    """Abstract base class for all wireless packet analyzers."""
    
    def __init__(self, name: str, category: AnalysisCategory, version: str = "1.0"):
        self.name = name
        self.category = category
        self.version = version
        self.enabled = True
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Analyzer metadata
        self.description = ""
        self.wireshark_filters = []
        self.dependencies = []  # Other analyzers this one depends on
        self.analysis_order = 100  # Lower numbers run first
        
        # Performance tracking
        self.packets_processed = 0
        self.processing_time = 0.0
        self.findings_generated = 0
        
    @abstractmethod
    def analyze(self, packets: List[Packet], context: AnalysisContext) -> List[Finding]:
        """
        Analyze packets and return findings.
        
        Args:
            packets: List of packets to analyze
            context: Analysis context with shared data and configuration
            
        Returns:
            List of findings discovered during analysis
            
        Raises:
            AnalysisError: If analysis fails
        """
        pass
    
    def is_applicable(self, packet: Packet) -> bool:
        """
        Check if this analyzer should process the given packet.
        
        Args:
            packet: Packet to check
            
        Returns:
            True if analyzer should process this packet
        """
        return True
    
    def pre_analysis_setup(self, context: AnalysisContext) -> None:
        """
        Setup method called before analysis begins.
        
        Args:
            context: Analysis context
        """
        pass
    
    def post_analysis_cleanup(self, context: AnalysisContext) -> None:
        """
        Cleanup method called after analysis completes.
        
        Args:
            context: Analysis context
        """
        pass
    
    def get_display_filters(self) -> List[str]:
        """
        Get Wireshark display filters relevant to this analyzer.
        
        Returns:
            List of Wireshark filter strings
        """
        return self.wireshark_filters
    
    def get_dependencies(self) -> List[str]:
        """
        Get list of analyzer names this analyzer depends on.
        
        Returns:
            List of analyzer names
        """
        return self.dependencies
    
    def extract_packet_metadata(self, packet: Packet, packet_index: int = 0) -> Dict[str, Any]:
        """
        Extract common metadata from a packet.
        
        Args:
            packet: Packet to extract metadata from
            packet_index: Index of packet in capture
            
        Returns:
            Dictionary of metadata
        """
        metadata = {
            'packet_index': packet_index,
            'timestamp': getattr(packet, 'time', 0.0)
        }
        
        # Basic 802.11 info
        if packet.haslayer(Dot11):
            dot11 = packet[Dot11]
            metadata.update({
                'bssid': self._normalize_mac(dot11.addr3) if dot11.addr3 else None,
                'src_mac': self._normalize_mac(dot11.addr2) if dot11.addr2 else None,
                'dst_mac': self._normalize_mac(dot11.addr1) if dot11.addr1 else None,
                'frame_type': dot11.type,
                'frame_subtype': dot11.subtype,
                'retry': bool(dot11.FCfield & 0x08),
                'to_ds': bool(dot11.FCfield & 0x01),
                'from_ds': bool(dot11.FCfield & 0x02)
            })
            
            # Determine frame type enum
            if dot11.type == 0:
                metadata['frame_type_enum'] = FrameType.MANAGEMENT
            elif dot11.type == 1:
                metadata['frame_type_enum'] = FrameType.CONTROL
            elif dot11.type == 2:
                metadata['frame_type_enum'] = FrameType.DATA
            else:
                metadata['frame_type_enum'] = FrameType.EXTENSION
        
        # Radiotap/PHY info if available
        if hasattr(packet, 'dBm_AntSignal'):
            metadata['rssi'] = packet.dBm_AntSignal
        if hasattr(packet, 'Channel'):
            metadata['channel'] = packet.Channel
        if hasattr(packet, 'Rate'):
            metadata['data_rate'] = packet.Rate
        if hasattr(packet, 'ChannelFrequency'):
            metadata['frequency'] = packet.ChannelFrequency
            
        return metadata
    
    def create_finding(
        self,
        severity: Severity,
        title: str,
        description: str,
        packet_refs: Optional[List[PacketReference]] = None,
        **kwargs
    ) -> Finding:
        """
        Create a finding with analyzer metadata.
        
        Args:
            severity: Severity level
            title: Finding title
            description: Detailed description
            packet_refs: Related packet references
            **kwargs: Additional finding attributes
            
        Returns:
            Finding instance
        """
        finding = Finding(
            category=self.category,
            severity=severity,
            title=title,
            description=description,
            packet_refs=packet_refs or [],
            analyzer_name=self.name,
            analyzer_version=self.version,
            **kwargs
        )
        
        self.findings_generated += 1
        return finding
    
    def _normalize_mac(self, mac: str) -> str:
        """
        Normalize MAC address format.
        
        Args:
            mac: MAC address string
            
        Returns:
            Normalized MAC address
        """
        if not mac:
            return mac
        return mac.lower().replace('-', ':')
    
    def _get_frame_type_name(self, packet: Packet) -> str:
        """
        Get human-readable frame type name.
        
        Args:
            packet: 802.11 packet
            
        Returns:
            Frame type name
        """
        if not packet.haslayer(Dot11):
            return "Unknown"
            
        dot11 = packet[Dot11]
        type_subtype = (dot11.type << 4) | dot11.subtype
        
        frame_types = {
            0x80: "Beacon",
            0x40: "Probe Request", 
            0x50: "Probe Response",
            0x00: "Association Request",
            0x10: "Association Response",
            0x20: "Reassociation Request",
            0x30: "Reassociation Response",
            0xB0: "Authentication",
            0xC0: "Deauthentication",
            0xA0: "Disassociation",
            0x84: "RTS",
            0xC4: "CTS",
            0xD4: "ACK",
            0xE4: "CF-End"
        }
        
        return frame_types.get(type_subtype, f"Type{dot11.type}Subtype{dot11.subtype}")


# Category-specific base classes

class CaptureQualityAnalyzer(BaseAnalyzer):
    """Base class for capture quality and method analysis."""
    
    def __init__(self, name: str, version: str = "1.0"):
        super().__init__(name, AnalysisCategory.CAPTURE_QUALITY, version)
        self.analysis_order = 10  # Run early


class RFPHYAnalyzer(BaseAnalyzer):
    """Base class for RF/PHY layer analysis."""
    
    def __init__(self, name: str, version: str = "1.0"):
        super().__init__(name, AnalysisCategory.RF_PHY, version)
        self.analysis_order = 20


class BeaconAnalyzer(BaseAnalyzer):
    """Base class for beacon frame analysis."""
    
    def __init__(self, name: str, version: str = "1.0"):
        super().__init__(name, AnalysisCategory.BEACONS, version)
        self.wireshark_filters = ["wlan.fc.type_subtype == 8"]
        self.analysis_order = 30
    
    def is_applicable(self, packet: Packet) -> bool:
        return packet.haslayer(Dot11Beacon)


class ProbeAnalyzer(BaseAnalyzer):
    """Base class for probe request/response analysis."""
    
    def __init__(self, name: str, version: str = "1.0"):
        super().__init__(name, AnalysisCategory.PROBE_BEHAVIOR, version)
        self.wireshark_filters = ["wlan.fc.type_subtype == 4", "wlan.fc.type_subtype == 5"]
        self.analysis_order = 40
    
    def is_applicable(self, packet: Packet) -> bool:
        return packet.haslayer(Dot11ProbeReq) or packet.haslayer(Dot11ProbeResp)


class AuthAssocAnalyzer(BaseAnalyzer):
    """Base class for authentication/association analysis."""
    
    def __init__(self, name: str, version: str = "1.0"):
        super().__init__(name, AnalysisCategory.AUTH_ASSOC, version)
        self.wireshark_filters = ["wlan.fc.type_subtype in {11,0,1,2}"]
        self.analysis_order = 50
    
    def is_applicable(self, packet: Packet) -> bool:
        return (packet.haslayer(Dot11Auth) or 
                packet.haslayer(Dot11AssoReq) or 
                packet.haslayer(Dot11AssoResp))


class EnterpriseSecurityAnalyzer(BaseAnalyzer):
    """Base class for 802.1X/EAP/TLS analysis."""
    
    def __init__(self, name: str, version: str = "1.0"):
        super().__init__(name, AnalysisCategory.ENTERPRISE_SECURITY, version)
        self.wireshark_filters = ["eap", "tls", "radius"]
        self.analysis_order = 60


class EAPOLAnalyzer(BaseAnalyzer):
    """Base class for 4-way handshake analysis."""
    
    def __init__(self, name: str, version: str = "1.0"):
        super().__init__(name, AnalysisCategory.EAPOL_HANDSHAKE, version)
        self.wireshark_filters = ["eapol"]
        self.analysis_order = 70
    
    def is_applicable(self, packet: Packet) -> bool:
        return packet.haslayer(EAPOL)


class DataControlAnalyzer(BaseAnalyzer):
    """Base class for data/control plane analysis."""
    
    def __init__(self, name: str, version: str = "1.0"):
        super().__init__(name, AnalysisCategory.DATA_CONTROL_PLANE, version)
        self.wireshark_filters = ["wlan.fc.type == 1", "wlan.ba", "wlan.rts", "wlan.cts"]
        self.analysis_order = 80


class QoSAnalyzer(BaseAnalyzer):
    """Base class for QoS/WMM analysis."""
    
    def __init__(self, name: str, version: str = "1.0"):
        super().__init__(name, AnalysisCategory.QOS_WMM, version)
        self.wireshark_filters = ["wlan.qos", "rtp", "sip"]
        self.analysis_order = 90


class PowerSaveAnalyzer(BaseAnalyzer):
    """Base class for power save analysis."""
    
    def __init__(self, name: str, version: str = "1.0"):
        super().__init__(name, AnalysisCategory.POWER_SAVE, version)
        self.wireshark_filters = ["wlan.tim", "wlan.twt"]
        self.analysis_order = 100


class RoamingAnalyzer(BaseAnalyzer):
    """Base class for roaming and steering analysis."""
    
    def __init__(self, name: str, version: str = "1.0"):
        super().__init__(name, AnalysisCategory.ROAMING_STEERING, version)
        self.wireshark_filters = ["wlan.mgt.btm", "wlan.mgt.measurement", "wlan.mgt.ft"]
        self.analysis_order = 110


class MulticastAnalyzer(BaseAnalyzer):
    """Base class for multicast/broadcast analysis."""
    
    def __init__(self, name: str, version: str = "1.0"):
        super().__init__(name, AnalysisCategory.MULTICAST_BROADCAST, version)
        self.wireshark_filters = [
            "arp", 
            "udp.port in {5353, 1900, 5355}", 
            "icmpv6 and (nd or router)"
        ]
        self.analysis_order = 120


class IPOnboardingAnalyzer(BaseAnalyzer):
    """Base class for IP layer onboarding analysis."""
    
    def __init__(self, name: str, version: str = "1.0"):
        super().__init__(name, AnalysisCategory.IP_ONBOARDING, version)
        self.wireshark_filters = ["dhcp", "bootp", "dns", "arp", "icmpv6"]
        self.analysis_order = 130


class CoexistenceAnalyzer(BaseAnalyzer):
    """Base class for coexistence and DFS analysis."""
    
    def __init__(self, name: str, version: str = "1.0"):
        super().__init__(name, AnalysisCategory.COEXISTENCE_DFS, version)
        self.wireshark_filters = ["wlan.mgt.tag.number == 37"]  # ERP
        self.analysis_order = 140


class SecurityThreatAnalyzer(BaseAnalyzer):
    """Base class for security threat detection."""
    
    def __init__(self, name: str, version: str = "1.0"):
        super().__init__(name, AnalysisCategory.SECURITY_THREATS, version)
        self.wireshark_filters = ["wlan.fc.type_subtype in {12,10}"]  # deauth/disassoc
        self.analysis_order = 150
    
    def is_applicable(self, packet: Packet) -> bool:
        return packet.haslayer(Dot11Deauth) or packet.haslayer(Dot11Disas)


class Band6GHzAnalyzer(BaseAnalyzer):
    """Base class for 6 GHz band specific analysis."""
    
    def __init__(self, name: str, version: str = "1.0"):
        super().__init__(name, AnalysisCategory.BAND_6GHZ, version)
        self.wireshark_filters = ["wlan_radio.frequency >= 5925"]
        self.analysis_order = 160


class MLOAnalyzer(BaseAnalyzer):
    """Base class for 802.11be MLO analysis."""
    
    def __init__(self, name: str, version: str = "1.0"):
        super().__init__(name, AnalysisCategory.MLO_BE, version)
        self.wireshark_filters = ["wlan.mgt.multi_link"]
        self.analysis_order = 170


class ClientProfilingAnalyzer(BaseAnalyzer):
    """Base class for client capability profiling."""
    
    def __init__(self, name: str, version: str = "1.0"):
        super().__init__(name, AnalysisCategory.CLIENT_PROFILING, version)
        self.analysis_order = 180


class APBehaviorAnalyzer(BaseAnalyzer):
    """Base class for AP behavior analysis."""
    
    def __init__(self, name: str, version: str = "1.0"):
        super().__init__(name, AnalysisCategory.AP_BEHAVIOR, version)
        self.analysis_order = 190


class ApplicationPerformanceAnalyzer(BaseAnalyzer):
    """Base class for application performance analysis."""
    
    def __init__(self, name: str, version: str = "1.0"):
        super().__init__(name, AnalysisCategory.APP_PERFORMANCE, version)
        self.wireshark_filters = ["tcp.analysis", "quic", "rtp"]
        self.analysis_order = 200


class HotspotAnalyzer(BaseAnalyzer):
    """Base class for Hotspot 2.0/Passpoint analysis."""
    
    def __init__(self, name: str, version: str = "1.0"):
        super().__init__(name, AnalysisCategory.HOTSPOT_PASSPOINT, version)
        self.wireshark_filters = ["wlan.gs.*", "anqp"]
        self.analysis_order = 210


class MetricsAnalyzer(BaseAnalyzer):
    """Base class for metrics computation."""
    
    def __init__(self, name: str, version: str = "1.0"):
        super().__init__(name, AnalysisCategory.METRICS_COMPUTATION, version)
        self.analysis_order = 220


class AnomalyAnalyzer(BaseAnalyzer):
    """Base class for anomaly detection."""
    
    def __init__(self, name: str, version: str = "1.0"):
        super().__init__(name, AnalysisCategory.ANOMALY_DETECTION, version)
        self.analysis_order = 230  # Run last to see patterns across all data


# Utility class for analyzer registration and management
class AnalyzerRegistry:
    """Registry for managing analyzer instances."""
    
    def __init__(self):
        self._analyzers: Dict[str, BaseAnalyzer] = {}
        self._categories: Dict[AnalysisCategory, List[BaseAnalyzer]] = {
            category: [] for category in AnalysisCategory
        }
        
    def register(self, analyzer: BaseAnalyzer) -> None:
        """
        Register an analyzer.
        
        Args:
            analyzer: Analyzer instance to register
        """
        self._analyzers[analyzer.name] = analyzer
        self._categories[analyzer.category].append(analyzer)
        
    def get_analyzer(self, name: str) -> Optional[BaseAnalyzer]:
        """
        Get analyzer by name.
        
        Args:
            name: Analyzer name
            
        Returns:
            Analyzer instance or None
        """
        return self._analyzers.get(name)
        
    def get_analyzers_by_category(self, category: AnalysisCategory) -> List[BaseAnalyzer]:
        """
        Get all analyzers in a category.
        
        Args:
            category: Analysis category
            
        Returns:
            List of analyzers
        """
        return self._categories.get(category, [])
        
    def get_enabled_analyzers(self) -> List[BaseAnalyzer]:
        """
        Get all enabled analyzers sorted by analysis order.
        
        Returns:
            List of enabled analyzers
        """
        enabled = [a for a in self._analyzers.values() if a.enabled]
        return sorted(enabled, key=lambda x: x.analysis_order)
        
    def get_all_analyzers(self) -> List[BaseAnalyzer]:
        """
        Get all registered analyzers.
        
        Returns:
            List of all analyzers
        """
        return list(self._analyzers.values())
        
    def disable_analyzer(self, name: str) -> None:
        """
        Disable an analyzer.
        
        Args:
            name: Analyzer name
        """
        if name in self._analyzers:
            self._analyzers[name].enabled = False
            
    def enable_analyzer(self, name: str) -> None:
        """
        Enable an analyzer.
        
        Args:
            name: Analyzer name
        """
        if name in self._analyzers:
            self._analyzers[name].enabled = True
