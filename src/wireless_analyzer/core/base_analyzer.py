"""
Base analyzer classes for the wireless PCAP analysis framework.

This module defines the abstract base analyzer class and parser-specific
base classes that all concrete analyzers must inherit from.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Type, Union
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


class AbstractBaseAnalyzer(ABC):
    """Abstract base class for all wireless packet analyzers (parser-agnostic)."""
    
    def __init__(self, name: str = None, category: AnalysisCategory = None, version: str = "1.0"):
        # Allow subclasses to set these later for backward compatibility
        self.name = name or getattr(self, 'name', self.__class__.__name__)
        self.category = category or getattr(self, 'category', AnalysisCategory.ANOMALY_DETECTION)
        self.version = version
        self.enabled = True
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Analyzer metadata
        self.description = getattr(self, 'description', "")
        self.wireshark_filters = getattr(self, 'wireshark_filters', [])
        self.dependencies = getattr(self, 'dependencies', [])  # Other analyzers this one depends on
        self.analysis_order = getattr(self, 'analysis_order', 100)  # Lower numbers run first
        
        # Performance tracking
        self.packets_processed = 0
        self.processing_time = 0.0
        self.findings_generated = 0
        
    @abstractmethod
    def analyze(self, packets: List[Any], context: AnalysisContext) -> List[Finding]:
        """
        Analyze packets and return findings.
        
        Args:
            packets: List of packets to analyze (parser-specific type)
            context: Analysis context with shared data and configuration
            
        Returns:
            List of findings discovered during analysis
            
        Raises:
            AnalysisError: If analysis fails
        """
        pass
    
    @abstractmethod
    def is_applicable(self, packet: Any) -> bool:
        """
        Check if this analyzer should process the given packet.
        
        Args:
            packet: Packet to check (parser-specific type)
            
        Returns:
            True if analyzer should process this packet
        """
        pass
    
    @abstractmethod
    def extract_packet_metadata(self, packet: Any, packet_index: int = 0) -> Dict[str, Any]:
        """
        Extract common metadata from a packet.
        
        Args:
            packet: Packet to extract metadata from (parser-specific type)
            packet_index: Index of packet in capture
            
        Returns:
            Dictionary of metadata
        """
        pass
    
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


# ============================================================================
# SCAPY-SPECIFIC BASE ANALYZER
# ============================================================================

# Scapy imports with error handling
try:
    from scapy.all import Packet
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp
    from scapy.layers.dot11 import Dot11Auth, Dot11AssoReq, Dot11AssoResp
    from scapy.layers.dot11 import Dot11Deauth, Dot11Disas
    from scapy.layers.eap import EAPOL
    SCAPY_AVAILABLE = True
except ImportError as e:
    SCAPY_AVAILABLE = False
    Packet = None


class BaseScapyAnalyzer(AbstractBaseAnalyzer):
    """Base class for all Scapy-based wireless packet analyzers."""
    
    def __init__(self, name: str = None, category: AnalysisCategory = None, version: str = "1.0"):
        super().__init__(name, category, version)
        
        if not SCAPY_AVAILABLE:
            self.logger.warning("Scapy not available - analyzer will not function")
        
    def analyze(self, packets: List[Packet], context: AnalysisContext) -> List[Finding]:
        """
        Analyze Scapy packets and return findings.
        
        Args:
            packets: List of Scapy packets to analyze
            context: Analysis context with shared data and configuration
            
        Returns:
            List of findings discovered during analysis
            
        Raises:
            AnalysisError: If analysis fails
        """
        if not SCAPY_AVAILABLE:
            return []
            
        # Default implementation that calls analyze_packet if available
        findings = []
        
        if hasattr(self, 'analyze_packet') and callable(self.analyze_packet):
            for packet in packets:
                try:
                    packet_findings = self.analyze_packet(packet)
                    if packet_findings:
                        findings.extend(packet_findings)
                except Exception as e:
                    self.logger.debug(f"Error analyzing packet: {e}")
                    continue
        else:
            # If no analyze_packet method, subclass should override this method
            raise NotImplementedError(f"{self.__class__.__name__} must implement either analyze() or analyze_packet() method")
        
        return findings
    
    def is_applicable(self, packet: Packet) -> bool:
        """
        Check if this analyzer should process the given Scapy packet.
        
        Args:
            packet: Scapy packet to check
            
        Returns:
            True if analyzer should process this packet
        """
        return True
    
    def extract_packet_metadata(self, packet: Packet, packet_index: int = 0) -> Dict[str, Any]:
        """
        Extract common metadata from a Scapy packet.
        
        Args:
            packet: Scapy packet to extract metadata from
            packet_index: Index of packet in capture
            
        Returns:
            Dictionary of metadata
        """
        if not SCAPY_AVAILABLE:
            return {'packet_index': packet_index}
            
        metadata = {
            'packet_index': packet_index,
            'timestamp': getattr(packet, 'time', 0.0),
            'parser': 'scapy'
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
    
    def _get_frame_type_name(self, packet: Packet) -> str:
        """
        Get human-readable frame type name from Scapy packet.
        
        Args:
            packet: 802.11 packet
            
        Returns:
            Frame type name
        """
        if not SCAPY_AVAILABLE or not packet.haslayer(Dot11):
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


# ============================================================================
# PYSHARK-SPECIFIC BASE ANALYZER  
# ============================================================================

# PyShark imports with error handling
try:
    import pyshark
    from pyshark.packet.packet import Packet as PySharkPacket
    PYSHARK_AVAILABLE = True
except ImportError as e:
    PYSHARK_AVAILABLE = False
    PySharkPacket = None
    pyshark = None


class BasePySharkAnalyzer(AbstractBaseAnalyzer):
    """Base class for all PyShark-based wireless packet analyzers."""
    
    def __init__(self, name: str = None, category: AnalysisCategory = None, version: str = "1.0"):
        super().__init__(name, category, version)
        
        if not PYSHARK_AVAILABLE:
            self.logger.warning("PyShark not available - analyzer will not function")
    
    def __del__(self):
        # Ensure PyShark resources are cleaned up
        # if PYSHARK_AVAILABLE and pyshark is not None:
        #     pyshark.tshark.tshark_process_cleanup()
        try:
            if hasattr(self, '_capture') and self._capture:
                self._capture.close()
        except Exception as e:
            self.logger.debug(f"Error during PyShark cleanup: {e}")

    def analyze(self, packets: List[Any], context: AnalysisContext) -> List[Finding]:
        """
        Analyze PyShark packets and return findings.
        
        Args:
            packets: List of PyShark packets to analyze
            context: Analysis context with shared data and configuration
            
        Returns:
            List of findings discovered during analysis
            
        Raises:
            AnalysisError: If analysis fails
        """
        if not PYSHARK_AVAILABLE:
            return []
            
        # Default implementation that calls analyze_packet if available
        findings = []
        
        if hasattr(self, 'analyze_packet') and callable(self.analyze_packet):
            for packet in packets:
                try:
                    packet_findings = self.analyze_packet(packet)
                    if packet_findings:
                        findings.extend(packet_findings)
                except Exception as e:
                    self.logger.debug(f"Error analyzing packet: {e}")
                    continue
        else:
            # If no analyze_packet method, subclass should override this method
            raise NotImplementedError(f"{self.__class__.__name__} must implement either analyze() or analyze_packet() method")
        
        return findings
    
    def is_applicable(self, packet: Any) -> bool:
        """
        Check if this analyzer should process the given PyShark packet.
        
        Args:
            packet: PyShark packet to check
            
        Returns:
            True if analyzer should process this packet
        """
        return True
    
    def extract_packet_metadata(self, packet: Any, packet_index: int = 0) -> Dict[str, Any]:
        """
        Extract common metadata from a PyShark packet.
        
        Args:
            packet: PyShark packet to extract metadata from
            packet_index: Index of packet in capture
            
        Returns:
            Dictionary of metadata
        """
        if not PYSHARK_AVAILABLE:
            return {'packet_index': packet_index}
            
        metadata = {
            'packet_index': packet_index,
            'parser': 'pyshark'
        }
        
        # Extract timestamp
        try:
            if hasattr(packet, 'sniff_timestamp'):
                metadata['timestamp'] = float(packet.sniff_timestamp)
            elif hasattr(packet, 'frame_info') and hasattr(packet.frame_info, 'time_epoch'):
                metadata['timestamp'] = float(packet.frame_info.time_epoch)
            else:
                metadata['timestamp'] = 0.0
        except (AttributeError, ValueError):
            metadata['timestamp'] = 0.0
        
        # Basic 802.11 info
        try:
            if hasattr(packet, 'wlan'):
                wlan = packet.wlan
                
                # Extract MAC addresses
                metadata.update({
                    'bssid': self._normalize_mac(wlan.bssid) if hasattr(wlan, 'bssid') else None,
                    'src_mac': self._normalize_mac(wlan.sa) if hasattr(wlan, 'sa') else None,
                    'dst_mac': self._normalize_mac(wlan.da) if hasattr(wlan, 'da') else None,
                })
                
                # Extract frame type info
                if hasattr(wlan, 'fc_type'):
                    metadata['frame_type'] = int(wlan.fc_type)
                if hasattr(wlan, 'fc_subtype'):
                    metadata['frame_subtype'] = int(wlan.fc_subtype)
                    
                # Frame control flags
                if hasattr(wlan, 'fc_retry'):
                    metadata['retry'] = bool(int(wlan.fc_retry))
                if hasattr(wlan, 'fc_to_ds'):
                    metadata['to_ds'] = bool(int(wlan.fc_to_ds))
                if hasattr(wlan, 'fc_from_ds'):
                    metadata['from_ds'] = bool(int(wlan.fc_from_ds))
                    
                # Determine frame type enum
                frame_type = metadata.get('frame_type', -1)
                if frame_type == 0:
                    metadata['frame_type_enum'] = FrameType.MANAGEMENT
                elif frame_type == 1:
                    metadata['frame_type_enum'] = FrameType.CONTROL
                elif frame_type == 2:
                    metadata['frame_type_enum'] = FrameType.DATA
                else:
                    metadata['frame_type_enum'] = FrameType.EXTENSION
                    
        except (AttributeError, ValueError):
            pass
        
        # Radiotap/PHY info if available
        try:
            if hasattr(packet, 'radiotap'):
                radiotap = packet.radiotap
                if hasattr(radiotap, 'dbm_antsignal'):
                    metadata['rssi'] = int(radiotap.dbm_antsignal)
                if hasattr(radiotap, 'channel_freq'):
                    metadata['frequency'] = int(radiotap.channel_freq)
                if hasattr(radiotap, 'datarate'):
                    metadata['data_rate'] = int(radiotap.datarate)
        except (AttributeError, ValueError):
            pass
            
        return metadata
    
    def _get_frame_type_name(self, packet: Any) -> str:
        """
        Get human-readable frame type name from PyShark packet.
        
        Args:
            packet: 802.11 packet
            
        Returns:
            Frame type name
        """
        if not PYSHARK_AVAILABLE or not hasattr(packet, 'wlan'):
            return "Unknown"
            
        try:
            wlan = packet.wlan
            if hasattr(wlan, 'fc_type') and hasattr(wlan, 'fc_subtype'):
                frame_type = int(wlan.fc_type)
                subtype = int(wlan.fc_subtype)
                type_subtype = (frame_type << 4) | subtype
                
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
                
                return frame_types.get(type_subtype, f"Type{frame_type}Subtype{subtype}")
        except (AttributeError, ValueError):
            pass
            
        return "Unknown"


# # ============================================================================
# # CATEGORY-SPECIFIC BASE CLASSES FOR SCAPY
# # ============================================================================

# class ScapyCaptureQualityAnalyzer(BaseScapyAnalyzer):
#     """Base class for Scapy-based capture quality and method analysis."""
    
#     def __init__(self, name: str, version: str = "1.0"):
#         super().__init__(name, AnalysisCategory.CAPTURE_QUALITY, version)
#         self.analysis_order = 10  # Run early


# class ScapyRFPHYAnalyzer(BaseScapyAnalyzer):
#     """Base class for Scapy-based RF/PHY layer analysis."""
    
#     def __init__(self, name: str, version: str = "1.0"):
#         super().__init__(name, AnalysisCategory.RF_PHY, version)
#         self.analysis_order = 20


# class ScapyBeaconAnalyzer(BaseScapyAnalyzer):
#     """Base class for Scapy-based beacon frame analysis."""
    
#     def __init__(self, name: str, version: str = "1.0"):
#         super().__init__(name, AnalysisCategory.BEACONS, version)
#         self.wireshark_filters = ["wlan.fc.type_subtype == 8"]
#         self.analysis_order = 30
    
#     def is_applicable(self, packet: Packet) -> bool:
#         if not SCAPY_AVAILABLE:
#             return False
#         return packet.haslayer(Dot11Beacon)


# class ScapyProbeAnalyzer(BaseScapyAnalyzer):
#     """Base class for Scapy-based probe request/response analysis."""
    
#     def __init__(self, name: str, version: str = "1.0"):
#         super().__init__(name, AnalysisCategory.PROBE_BEHAVIOR, version)
#         self.wireshark_filters = ["wlan.fc.type_subtype == 4", "wlan.fc.type_subtype == 5"]
#         self.analysis_order = 40
    
#     def is_applicable(self, packet: Packet) -> bool:
#         if not SCAPY_AVAILABLE:
#             return False
#         return packet.haslayer(Dot11ProbeReq) or packet.haslayer(Dot11ProbeResp)


# class ScapyAuthAssocAnalyzer(BaseScapyAnalyzer):
#     """Base class for Scapy-based authentication/association analysis."""
    
#     def __init__(self, name: str, version: str = "1.0"):
#         super().__init__(name, AnalysisCategory.AUTH_ASSOC, version)
#         self.wireshark_filters = ["wlan.fc.type_subtype in {11,0,1,2}"]
#         self.analysis_order = 50
    
#     def is_applicable(self, packet: Packet) -> bool:
#         if not SCAPY_AVAILABLE:
#             return False
#         return (packet.haslayer(Dot11Auth) or 
#                 packet.haslayer(Dot11AssoReq) or 
#                 packet.haslayer(Dot11AssoResp))


# class ScapyEnterpriseSecurityAnalyzer(BaseScapyAnalyzer):
#     """Base class for Scapy-based 802.1X/EAP/TLS analysis."""
    
#     def __init__(self, name: str, version: str = "1.0"):
#         super().__init__(name, AnalysisCategory.ENTERPRISE_SECURITY, version)
#         self.wireshark_filters = ["eap", "tls", "radius"]
#         self.analysis_order = 60


# class ScapyEAPOLAnalyzer(BaseScapyAnalyzer):
#     """Base class for Scapy-based 4-way handshake analysis."""
    
#     def __init__(self, name: str, version: str = "1.0"):
#         super().__init__(name, AnalysisCategory.EAPOL_HANDSHAKE, version)
#         self.wireshark_filters = ["eapol"]
#         self.analysis_order = 70
    
#     def is_applicable(self, packet: Packet) -> bool:
#         if not SCAPY_AVAILABLE:
#             return False
#         return packet.haslayer(EAPOL)


# class ScapySecurityThreatAnalyzer(BaseScapyAnalyzer):
#     """Base class for Scapy-based security threat detection."""
    
#     def __init__(self, name: str, version: str = "1.0"):
#         super().__init__(name, AnalysisCategory.SECURITY_THREATS, version)
#         self.wireshark_filters = ["wlan.fc.type_subtype in {12,10}"]  # deauth/disassoc
#         self.analysis_order = 150
    
#     def is_applicable(self, packet: Packet) -> bool:
#         if not SCAPY_AVAILABLE:
#             return False
#         return packet.haslayer(Dot11Deauth) or packet.haslayer(Dot11Disas)


# # ============================================================================
# # CATEGORY-SPECIFIC BASE CLASSES FOR PYSHARK
# # ============================================================================

# class PySharkCaptureQualityAnalyzer(BasePySharkAnalyzer):
#     """Base class for PyShark-based capture quality and method analysis."""
    
#     def __init__(self, name: str, version: str = "1.0"):
#         super().__init__(name, AnalysisCategory.CAPTURE_QUALITY, version)
#         self.analysis_order = 10  # Run early


# class PySharkRFPHYAnalyzer(BasePySharkAnalyzer):
#     """Base class for PyShark-based RF/PHY layer analysis."""
    
#     def __init__(self, name: str, version: str = "1.0"):
#         super().__init__(name, AnalysisCategory.RF_PHY, version)
#         self.analysis_order = 20


# class PySharkBeaconAnalyzer(BasePySharkAnalyzer):
#     """Base class for PyShark-based beacon frame analysis."""
    
#     def __init__(self, name: str, version: str = "1.0"):
#         super().__init__(name, AnalysisCategory.BEACONS, version)
#         self.wireshark_filters = ["wlan.fc.type_subtype == 8"]
#         self.analysis_order = 30
    
#     def is_applicable(self, packet: Any) -> bool:
#         if not PYSHARK_AVAILABLE:
#             return False
#         try:
#             return (hasattr(packet, 'wlan') and 
#                    hasattr(packet.wlan, 'fc_type') and 
#                    hasattr(packet.wlan, 'fc_subtype') and
#                    int(packet.wlan.fc_type) == 0 and int(packet.wlan.fc_subtype) == 8)
#         except (AttributeError, ValueError):
#             return False


# class PySharkProbeAnalyzer(BasePySharkAnalyzer):
#     """Base class for PyShark-based probe request/response analysis."""
    
#     def __init__(self, name: str, version: str = "1.0"):
#         super().__init__(name, AnalysisCategory.PROBE_BEHAVIOR, version)
#         self.wireshark_filters = ["wlan.fc.type_subtype == 4", "wlan.fc.type_subtype == 5"]
#         self.analysis_order = 40
    
#     def is_applicable(self, packet: Any) -> bool:
#         if not PYSHARK_AVAILABLE:
#             return False
#         try:
#             return (hasattr(packet, 'wlan') and 
#                    hasattr(packet.wlan, 'fc_type') and 
#                    hasattr(packet.wlan, 'fc_subtype') and
#                    int(packet.wlan.fc_type) == 0 and 
#                    int(packet.wlan.fc_subtype) in [4, 5])
#         except (AttributeError, ValueError):
#             return False


# class PySharkAuthAssocAnalyzer(BasePySharkAnalyzer):
#     """Base class for PyShark-based authentication/association analysis."""
    
#     def __init__(self, name: str, version: str = "1.0"):
#         super().__init__(name, AnalysisCategory.AUTH_ASSOC, version)
#         self.wireshark_filters = ["wlan.fc.type_subtype in {11,0,1,2}"]
#         self.analysis_order = 50
    
#     def is_applicable(self, packet: Any) -> bool:
#         if not PYSHARK_AVAILABLE:
#             return False
#         try:
#             return (hasattr(packet, 'wlan') and 
#                    hasattr(packet.wlan, 'fc_type') and 
#                    hasattr(packet.wlan, 'fc_subtype') and
#                    int(packet.wlan.fc_type) == 0 and 
#                    int(packet.wlan.fc_subtype) in [0, 1, 2, 11])
#         except (AttributeError, ValueError):
#             return False


# class PySharkEnterpriseSecurityAnalyzer(BasePySharkAnalyzer):
#     """Base class for PyShark-based 802.1X/EAP/TLS analysis."""
    
#     def __init__(self, name: str, version: str = "1.0"):
#         super().__init__(name, AnalysisCategory.ENTERPRISE_SECURITY, version)
#         self.wireshark_filters = ["eap", "tls", "radius"]
#         self.analysis_order = 60


# class PySharkEAPOLAnalyzer(BasePySharkAnalyzer):
#     """Base class for PyShark-based 4-way handshake analysis."""
    
#     def __init__(self, name: str, version: str = "1.0"):
#         super().__init__(name, AnalysisCategory.EAPOL_HANDSHAKE, version)
#         self.wireshark_filters = ["eapol"]
#         self.analysis_order = 70
    
#     def is_applicable(self, packet: Any) -> bool:
#         if not PYSHARK_AVAILABLE:
#             return False
#         return hasattr(packet, 'eapol')


# class PySharkSecurityThreatAnalyzer(BasePySharkAnalyzer):
#     """Base class for PyShark-based security threat detection."""
    
#     def __init__(self, name: str, version: str = "1.0"):
#         super().__init__(name, AnalysisCategory.SECURITY_THREATS, version)
#         self.wireshark_filters = ["wlan.fc.type_subtype in {12,10}"]  # deauth/disassoc
#         self.analysis_order = 150
    
#     def is_applicable(self, packet: Any) -> bool:
#         if not PYSHARK_AVAILABLE:
#             return False
#         try:
#             return (hasattr(packet, 'wlan') and 
#                    hasattr(packet.wlan, 'fc_type') and 
#                    hasattr(packet.wlan, 'fc_subtype') and
#                    int(packet.wlan.fc_type) == 0 and 
#                    int(packet.wlan.fc_subtype) in [10, 12])
#         except (AttributeError, ValueError):
#             return False
