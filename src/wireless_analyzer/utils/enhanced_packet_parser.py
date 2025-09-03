"""
Enhanced packet parser with multiple library support and detailed diagnostics.

This module provides fallback parsing capabilities and detailed logging
to diagnose PCAP parsing issues in wireless analysis.
"""

import logging
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from datetime import datetime

# Scapy imports (primary parser)
try:
    from scapy.all import Packet, rdpcap
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11Deauth
    from scapy.layers.dot11 import RadioTap
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("Scapy not available")

# PyShark imports (fallback parser) 
try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False
    logging.info("PyShark not available - install with: pip install pyshark")

# dpkt imports (performance parser)
try:
    import dpkt
    import socket
    DPKT_AVAILABLE = True
except ImportError:
    DPKT_AVAILABLE = False
    logging.info("dpkt not available - install with: pip install dpkt")


@dataclass
class ParsedPacket:
    """Unified packet representation across different parsers."""
    timestamp: float
    frame_type: str
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    bssid: Optional[str] = None
    ssid: Optional[str] = None
    channel: Optional[int] = None
    frequency: Optional[int] = None
    rssi: Optional[int] = None
    frame_subtype: Optional[int] = None
    raw_data: Optional[bytes] = None
    parsing_source: str = "unknown"
    parsing_errors: List[str] = None
    
    def __post_init__(self):
        if self.parsing_errors is None:
            self.parsing_errors = []


@dataclass 
class ParsedResults:
    """Results from packet parsing with diagnostics."""
    packets: List[ParsedPacket]
    total_packets: int
    successful_parses: int
    parsing_errors: Dict[str, int]
    library_used: str
    parsing_time: float
    statistics: Dict[str, Any]


class EnhancedPacketParser:
    """
    Enhanced packet parser with multiple library support and comprehensive diagnostics.
    """
    
    def __init__(self, prefer_library: str = "auto"):
        """
        Initialize parser with library preference.
        
        Args:
            prefer_library: Preferred library ("scapy", "pyshark", "dpkt", "auto")
        """
        self.logger = logging.getLogger(__name__)
        self.prefer_library = prefer_library
        
        # Initialize available parsers
        self.available_parsers = {}
        if SCAPY_AVAILABLE:
            self.available_parsers['scapy'] = self._parse_with_scapy
        if PYSHARK_AVAILABLE:
            self.available_parsers['pyshark'] = self._parse_with_pyshark  
        if DPKT_AVAILABLE:
            self.available_parsers['dpkt'] = self._parse_with_dpkt
            
        self.logger.info(f"Available parsers: {list(self.available_parsers.keys())}")
        
        # Statistics tracking
        self.reset_stats()
        
    def reset_stats(self):
        """Reset parsing statistics."""
        self.stats = {
            'total_files_processed': 0,
            'total_packets_processed': 0,
            'library_usage': {},
            'error_counts': {},
            'field_extraction_success': {
                'timestamp': 0, 'addresses': 0, 'ssid': 0, 
                'channel': 0, 'rssi': 0, 'frame_type': 0
            }
        }
    
    def parse_pcap(self, pcap_file: str, max_packets: Optional[int] = None) -> ParsedResults:
        """
        Parse PCAP file with best-effort approach using multiple libraries.
        
        Args:
            pcap_file: Path to PCAP file
            max_packets: Maximum packets to parse
            
        Returns:
            ParsedResults with parsed packets and diagnostics
        """
        import time
        start_time = time.time()
        
        self.logger.info(f"Parsing PCAP file: {pcap_file}")
        self.stats['total_files_processed'] += 1
        
        # Determine parsing order
        parsing_order = self._get_parsing_order()
        
        results = None
        last_error = None
        
        for library in parsing_order:
            if library not in self.available_parsers:
                continue
                
            try:
                self.logger.info(f"Attempting parsing with {library}")
                results = self.available_parsers[library](pcap_file, max_packets)
                results.library_used = library
                self.stats['library_usage'][library] = self.stats['library_usage'].get(library, 0) + 1
                break
                
            except Exception as e:
                self.logger.warning(f"Parser {library} failed: {e}")
                self.stats['error_counts'][library] = self.stats['error_counts'].get(library, 0) + 1
                last_error = e
                continue
        
        if results is None:
            raise Exception(f"All parsers failed. Last error: {last_error}")
            
        results.parsing_time = time.time() - start_time
        self.stats['total_packets_processed'] += results.total_packets
        
        self.logger.info(f"Parsing complete: {results.successful_parses}/{results.total_packets} "
                        f"packets in {results.parsing_time:.2f}s using {results.library_used}")
        
        return results
    
    def _get_parsing_order(self) -> List[str]:
        """Get parsing order based on preference and availability."""
        if self.prefer_library == "auto":
            # Default order: scapy (familiar) -> pyshark (comprehensive) -> dpkt (fast)
            return ['scapy', 'pyshark', 'dpkt']
        elif self.prefer_library in self.available_parsers:
            # Preferred library first, then others
            others = [lib for lib in self.available_parsers if lib != self.prefer_library]
            return [self.prefer_library] + others
        else:
            return list(self.available_parsers.keys())
    
    def _parse_with_scapy(self, pcap_file: str, max_packets: Optional[int] = None) -> ParsedResults:
        """Parse PCAP file using Scapy."""
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy not available")
            
        # Load packets
        try:
            raw_packets = rdpcap(pcap_file)
            if max_packets:
                raw_packets = raw_packets[:max_packets]
        except Exception as e:
            raise Exception(f"Failed to load PCAP with Scapy: {e}")
            
        parsed_packets = []
        parsing_errors = {}
        successful_parses = 0
        
        self.logger.info(f"Processing {len(raw_packets)} packets with Scapy")
        
        for i, packet in enumerate(raw_packets):
            try:
                parsed = self._extract_scapy_fields(packet, i)
                if parsed:
                    parsed_packets.append(parsed)
                    successful_parses += 1
                    self._update_field_stats(parsed)
                else:
                    parsing_errors['field_extraction_failed'] = parsing_errors.get('field_extraction_failed', 0) + 1
                    
            except Exception as e:
                error_type = type(e).__name__
                parsing_errors[error_type] = parsing_errors.get(error_type, 0) + 1
                self.logger.debug(f"Scapy parsing error on packet {i}: {e}")
                
        # Generate statistics
        statistics = self._generate_scapy_statistics(parsed_packets)
                
        return ParsedResults(
            packets=parsed_packets,
            total_packets=len(raw_packets),
            successful_parses=successful_parses,
            parsing_errors=parsing_errors,
            library_used="scapy",
            parsing_time=0,  # Will be set by caller
            statistics=statistics
        )
    
    def _extract_scapy_fields(self, packet: Packet, packet_index: int) -> Optional[ParsedPacket]:
        """Extract fields from Scapy packet with enhanced error handling."""
        parsed = ParsedPacket(
            timestamp=0.0,
            frame_type="unknown",
            parsing_source="scapy"
        )
        
        errors = []
        
        # Extract timestamp
        try:
            if hasattr(packet, 'time'):
                time_val = packet.time
                if hasattr(time_val, '__float__'):
                    parsed.timestamp = float(time_val)
                elif hasattr(time_val, 'val'):
                    parsed.timestamp = float(time_val.val)
                else:
                    parsed.timestamp = float(time_val)
        except Exception as e:
            errors.append(f"timestamp_extraction: {e}")
            
        # Extract 802.11 information
        if packet.haslayer(Dot11):
            try:
                dot11 = packet[Dot11]
                
                # Extract addresses
                if hasattr(dot11, 'addr1') and dot11.addr1:
                    parsed.dst_mac = str(dot11.addr1).lower()
                if hasattr(dot11, 'addr2') and dot11.addr2:
                    parsed.src_mac = str(dot11.addr2).lower()
                if hasattr(dot11, 'addr3') and dot11.addr3:
                    parsed.bssid = str(dot11.addr3).lower()
                    
                # Extract frame type info
                if hasattr(dot11, 'type') and hasattr(dot11, 'subtype'):
                    frame_type = getattr(dot11, 'type', None)
                    frame_subtype = getattr(dot11, 'subtype', None)
                    parsed.frame_subtype = frame_subtype
                    
                    # Determine frame type name
                    if frame_type == 0:  # Management
                        parsed.frame_type = "management"
                        if packet.haslayer(Dot11Beacon):
                            parsed.frame_type = "beacon"
                        elif packet.haslayer(Dot11ProbeReq):
                            parsed.frame_type = "probe_request"
                        elif packet.haslayer(Dot11Deauth):
                            parsed.frame_type = "deauth"
                    elif frame_type == 1:
                        parsed.frame_type = "control"
                    elif frame_type == 2:
                        parsed.frame_type = "data"
                        
            except Exception as e:
                errors.append(f"dot11_extraction: {e}")
        else:
            # Not an 802.11 packet - determine what it is
            layer_names = []
            layer = packet
            while layer:
                layer_names.append(layer.__class__.__name__)
                layer = layer.payload if hasattr(layer, 'payload') else None
            parsed.frame_type = "non_802_11"
            errors.append(f"not_802_11: layers={' -> '.join(layer_names)}")
            
        # Extract RadioTap information
        if packet.haslayer(RadioTap):
            try:
                radiotap = packet[RadioTap]
                
                # RSSI
                if hasattr(radiotap, 'dBm_AntSignal'):
                    parsed.rssi = int(radiotap.dBm_AntSignal)
                elif hasattr(radiotap, 'dbm_antsignal'):
                    parsed.rssi = int(radiotap.dbm_antsignal)
                    
                # Channel/Frequency
                if hasattr(radiotap, 'Channel'):
                    parsed.channel = int(radiotap.Channel)
                elif hasattr(radiotap, 'ChannelFrequency'):
                    parsed.frequency = int(radiotap.ChannelFrequency)
                    # Convert frequency to channel if needed
                    if parsed.frequency and not parsed.channel:
                        parsed.channel = self._freq_to_channel(parsed.frequency)
                        
            except Exception as e:
                errors.append(f"radiotap_extraction: {e}")
                
        # Extract SSID from management frames
        if parsed.frame_type in ["beacon", "probe_request"]:
            try:
                if hasattr(packet, 'info') and packet.info:
                    ssid_bytes = packet.info
                    if isinstance(ssid_bytes, bytes):
                        parsed.ssid = ssid_bytes.decode('utf-8', errors='ignore')
                    else:
                        parsed.ssid = str(ssid_bytes)
            except Exception as e:
                errors.append(f"ssid_extraction: {e}")
        
        parsed.parsing_errors = errors
        return parsed
        
    def _parse_with_pyshark(self, pcap_file: str, max_packets: Optional[int] = None) -> ParsedResults:
        """Parse PCAP file using PyShark."""
        if not PYSHARK_AVAILABLE:
            raise ImportError("PyShark not available")
            
        parsed_packets = []
        parsing_errors = {}
        successful_parses = 0
        
        try:
            # Open capture with 802.11 filter
            cap = pyshark.FileCapture(pcap_file, display_filter='wlan')
            
            packet_count = 0
            for packet in cap:
                if max_packets and packet_count >= max_packets:
                    break
                    
                try:
                    parsed = self._extract_pyshark_fields(packet, packet_count)
                    if parsed:
                        parsed_packets.append(parsed)
                        successful_parses += 1
                        self._update_field_stats(parsed)
                        
                except Exception as e:
                    error_type = type(e).__name__
                    parsing_errors[error_type] = parsing_errors.get(error_type, 0) + 1
                    self.logger.debug(f"PyShark parsing error on packet {packet_count}: {e}")
                    
                packet_count += 1
                
            cap.close()
            
        except Exception as e:
            raise Exception(f"PyShark capture failed: {e}")
            
        statistics = self._generate_pyshark_statistics(parsed_packets)
        
        return ParsedResults(
            packets=parsed_packets,
            total_packets=packet_count,
            successful_parses=successful_parses,
            parsing_errors=parsing_errors,
            library_used="pyshark",
            parsing_time=0,
            statistics=statistics
        )
    
    def _extract_pyshark_fields(self, packet, packet_index: int) -> Optional[ParsedPacket]:
        """Extract fields from PyShark packet."""
        parsed = ParsedPacket(
            timestamp=float(packet.sniff_time.timestamp()) if hasattr(packet, 'sniff_time') else 0.0,
            frame_type="unknown",
            parsing_source="pyshark"
        )
        
        errors = []
        
        # Extract WLAN information
        if hasattr(packet, 'wlan'):
            wlan = packet.wlan
            
            # Addresses
            parsed.src_mac = getattr(wlan, 'sa', None)
            parsed.dst_mac = getattr(wlan, 'da', None) 
            parsed.bssid = getattr(wlan, 'bssid', None)
            
            # Frame type
            fc_type = getattr(wlan, 'fc_type', None)
            fc_subtype = getattr(wlan, 'fc_subtype', None)
            
            if fc_type == '0':  # Management
                parsed.frame_type = "management"
                if fc_subtype == '8':
                    parsed.frame_type = "beacon"
                elif fc_subtype == '4':
                    parsed.frame_type = "probe_request"
            
            # SSID
            parsed.ssid = getattr(wlan, 'ssid', None)
            
            # Channel
            if hasattr(wlan, 'channel'):
                try:
                    parsed.channel = int(wlan.channel)
                except:
                    pass
                    
        # Extract RadioTap information
        if hasattr(packet, 'radiotap'):
            radiotap = packet.radiotap
            
            # RSSI
            if hasattr(radiotap, 'dbm_antsignal'):
                try:
                    parsed.rssi = int(radiotap.dbm_antsignal)
                except:
                    pass
                    
            # Frequency
            if hasattr(radiotap, 'channel_freq'):
                try:
                    parsed.frequency = int(radiotap.channel_freq)
                    if not parsed.channel:
                        parsed.channel = self._freq_to_channel(parsed.frequency)
                except:
                    pass
        
        parsed.parsing_errors = errors
        return parsed
        
    def _parse_with_dpkt(self, pcap_file: str, max_packets: Optional[int] = None) -> ParsedResults:
        """Parse PCAP file using dpkt (basic implementation)."""
        if not DPKT_AVAILABLE:
            raise ImportError("dpkt not available")
            
        parsed_packets = []
        parsing_errors = {}
        successful_parses = 0
        packet_count = 0
        
        try:
            with open(pcap_file, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)
                
                for timestamp, buf in pcap:
                    if max_packets and packet_count >= max_packets:
                        break
                        
                    try:
                        parsed = self._extract_dpkt_fields(buf, timestamp, packet_count)
                        if parsed:
                            parsed_packets.append(parsed)
                            successful_parses += 1
                            self._update_field_stats(parsed)
                            
                    except Exception as e:
                        error_type = type(e).__name__
                        parsing_errors[error_type] = parsing_errors.get(error_type, 0) + 1
                        self.logger.debug(f"dpkt parsing error on packet {packet_count}: {e}")
                        
                    packet_count += 1
                    
        except Exception as e:
            raise Exception(f"dpkt file reading failed: {e}")
            
        statistics = self._generate_dpkt_statistics(parsed_packets)
        
        return ParsedResults(
            packets=parsed_packets,
            total_packets=packet_count,
            successful_parses=successful_parses,
            parsing_errors=parsing_errors,
            library_used="dpkt",
            parsing_time=0,
            statistics=statistics
        )
    
    def _extract_dpkt_fields(self, buf: bytes, timestamp: float, packet_index: int) -> Optional[ParsedPacket]:
        """Extract fields from dpkt packet (basic implementation)."""
        parsed = ParsedPacket(
            timestamp=timestamp,
            frame_type="unknown",
            parsing_source="dpkt",
            raw_data=buf
        )
        
        # Basic dpkt 802.11 parsing would go here
        # This is a placeholder - full dpkt 802.11 parsing is more complex
        parsed.frame_type = "dpkt_parsed"
        
        return parsed
    
    def _update_field_stats(self, parsed: ParsedPacket):
        """Update field extraction success statistics."""
        if parsed.timestamp > 0:
            self.stats['field_extraction_success']['timestamp'] += 1
        if parsed.src_mac or parsed.dst_mac:
            self.stats['field_extraction_success']['addresses'] += 1
        if parsed.ssid:
            self.stats['field_extraction_success']['ssid'] += 1
        if parsed.channel:
            self.stats['field_extraction_success']['channel'] += 1
        if parsed.rssi:
            self.stats['field_extraction_success']['rssi'] += 1
        if parsed.frame_type != "unknown":
            self.stats['field_extraction_success']['frame_type'] += 1
    
    def _freq_to_channel(self, frequency: int) -> Optional[int]:
        """Convert frequency to 802.11 channel number."""
        # 2.4 GHz channels
        if 2412 <= frequency <= 2484:
            if frequency == 2484:
                return 14
            return (frequency - 2407) // 5
        # 5 GHz channels (basic mapping)
        elif 5000 <= frequency <= 6000:
            return (frequency - 5000) // 5
        return None
    
    def _generate_scapy_statistics(self, packets: List[ParsedPacket]) -> Dict[str, Any]:
        """Generate statistics for Scapy parsing results."""
        stats = {
            'frame_types': {},
            'channels': set(),
            'ssids': set(),
            'rssi_available': 0,
            'timestamp_available': 0
        }
        
        for packet in packets:
            # Frame type distribution
            stats['frame_types'][packet.frame_type] = stats['frame_types'].get(packet.frame_type, 0) + 1
            
            if packet.channel:
                stats['channels'].add(packet.channel)
            if packet.ssid:
                stats['ssids'].add(packet.ssid)
            if packet.rssi:
                stats['rssi_available'] += 1
            if packet.timestamp > 0:
                stats['timestamp_available'] += 1
                
        # Convert sets to lists for JSON serialization
        stats['channels'] = list(stats['channels'])
        stats['ssids'] = list(stats['ssids'])
        
        return stats
    
    def _generate_pyshark_statistics(self, packets: List[ParsedPacket]) -> Dict[str, Any]:
        """Generate statistics for PyShark parsing results."""
        return self._generate_scapy_statistics(packets)  # Same format
    
    def _generate_dpkt_statistics(self, packets: List[ParsedPacket]) -> Dict[str, Any]:
        """Generate statistics for dpkt parsing results.""" 
        return self._generate_scapy_statistics(packets)  # Same format
    
    def get_parsing_statistics(self) -> Dict[str, Any]:
        """Get comprehensive parsing statistics."""
        return self.stats
    
    def diagnose_pcap(self, pcap_file: str, max_packets: int = 100) -> Dict[str, Any]:
        """
        Diagnose PCAP file parsing issues.
        
        Args:
            pcap_file: Path to PCAP file
            max_packets: Maximum packets to analyze for diagnosis
            
        Returns:
            Detailed diagnosis information
        """
        diagnosis = {
            'file': pcap_file,
            'library_results': {},
            'recommendations': []
        }
        
        # Test each available parser
        for library in self.available_parsers:
            try:
                results = self.available_parsers[library](pcap_file, max_packets)
                diagnosis['library_results'][library] = {
                    'success': True,
                    'packets_parsed': results.successful_parses,
                    'total_packets': results.total_packets,
                    'parsing_errors': results.parsing_errors,
                    'statistics': results.statistics
                }
            except Exception as e:
                diagnosis['library_results'][library] = {
                    'success': False,
                    'error': str(e)
                }
        
        # Generate recommendations
        successful_parsers = [lib for lib, result in diagnosis['library_results'].items() 
                            if result.get('success', False)]
        
        if not successful_parsers:
            diagnosis['recommendations'].append("No parsers succeeded - check PCAP file format")
        elif len(successful_parsers) == 1:
            diagnosis['recommendations'].append(f"Only {successful_parsers[0]} succeeded - use as primary parser")
        else:
            # Compare parser effectiveness
            best_parser = max(successful_parsers, 
                            key=lambda lib: diagnosis['library_results'][lib]['packets_parsed'])
            diagnosis['recommendations'].append(f"Best parser: {best_parser}")
            
        return diagnosis