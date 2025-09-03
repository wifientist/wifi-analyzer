"""
Unified packet loader with multi-library support for wireless PCAP analysis.

This module provides a robust packet loading system that can fallback between
Scapy, PyShark, and dpkt to ensure maximum compatibility and data extraction.
"""

import logging
import time
from typing import List, Dict, Any, Optional, Tuple, Union
from dataclasses import dataclass
from pathlib import Path

# Try importing all available libraries
SCAPY_AVAILABLE = False
PYSHARK_AVAILABLE = False
DPKT_AVAILABLE = False

try:
    from scapy.all import rdpcap, Packet as ScapyPacket
    from scapy.layers.dot11 import Dot11, RadioTap
    SCAPY_AVAILABLE = True
except ImportError:
    ScapyPacket = None

try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    pass

try:
    import dpkt
    DPKT_AVAILABLE = True
except ImportError:
    pass


@dataclass
class UnifiedPacketInfo:
    """
    Unified packet information that normalizes data across different parsing libraries.
    This ensures consistent data flow to analyzers regardless of the source library.
    """
    # Core packet info
    raw_packet: Any  # Original packet object from whichever library was used
    packet_index: int
    timestamp: float
    
    # 802.11 addressing
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    bssid: Optional[str] = None
    
    # Frame information
    frame_type: Optional[int] = None  # 0=mgmt, 1=ctrl, 2=data
    frame_subtype: Optional[int] = None
    frame_name: str = "unknown"  # Human readable name
    
    # RadioTap/PHY information
    rssi: Optional[int] = None
    channel: Optional[int] = None
    frequency: Optional[int] = None
    data_rate: Optional[str] = None
    
    # Protocol-specific data
    ssid: Optional[str] = None
    beacon_interval: Optional[int] = None
    capabilities: Optional[int] = None
    
    # Quality indicators
    fcs_bad: bool = False
    retry: bool = False
    
    # Parsing metadata
    parsing_library: str = "unknown"
    parsing_errors: List[str] = None
    
    def __post_init__(self):
        if self.parsing_errors is None:
            self.parsing_errors = []
            
    def has_layer(self, layer_name: str) -> bool:
        """Check if packet has a specific layer (adapter method)."""
        if self.parsing_library == "scapy" and hasattr(self.raw_packet, 'haslayer'):
            if layer_name == "Dot11":
                from scapy.layers.dot11 import Dot11
                return self.raw_packet.haslayer(Dot11)
            elif layer_name == "RadioTap":
                from scapy.layers.dot11 import RadioTap
                return self.raw_packet.haslayer(RadioTap)
            # Add other layer checks as needed
        elif self.parsing_library == "pyshark":
            layer_map = {
                "Dot11": "wlan",
                "RadioTap": "radiotap"
            }
            return hasattr(self.raw_packet, layer_map.get(layer_name, layer_name.lower()))
        return False


class UnifiedPacketLoader:
    """
    Unified packet loader that tries multiple libraries to maximize packet parsing success.
    """
    
    def __init__(self, prefer_library: str = "auto", analysis_requirements: Optional[Dict[str, Any]] = None):
        """
        Initialize packet loader with analysis requirements.
        
        Args:
            prefer_library: Preferred library ("scapy", "pyshark", "dpkt", "auto")
            analysis_requirements: Dict specifying analysis needs for parser selection
        """
        self.logger = logging.getLogger(__name__)
        self.prefer_library = prefer_library
        self.analysis_requirements = analysis_requirements or {}
        
        # Initialize available parsers in order of preference
        self.available_parsers = []
        if SCAPY_AVAILABLE:
            self.available_parsers.append("scapy")
        if PYSHARK_AVAILABLE:
            self.available_parsers.append("pyshark")
        if DPKT_AVAILABLE:
            self.available_parsers.append("dpkt")
            
        self.logger.info(f"Available packet parsers: {self.available_parsers}")
        if self.analysis_requirements:
            self.logger.info(f"Analysis requirements: {self.analysis_requirements}")
        
        # Statistics
        self.stats = {
            'files_processed': 0,
            'total_packets_loaded': 0,
            'library_usage': {},
            'parsing_errors': {},
            'field_extraction_success': {}
        }
        
    def configure_for_analyzers(self, enabled_analyzers: List[str]) -> None:
        """
        Configure loader based on enabled analyzers to optimize parser selection.
        
        Args:
            enabled_analyzers: List of enabled analyzer names
        """
        requirements = {
            'needs_enterprise_security': False,
            'needs_detailed_radioinfo': False,
            'needs_high_performance': False,
            'needs_beacon_analysis': False,
            'needs_deauth_analysis': False,
            'needs_probe_analysis': False
        }
        
        for analyzer_name in enabled_analyzers:
            name_lower = analyzer_name.lower()
            
            # Enterprise/security analyzers need comprehensive parsing
            if any(keyword in name_lower for keyword in ['enterprise', 'security', 'wpa', 'eap']):
                requirements['needs_enterprise_security'] = True
                
            # Signal/RF analyzers need detailed RadioTap info
            if any(keyword in name_lower for keyword in ['signal', 'rf', 'phy', 'rssi']):
                requirements['needs_detailed_radioinfo'] = True
                
            # Specific frame analyzers
            if 'beacon' in name_lower:
                requirements['needs_beacon_analysis'] = True
            if 'deauth' in name_lower:
                requirements['needs_deauth_analysis'] = True
            if 'probe' in name_lower:
                requirements['needs_probe_analysis'] = True
                
            # Performance-sensitive analyzers (if analyzing large volumes)
            if any(keyword in name_lower for keyword in ['flood', 'bulk', 'volume']):
                requirements['needs_high_performance'] = True
                
        self.analysis_requirements = requirements
        self.logger.info(f"Configured analysis requirements: {requirements}")
        
    def load_packets(self, pcap_file: str, max_packets: Optional[int] = None) -> Tuple[List[UnifiedPacketInfo], Dict[str, Any]]:
        """
        Load packets from PCAP file using best available parser.
        
        Args:
            pcap_file: Path to PCAP file
            max_packets: Maximum packets to load
            
        Returns:
            Tuple of (packet_list, metadata)
            
        Raises:
            Exception: If all parsers fail
        """
        start_time = time.time()
        self.stats['files_processed'] += 1
        
        pcap_path = Path(pcap_file)
        if not pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_file}")
            
        self.logger.info(f"Loading packets from {pcap_file}")
        
        # Determine parser order based on file characteristics
        parser_order = self._get_parser_order(pcap_file)
        
        packets = None
        metadata = None
        last_error = None
        
        for parser_name in parser_order:
            try:
                self.logger.info(f"Attempting to load with {parser_name}")
                packets, metadata = self._load_with_parser(parser_name, pcap_file, max_packets)
                metadata['library_used'] = parser_name
                metadata['loading_time'] = time.time() - start_time
                
                # Update usage stats
                self.stats['library_usage'][parser_name] = self.stats['library_usage'].get(parser_name, 0) + 1
                self.stats['total_packets_loaded'] += len(packets)
                
                self.logger.info(f"Successfully loaded {len(packets)} packets using {parser_name}")
                break
                
            except Exception as e:
                self.logger.warning(f"Parser {parser_name} failed: {e}")
                self.stats['parsing_errors'][parser_name] = self.stats['parsing_errors'].get(parser_name, 0) + 1
                last_error = e
                continue
                
        if packets is None:
            raise Exception(f"All packet parsers failed. Last error: {last_error}")
            
        return packets, metadata
    
    def _get_parser_order(self, pcap_file: str) -> List[str]:
        """
        Intelligently determine parser order based on PCAP file characteristics.
        
        Args:
            pcap_file: Path to PCAP file
            
        Returns:
            Ordered list of parsers to try, best first
        """
        if self.prefer_library != "auto" and self.prefer_library in self.available_parsers:
            # User has explicit preference
            others = [p for p in self.available_parsers if p != self.prefer_library]
            return [self.prefer_library] + others
            
        # Analyze PCAP file characteristics to make intelligent choice
        pcap_info = self._analyze_pcap_file(pcap_file)
        
        # Decision logic based on PCAP characteristics
        parser_scores = {}
        
        # Initialize all available parsers with base scores
        for parser in self.available_parsers:
            parser_scores[parser] = 0
            
        # Scoring logic for different scenarios
        
        # 1. RadioTap presence (critical for wireless analysis)
        if pcap_info.get('has_radiotap', False):
            parser_scores['pyshark'] += 30  # PyShark excels at RadioTap parsing
            parser_scores['scapy'] += 20    # Scapy is decent
            parser_scores['dpkt'] += 5      # dpkt is basic
            
        # 2. Link layer type analysis
        link_type = pcap_info.get('link_type')
        if link_type == 127:  # IEEE 802.11 RadioTap
            parser_scores['pyshark'] += 25  # Best for full 802.11 dissection
            parser_scores['scapy'] += 15    # Good 802.11 support
        elif link_type == 105:  # IEEE 802.11 without RadioTap
            parser_scores['scapy'] += 20    # Good for basic 802.11
            parser_scores['pyshark'] += 15  # Still good but less advantage
        elif link_type == 1:  # Ethernet (not wireless)
            # Probably not a wireless capture, use fastest
            parser_scores['dpkt'] += 25
            parser_scores['scapy'] += 10
            
        # 3. File size considerations
        file_size_mb = pcap_info.get('size_mb', 0)
        if file_size_mb > 100:  # Large files
            parser_scores['dpkt'] += 20    # dpkt is fastest
            parser_scores['scapy'] += 5    # Moderate performance
            parser_scores['pyshark'] -= 10 # PyShark can be slow on large files
        elif file_size_mb < 10:  # Small files
            parser_scores['pyshark'] += 15 # Use best quality parsing for small files
            parser_scores['scapy'] += 10
            
        # 4. Analysis requirements from enabled analyzers
        req = self.analysis_requirements
        
        # Enterprise security analysis needs comprehensive parsing
        if req.get('needs_enterprise_security', False):
            parser_scores['pyshark'] += 25  # Best for complex protocol dissection
            parser_scores['scapy'] += 10    # Decent for security analysis
            
        # Detailed RadioTap info (RSSI, channel, rates) crucial for RF analysis
        if req.get('needs_detailed_radioinfo', False):
            parser_scores['pyshark'] += 30  # Best RadioTap field extraction
            parser_scores['scapy'] += 15    # Good RadioTap support
            parser_scores['dpkt'] += 5      # Basic support
            
        # High performance needs for flood detection, etc.
        if req.get('needs_high_performance', False):
            parser_scores['dpkt'] += 25     # Fastest processing
            parser_scores['scapy'] += 5     # Moderate speed
            parser_scores['pyshark'] -= 15  # Slowest option
            
        # Beacon analysis - all parsers handle well, slight preference for PyShark
        if req.get('needs_beacon_analysis', False):
            parser_scores['pyshark'] += 10  # Best IE parsing
            parser_scores['scapy'] += 8     # Good beacon support
            
        # Deauth analysis - Scapy traditionally strong here
        if req.get('needs_deauth_analysis', False):
            parser_scores['scapy'] += 12    # Good deauth frame handling
            parser_scores['pyshark'] += 10  # Also good
            
        # Probe analysis - PyShark excels at probe request/response details  
        if req.get('needs_probe_analysis', False):
            parser_scores['pyshark'] += 15  # Best probe frame dissection
            parser_scores['scapy'] += 8     # Good support
            
        # 5. PCAPNG format handling
        if pcap_info.get('format') == 'pcapng':
            parser_scores['pyshark'] += 15  # PyShark handles PCAPNG better
            parser_scores['scapy'] += 5
            
        # Sort parsers by score (highest first)
        sorted_parsers = sorted(parser_scores.items(), key=lambda x: x[1], reverse=True)
        parser_order = [parser for parser, score in sorted_parsers if parser in self.available_parsers]
        
        self.logger.info(f"Parser selection scores: {dict(sorted_parsers)}")
        self.logger.info(f"Selected parser order: {parser_order}")
        
        return parser_order
    
    def _analyze_pcap_file(self, pcap_file: str) -> Dict[str, Any]:
        """
        Analyze PCAP file characteristics to guide parser selection.
        
        Args:
            pcap_file: Path to PCAP file
            
        Returns:
            Dictionary with file characteristics
        """
        pcap_path = Path(pcap_file)
        info = {
            'size_mb': pcap_path.stat().st_size / (1024 * 1024),
            'format': 'unknown',
            'link_type': None,
            'has_radiotap': False,
            'sample_packet_analysis': {}
        }
        
        try:
            # Read file header to determine format and link type
            with open(pcap_file, 'rb') as f:
                header = f.read(24)  # PCAP global header is 24 bytes
                
            if len(header) >= 24:
                magic = header[:4]
                
                if magic == b'\xd4\xc3\xb2\xa1':  # Original pcap (little endian)
                    info['format'] = 'pcap'
                    info['link_type'] = int.from_bytes(header[20:24], 'little')
                elif magic == b'\xa1\xb2\xc3\xd4':  # Original pcap (big endian)
                    info['format'] = 'pcap'
                    info['link_type'] = int.from_bytes(header[20:24], 'big')
                elif magic == b'\x0a\x0d\x0d\x0a':  # PCAPNG
                    info['format'] = 'pcapng'
                    # PCAPNG link type analysis is more complex, do quick sample
                    info['link_type'] = self._quick_pcapng_analysis(pcap_file)
                    
            # Quick packet sampling to detect RadioTap and 802.11 characteristics
            sample_info = self._quick_packet_sample(pcap_file)
            info.update(sample_info)
            
        except Exception as e:
            self.logger.debug(f"Error analyzing PCAP file: {e}")
            
        return info
    
    def _quick_pcapng_analysis(self, pcap_file: str) -> Optional[int]:
        """Quick analysis of PCAPNG file to determine likely link type."""
        # For PCAPNG files, we'll use a simple heuristic
        # Most wireless captures will be RadioTap (127) or 802.11 (105)
        try:
            # Try to determine from filename or do quick sample
            filename = Path(pcap_file).name.lower()
            if 'wifi' in filename or 'wireless' in filename or '802' in filename:
                return 127  # Assume RadioTap for wireless
            return None
        except:
            return None
    
    def _quick_packet_sample(self, pcap_file: str) -> Dict[str, Any]:
        """
        Sample first few packets to detect wireless characteristics.
        This uses the fastest available parser for quick analysis.
        """
        sample_info = {
            'has_radiotap': False,
            'has_dot11': False,
            'packet_sample_size': 0,
            'wireless_indicators': []
        }
        
        # Try with the most lightweight parser first (dpkt if available)
        if DPKT_AVAILABLE:
            try:
                with open(pcap_file, 'rb') as f:
                    pcap = dpkt.pcap.Reader(f)
                    count = 0
                    
                    for timestamp, buf in pcap:
                        count += 1
                        if count > 10:  # Sample only first 10 packets
                            break
                            
                        # Very basic RadioTap detection (magic bytes)
                        if len(buf) > 4 and buf[0:2] == b'\x00\x00':  # RadioTap version
                            sample_info['has_radiotap'] = True
                            sample_info['wireless_indicators'].append('radiotap_header')
                            
                        # Look for 802.11 management frame patterns
                        if len(buf) > 24:
                            # Check for common 802.11 frame control patterns
                            fc = buf[0] if len(buf) > 0 else 0
                            frame_type = (fc & 0x0C) >> 2
                            if frame_type == 0:  # Management frame
                                sample_info['has_dot11'] = True
                                sample_info['wireless_indicators'].append('mgmt_frames')
                                
                    sample_info['packet_sample_size'] = count
                    
            except Exception as e:
                self.logger.debug(f"dpkt sampling failed: {e}")
                
        # If dpkt failed or unavailable, try quick Scapy sample
        elif SCAPY_AVAILABLE:
            try:
                # Read just first few packets with Scapy
                packets = rdpcap(pcap_file, count=5)
                sample_info['packet_sample_size'] = len(packets)
                
                for packet in packets:
                    if packet.haslayer(RadioTap):
                        sample_info['has_radiotap'] = True
                        sample_info['wireless_indicators'].append('scapy_radiotap')
                    if packet.haslayer(Dot11):
                        sample_info['has_dot11'] = True
                        sample_info['wireless_indicators'].append('scapy_dot11')
                        
            except Exception as e:
                self.logger.debug(f"Scapy sampling failed: {e}")
                
        return sample_info
    
    def _load_with_parser(self, parser_name: str, pcap_file: str, max_packets: Optional[int]) -> Tuple[List[UnifiedPacketInfo], Dict[str, Any]]:
        """Load packets with specific parser."""
        if parser_name == "scapy":
            return self._load_with_scapy(pcap_file, max_packets)
        elif parser_name == "pyshark":
            return self._load_with_pyshark(pcap_file, max_packets)
        elif parser_name == "dpkt":
            return self._load_with_dpkt(pcap_file, max_packets)
        else:
            raise ValueError(f"Unknown parser: {parser_name}")
    
    def _load_with_scapy(self, pcap_file: str, max_packets: Optional[int]) -> Tuple[List[UnifiedPacketInfo], Dict[str, Any]]:
        """Load packets using Scapy."""
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy not available")
            
        # Load raw packets
        raw_packets = rdpcap(pcap_file)
        if max_packets:
            raw_packets = raw_packets[:max_packets]
            
        self.logger.info(f"Scapy loaded {len(raw_packets)} raw packets")
        
        # Convert to unified format
        unified_packets = []
        parsing_errors = {}
        field_success = {'timestamp': 0, 'addresses': 0, 'rssi': 0, 'channel': 0, 'frame_type': 0}
        
        for i, raw_packet in enumerate(raw_packets):
            try:
                unified = self._extract_scapy_info(raw_packet, i)
                unified_packets.append(unified)
                
                # Update field success stats
                if unified.timestamp > 0:
                    field_success['timestamp'] += 1
                if unified.src_mac or unified.dst_mac:
                    field_success['addresses'] += 1
                if unified.rssi is not None:
                    field_success['rssi'] += 1
                if unified.channel is not None:
                    field_success['channel'] += 1
                if unified.frame_type is not None:
                    field_success['frame_type'] += 1
                    
            except Exception as e:
                error_type = type(e).__name__
                parsing_errors[error_type] = parsing_errors.get(error_type, 0) + 1
                self.logger.debug(f"Scapy parsing error on packet {i}: {e}")
                
        metadata = {
            'total_raw_packets': len(raw_packets),
            'successfully_parsed': len(unified_packets),
            'parsing_errors': parsing_errors,
            'field_success_rates': field_success,
            'parser_specific_info': self._analyze_scapy_packets(unified_packets)
        }
        
        return unified_packets, metadata
    
    def _extract_scapy_info(self, packet: ScapyPacket, packet_index: int) -> UnifiedPacketInfo:
        """Extract information from Scapy packet."""
        unified = UnifiedPacketInfo(
            raw_packet=packet,
            packet_index=packet_index,
            timestamp=0.0,
            parsing_library="scapy"
        )
        
        errors = []
        
        # Extract timestamp
        try:
            if hasattr(packet, 'time'):
                time_val = packet.time
                if hasattr(time_val, '__float__'):
                    unified.timestamp = float(time_val)
                elif hasattr(time_val, 'val'):
                    unified.timestamp = float(time_val.val)
                else:
                    unified.timestamp = float(time_val)
        except Exception as e:
            errors.append(f"timestamp: {e}")
            
        # Extract 802.11 information
        if packet.haslayer(Dot11):
            try:
                dot11 = packet[Dot11]
                
                # Addresses
                unified.src_mac = self._normalize_mac(str(dot11.addr2)) if hasattr(dot11, 'addr2') and dot11.addr2 else None
                unified.dst_mac = self._normalize_mac(str(dot11.addr1)) if hasattr(dot11, 'addr1') and dot11.addr1 else None
                unified.bssid = self._normalize_mac(str(dot11.addr3)) if hasattr(dot11, 'addr3') and dot11.addr3 else None
                
                # Frame type info
                unified.frame_type = getattr(dot11, 'type', None)
                unified.frame_subtype = getattr(dot11, 'subtype', None)
                unified.frame_name = self._get_frame_name(unified.frame_type, unified.frame_subtype, packet)
                
                # Frame control flags
                if hasattr(dot11, 'FCfield'):
                    fc_field = getattr(dot11, 'FCfield', 0)
                    if isinstance(fc_field, int):
                        unified.retry = bool(fc_field & 0x08)
                        
            except Exception as e:
                errors.append(f"dot11: {e}")
        else:
            # Not 802.11 - log what it is
            layers = self._get_packet_layers(packet)
            errors.append(f"not_dot11: {' -> '.join(layers)}")
            
        # Extract RadioTap information
        if packet.haslayer(RadioTap):
            try:
                radiotap = packet[RadioTap]
                
                # RSSI
                if hasattr(radiotap, 'dBm_AntSignal'):
                    unified.rssi = int(radiotap.dBm_AntSignal)
                elif hasattr(radiotap, 'dbm_antsignal'):
                    unified.rssi = int(radiotap.dbm_antsignal)
                    
                # Channel/Frequency
                if hasattr(radiotap, 'Channel'):
                    unified.channel = int(radiotap.Channel)
                elif hasattr(radiotap, 'ChannelFrequency'):
                    unified.frequency = int(radiotap.ChannelFrequency)
                    unified.channel = self._freq_to_channel(unified.frequency)
                    
                # Data rate
                if hasattr(radiotap, 'Rate'):
                    rate_val = getattr(radiotap, 'Rate', 0)
                    unified.data_rate = f"{rate_val * 0.5:.1f}Mbps" if rate_val else None
                    
            except Exception as e:
                errors.append(f"radiotap: {e}")
                
        # Extract management frame specifics
        if unified.frame_name in ["beacon", "probe_request", "probe_response"]:
            try:
                # SSID extraction
                if hasattr(packet, 'info') and packet.info:
                    ssid_bytes = packet.info
                    if isinstance(ssid_bytes, bytes):
                        unified.ssid = ssid_bytes.decode('utf-8', errors='ignore')
                    else:
                        unified.ssid = str(ssid_bytes)
                        
                # Beacon interval (for beacons)
                if hasattr(packet, 'beacon_int'):
                    unified.beacon_interval = int(packet.beacon_int)
                    
                # Capabilities
                if hasattr(packet, 'cap'):
                    unified.capabilities = int(packet.cap)
                    
            except Exception as e:
                errors.append(f"mgmt_frame: {e}")
                
        # Check for FCS errors
        if hasattr(packet, 'fcs_bad'):
            unified.fcs_bad = bool(packet.fcs_bad)
            
        unified.parsing_errors = errors
        return unified
    
    def _load_with_pyshark(self, pcap_file: str, max_packets: Optional[int]) -> Tuple[List[UnifiedPacketInfo], Dict[str, Any]]:
        """Load packets using PyShark."""
        if not PYSHARK_AVAILABLE:
            raise ImportError("PyShark not available")
            
        unified_packets = []
        parsing_errors = {}
        packet_count = 0
        
        try:
            # Try WLAN filter first, but fallback to no filter if needed
            cap = None
            packet_count = 0
            
            # First try with WLAN filter for optimal performance
            try:
                cap = pyshark.FileCapture(pcap_file, display_filter='wlan')
                # Test if we can read at least one packet with WLAN filter
                test_packet = next(iter(cap), None)
                if test_packet:
                    cap.close()  # Close and reopen to reset
                    cap = pyshark.FileCapture(pcap_file, display_filter='wlan')
                else:
                    # WLAN filter returned no packets, try without filter
                    cap.close()
                    cap = None
            except Exception:
                if cap:
                    cap.close()
                cap = None
                
            # Fallback to no filter if WLAN filter failed
            if cap is None:
                self.logger.info("PyShark WLAN filter failed, trying without filter")
                cap = pyshark.FileCapture(pcap_file)
            
            for packet in cap:
                if max_packets and packet_count >= max_packets:
                    break
                    
                try:
                    unified = self._extract_pyshark_info(packet, packet_count)
                    # Only include packets that have some 802.11 information
                    if unified and (unified.frame_type is not None or hasattr(packet, 'wlan')):
                        unified_packets.append(unified)
                except Exception as e:
                    error_type = type(e).__name__
                    parsing_errors[error_type] = parsing_errors.get(error_type, 0) + 1
                    self.logger.debug(f"PyShark parsing error on packet {packet_count}: {e}")
                    
                packet_count += 1
                
            cap.close()
            
        except Exception as e:
            raise Exception(f"PyShark capture failed: {e}")
            
        # Determine if WLAN filter was used
        used_wlan_filter = 'wlan' in (cap.display_filter or '') if hasattr(cap, 'display_filter') else False
        
        metadata = {
            'total_raw_packets': packet_count,
            'successfully_parsed': len(unified_packets),
            'parsing_errors': parsing_errors,
            'parser_specific_info': {
                'filtered_for_wlan': used_wlan_filter,
                'filter_used': cap.display_filter if hasattr(cap, 'display_filter') else None
            }
        }
        
        return unified_packets, metadata
    
    def _extract_pyshark_info(self, packet, packet_index: int) -> UnifiedPacketInfo:
        """Extract information from PyShark packet."""
        unified = UnifiedPacketInfo(
            raw_packet=packet,
            packet_index=packet_index,
            timestamp=float(packet.sniff_time.timestamp()) if hasattr(packet, 'sniff_time') else 0.0,
            parsing_library="pyshark"
        )
        
        # Extract WLAN information
        if hasattr(packet, 'wlan'):
            wlan = packet.wlan
            
            unified.src_mac = self._normalize_mac(getattr(wlan, 'sa', None))
            unified.dst_mac = self._normalize_mac(getattr(wlan, 'da', None))
            unified.bssid = self._normalize_mac(getattr(wlan, 'bssid', None))
            
            # Frame type
            fc_type = getattr(wlan, 'fc_type', None)
            fc_subtype = getattr(wlan, 'fc_subtype', None)
            if fc_type is not None:
                unified.frame_type = int(fc_type)
            if fc_subtype is not None:
                unified.frame_subtype = int(fc_subtype)
            unified.frame_name = self._get_frame_name(unified.frame_type, unified.frame_subtype)
            
            # SSID and other fields
            unified.ssid = getattr(wlan, 'ssid', None)
            
            # Channel
            if hasattr(wlan, 'channel'):
                try:
                    unified.channel = int(wlan.channel)
                except:
                    pass
                    
        # Extract RadioTap information
        if hasattr(packet, 'radiotap'):
            radiotap = packet.radiotap
            
            if hasattr(radiotap, 'dbm_antsignal'):
                try:
                    unified.rssi = int(radiotap.dbm_antsignal)
                except:
                    pass
                    
            if hasattr(radiotap, 'channel_freq'):
                try:
                    unified.frequency = int(radiotap.channel_freq)
                    if not unified.channel:
                        unified.channel = self._freq_to_channel(unified.frequency)
                except:
                    pass
                    
        return unified
    
    def _load_with_dpkt(self, pcap_file: str, max_packets: Optional[int]) -> Tuple[List[UnifiedPacketInfo], Dict[str, Any]]:
        """Load packets using dpkt (basic implementation for now)."""
        if not DPKT_AVAILABLE:
            raise ImportError("dpkt not available")
            
        # This is a placeholder - full dpkt 802.11 implementation would be more complex
        unified_packets = []
        packet_count = 0
        
        with open(pcap_file, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            
            for timestamp, buf in pcap:
                if max_packets and packet_count >= max_packets:
                    break
                    
                unified = UnifiedPacketInfo(
                    raw_packet=buf,
                    packet_index=packet_count,
                    timestamp=timestamp,
                    parsing_library="dpkt",
                    frame_name="dpkt_raw"
                )
                
                unified_packets.append(unified)
                packet_count += 1
                
        metadata = {
            'total_raw_packets': packet_count,
            'successfully_parsed': len(unified_packets),
            'parsing_errors': {},
            'parser_specific_info': {'note': 'dpkt implementation is basic'}
        }
        
        return unified_packets, metadata
    
    def _get_packet_layers(self, packet) -> List[str]:
        """Get list of packet layer names."""
        layers = []
        layer = packet
        while layer and len(layers) < 10:  # Prevent infinite loops
            layers.append(layer.__class__.__name__)
            layer = layer.payload if hasattr(layer, 'payload') else None
        return layers
    
    def _get_frame_name(self, frame_type: Optional[int], frame_subtype: Optional[int], packet=None) -> str:
        """Get human-readable frame name."""
        if frame_type is None:
            return "unknown"
            
        if frame_type == 0:  # Management
            if frame_subtype == 8:
                return "beacon"
            elif frame_subtype == 4:
                return "probe_request"
            elif frame_subtype == 5:
                return "probe_response"
            elif frame_subtype == 11:
                return "authentication"
            elif frame_subtype == 0:
                return "association_request"
            elif frame_subtype == 1:
                return "association_response"
            elif frame_subtype == 12:
                return "deauthentication"
            elif frame_subtype == 10:
                return "disassociation"
            else:
                return f"management_{frame_subtype}"
        elif frame_type == 1:  # Control
            return f"control_{frame_subtype}"
        elif frame_type == 2:  # Data
            return f"data_{frame_subtype}"
        else:
            return f"type_{frame_type}_subtype_{frame_subtype}"
    
    def _normalize_mac(self, mac: Optional[str]) -> Optional[str]:
        """Normalize MAC address format."""
        if not mac or mac == "None":
            return None
        try:
            return str(mac).lower().replace('-', ':')
        except:
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
    
    def _analyze_scapy_packets(self, packets: List[UnifiedPacketInfo]) -> Dict[str, Any]:
        """Analyze Scapy-parsed packets for metadata."""
        stats = {
            'frame_types': {},
            'channels': set(),
            'ssids': set(),
            'field_availability': {
                'rssi': 0,
                'channel': 0,
                'ssid': 0,
                'addresses': 0
            }
        }
        
        for packet in packets:
            # Frame type distribution
            stats['frame_types'][packet.frame_name] = stats['frame_types'].get(packet.frame_name, 0) + 1
            
            # Collect unique values
            if packet.channel:
                stats['channels'].add(packet.channel)
            if packet.ssid:
                stats['ssids'].add(packet.ssid)
                
            # Field availability
            if packet.rssi is not None:
                stats['field_availability']['rssi'] += 1
            if packet.channel is not None:
                stats['field_availability']['channel'] += 1
            if packet.ssid:
                stats['field_availability']['ssid'] += 1
            if packet.src_mac or packet.dst_mac:
                stats['field_availability']['addresses'] += 1
                
        # Convert sets to lists
        stats['channels'] = list(stats['channels'])
        stats['ssids'] = list(stats['ssids'])
        
        return stats
    
    def get_stats(self) -> Dict[str, Any]:
        """Get loader statistics."""
        return self.stats.copy()