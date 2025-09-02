"""
Core data models for wireless PCAP analysis framework.

This module defines the fundamental data structures used throughout
the analysis framework, including findings, results, and enums.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Any, Optional, Set, Union
import json


class Severity(Enum):
    """Severity levels for analysis findings."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    ERROR = "error"


class AnalysisCategory(Enum):
    """Analysis categories based on the comprehensive wireless checklist."""
    # Core analysis categories from the checklist
    CAPTURE_QUALITY = "capture_quality"
    RF_PHY = "rf_phy" 
    BEACONS = "beacons"
    PROBE_BEHAVIOR = "probe_behavior"
    AUTH_ASSOC = "auth_assoc"
    ENTERPRISE_SECURITY = "enterprise_security"
    EAPOL_HANDSHAKE = "eapol_handshake"
    DATA_CONTROL_PLANE = "data_control_plane"
    QOS_WMM = "qos_wmm"
    POWER_SAVE = "power_save"
    ROAMING_STEERING = "roaming_steering"
    MULTICAST_BROADCAST = "multicast_broadcast"
    IP_ONBOARDING = "ip_onboarding"
    COEXISTENCE_DFS = "coexistence_dfs"
    SECURITY_THREATS = "security_threats"
    BAND_6GHZ = "band_6ghz"
    MLO_BE = "mlo_be"
    CLIENT_PROFILING = "client_profiling"
    AP_BEHAVIOR = "ap_behavior"
    APP_PERFORMANCE = "app_performance"
    HOTSPOT_PASSPOINT = "hotspot_passpoint"
    METRICS_COMPUTATION = "metrics_computation"
    ANOMALY_DETECTION = "anomaly_detection"


class FrameType(Enum):
    """802.11 frame types for analysis categorization."""
    MANAGEMENT = "management"
    CONTROL = "control" 
    DATA = "data"
    EXTENSION = "extension"


class SecurityProtocol(Enum):
    """Security protocols and methods."""
    OPEN = "open"
    WEP = "wep"
    WPA = "wpa"
    WPA2 = "wpa2"
    WPA3 = "wpa3"
    OWE = "owe"
    SAE = "sae"
    EAP_TLS = "eap_tls"
    PEAP = "peap"
    EAP_TTLS = "eap_ttls"
    EAP_FAST = "eap_fast"


@dataclass
class PacketReference:
    """Reference to a specific packet in the capture."""
    packet_index: int
    timestamp: float
    frame_number: Optional[int] = None
    offset: Optional[int] = None


@dataclass 
class NetworkEntity:
    """Represents a network entity (AP, STA, etc.)."""
    mac_address: str
    entity_type: str  # "ap", "sta", "unknown"
    vendor_oui: Optional[str] = None
    capabilities: Dict[str, Any] = field(default_factory=dict)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


@dataclass
class Finding:
    """Represents a single analysis finding."""
    category: AnalysisCategory
    severity: Severity
    title: str
    description: str
    timestamp: datetime = field(default_factory=datetime.now)
    details: Dict[str, Any] = field(default_factory=dict)
    packet_refs: List[PacketReference] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    # Contextual information
    bssid: Optional[str] = None
    ssid: Optional[str] = None
    station_mac: Optional[str] = None
    channel: Optional[int] = None
    frequency: Optional[int] = None
    rssi: Optional[float] = None
    data_rate: Optional[str] = None
    frame_types_involved: List[FrameType] = field(default_factory=list)
    
    # Analysis metadata
    analyzer_name: Optional[str] = None
    analyzer_version: Optional[str] = None
    confidence: float = 1.0  # Confidence score 0.0-1.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for serialization."""
        return {
            'category': self.category.value,
            'severity': self.severity.value,
            'title': self.title,
            'description': self.description,
            'timestamp': self.timestamp.isoformat(),
            'details': self.details,
            'packet_refs': [
                {
                    'packet_index': ref.packet_index,
                    'timestamp': ref.timestamp,
                    'frame_number': ref.frame_number,
                    'offset': ref.offset
                }
                for ref in self.packet_refs
            ],
            'recommendations': self.recommendations,
            'bssid': self.bssid,
            'ssid': self.ssid,
            'station_mac': self.station_mac,
            'channel': self.channel,
            'frequency': self.frequency,
            'rssi': self.rssi,
            'data_rate': self.data_rate,
            'frame_types_involved': [ft.value for ft in self.frame_types_involved],
            'analyzer_name': self.analyzer_name,
            'analyzer_version': self.analyzer_version,
            'confidence': self.confidence
        }


@dataclass
class AnalysisMetrics:
    """Comprehensive metrics computed during analysis."""
    # Basic statistics
    total_packets: int = 0
    analysis_duration_seconds: float = 0.0
    capture_duration_seconds: float = 0.0
    
    # Frame type distribution
    management_frames: int = 0
    control_frames: int = 0
    data_frames: int = 0
    
    # Protocol distribution  
    beacon_frames: int = 0
    probe_requests: int = 0
    probe_responses: int = 0
    auth_frames: int = 0
    assoc_frames: int = 0
    deauth_frames: int = 0
    disassoc_frames: int = 0
    eapol_frames: int = 0
    
    # Quality metrics
    fcs_errors: int = 0
    retry_frames: int = 0
    duplicate_frames: int = 0
    
    # Network entities
    unique_aps: int = 0
    unique_stations: int = 0
    unique_ssids: int = 0
    unique_bssids: int = 0
    
    # Channel and RF
    channels_observed: Set[int] = field(default_factory=set)
    frequency_bands: Set[str] = field(default_factory=set)  # "2.4GHz", "5GHz", "6GHz"
    
    # Timing
    first_packet_time: Optional[datetime] = None
    last_packet_time: Optional[datetime] = None
    
    # Performance indicators
    average_rssi: Optional[float] = None
    rssi_std_dev: Optional[float] = None
    data_rates_observed: Set[str] = field(default_factory=set)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary."""
        return {
            'total_packets': self.total_packets,
            'analysis_duration_seconds': self.analysis_duration_seconds,
            'capture_duration_seconds': self.capture_duration_seconds,
            'frame_distribution': {
                'management': self.management_frames,
                'control': self.control_frames,
                'data': self.data_frames
            },
            'protocol_distribution': {
                'beacon': self.beacon_frames,
                'probe_request': self.probe_requests,
                'probe_response': self.probe_responses,
                'auth': self.auth_frames,
                'assoc': self.assoc_frames,
                'deauth': self.deauth_frames,
                'disassoc': self.disassoc_frames,
                'eapol': self.eapol_frames
            },
            'quality_metrics': {
                'fcs_errors': self.fcs_errors,
                'retry_frames': self.retry_frames,
                'duplicate_frames': self.duplicate_frames,
                'fcs_error_rate': self.fcs_errors / max(self.total_packets, 1)
            },
            'network_entities': {
                'unique_aps': self.unique_aps,
                'unique_stations': self.unique_stations,
                'unique_ssids': self.unique_ssids,
                'unique_bssids': self.unique_bssids
            },
            'rf_metrics': {
                'channels_observed': list(self.channels_observed),
                'frequency_bands': list(self.frequency_bands),
                'average_rssi': self.average_rssi,
                'rssi_std_dev': self.rssi_std_dev,
                'data_rates_observed': list(self.data_rates_observed)
            },
            'timing': {
                'first_packet_time': self.first_packet_time.isoformat() if self.first_packet_time else None,
                'last_packet_time': self.last_packet_time.isoformat() if self.last_packet_time else None,
                'capture_duration_seconds': self.capture_duration_seconds
            }
        }


@dataclass
class AnalysisResults:
    """Container for comprehensive analysis results."""
    pcap_file: str
    analysis_timestamp: datetime = field(default_factory=datetime.now)
    findings: List[Finding] = field(default_factory=list)
    metrics: AnalysisMetrics = field(default_factory=AnalysisMetrics)
    network_entities: Dict[str, NetworkEntity] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Analysis configuration
    analyzers_run: List[str] = field(default_factory=list)
    analysis_config: Dict[str, Any] = field(default_factory=dict)
    
    def add_finding(self, finding: Finding):
        """Add a finding to the results."""
        self.findings.append(finding)
    
    def get_findings_by_category(self, category: AnalysisCategory) -> List[Finding]:
        """Get all findings for a specific category."""
        return [f for f in self.findings if f.category == category]
    
    def get_findings_by_severity(self, severity: Severity) -> List[Finding]:
        """Get all findings with a specific severity."""
        return [f for f in self.findings if f.severity == severity]
    
    def get_findings_by_bssid(self, bssid: str) -> List[Finding]:
        """Get all findings related to a specific BSSID."""
        return [f for f in self.findings if f.bssid == bssid]
    
    def get_findings_by_station(self, station_mac: str) -> List[Finding]:
        """Get all findings related to a specific station."""
        return [f for f in self.findings if f.station_mac == station_mac]
    
    def get_high_confidence_findings(self, min_confidence: float = 0.8) -> List[Finding]:
        """Get findings with confidence above threshold."""
        return [f for f in self.findings if f.confidence >= min_confidence]
    
    def add_network_entity(self, entity: NetworkEntity):
        """Add or update a network entity."""
        self.network_entities[entity.mac_address] = entity
    
    def get_summary_stats(self) -> Dict[str, Any]:
        """Get summary statistics of the analysis."""
        return {
            'total_findings': len(self.findings),
            'findings_by_severity': {
                s.value: len(self.get_findings_by_severity(s)) 
                for s in Severity
            },
            'findings_by_category': {
                c.value: len(self.get_findings_by_category(c)) 
                for c in AnalysisCategory
            },
            'network_entities': len(self.network_entities),
            'analyzers_run': len(self.analyzers_run),
            'analysis_duration': self.metrics.analysis_duration_seconds,
            'capture_duration': self.metrics.capture_duration_seconds
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert results to dictionary for serialization."""
        return {
            'pcap_file': self.pcap_file,
            'analysis_timestamp': self.analysis_timestamp.isoformat(),
            'findings': [f.to_dict() for f in self.findings],
            'metrics': self.metrics.to_dict(),
            'network_entities': {
                mac: {
                    'mac_address': entity.mac_address,
                    'entity_type': entity.entity_type,
                    'vendor_oui': entity.vendor_oui,
                    'capabilities': entity.capabilities,
                    'first_seen': entity.first_seen.isoformat() if entity.first_seen else None,
                    'last_seen': entity.last_seen.isoformat() if entity.last_seen else None
                }
                for mac, entity in self.network_entities.items()
            },
            'metadata': self.metadata,
            'analyzers_run': self.analyzers_run,
            'analysis_config': self.analysis_config,
            'summary': self.get_summary_stats()
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Convert results to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)
    
    def save_to_file(self, output_path: str):
        """Save results to JSON file."""
        with open(output_path, 'w') as f:
            f.write(self.to_json())


@dataclass
class AnalysisContext:
    """Context information shared across analyzers."""
    pcap_file: str
    packet_count: int
    start_time: float
    end_time: float
    duration: float
    
    # Shared data structures for cross-analyzer communication
    network_entities: Dict[str, NetworkEntity] = field(default_factory=dict)
    handshake_sessions: Dict[str, List] = field(default_factory=dict)
    roaming_events: List[Dict] = field(default_factory=list)
    security_context: Dict[str, Any] = field(default_factory=dict)
    
    # Analysis configuration
    config: Dict[str, Any] = field(default_factory=dict)
    
    def get_entity(self, mac_address: str) -> Optional[NetworkEntity]:
        """Get network entity by MAC address."""
        return self.network_entities.get(mac_address)
    
    def add_entity(self, entity: NetworkEntity):
        """Add or update network entity."""
        self.network_entities[entity.mac_address] = entity
    
    def get_config(self, key: str, default: Any = None) -> Any:
        """Get configuration value."""
        return self.config.get(key, default)


# Exception classes for the framework
class AnalysisError(Exception):
    """Base exception for analysis errors."""
    pass


class PacketParsingError(AnalysisError):
    """Exception raised when packet parsing fails."""
    pass


class AnalyzerError(AnalysisError):
    """Exception raised by analyzers during analysis."""
    pass


class ConfigurationError(AnalysisError):
    """Exception raised for configuration issues."""
    pass
