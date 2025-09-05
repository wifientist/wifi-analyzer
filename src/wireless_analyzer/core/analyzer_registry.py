"""
Analyzer Registry for Dual-Pipeline Analysis

This module provides a centralized registry for managing both Scapy and PyShark
analyzers, enabling comprehensive comparison and analysis across both parsers.
"""

import logging
from typing import Dict, List, Any, Optional, Type, Tuple
from dataclasses import dataclass, field

# Import all Scapy analyzers
from ..analyzers.scapy.baseline.beacon_inventory import ScapyBeaconInventoryAnalyzer
from ..analyzers.scapy.baseline.beacon_analyzer import ScapyBeaconAnalyzer
from ..analyzers.scapy.baseline.auth_assoc_flow import ScapyAuthAssocFlowAnalyzer
from ..analyzers.scapy.baseline.capture_validator import ScapyCaptureQualityAnalyzer
from ..analyzers.scapy.baseline.eapol_pmf import ScapyEAPOLPMFAnalyzer
from ..analyzers.scapy.baseline.probe_behavior import ScapyProbeBehaviorAnalyzer
from ..analyzers.scapy.baseline.signal_quality import ScapySignalQualityAnalyzer
from ..analyzers.scapy.security.deauth_detector import ScapyDeauthFloodDetector
from ..analyzers.scapy.security.wpa_security_posture import ScapyWPASecurityPostureAnalyzer
from ..analyzers.scapy.security.rogue_ap_threats import ScapyRogueAPSecurityAnalyzer
from ..analyzers.scapy.security.enterprise_security import ScapyEnterpriseSecurityAnalyzer

# Import all PyShark analyzers
from ..analyzers.pyshark.baseline.beacon_inventory import PySharkBeaconInventoryAnalyzer
from ..analyzers.pyshark.baseline.beacon_analyzer import PySharkBeaconAnalyzer
from ..analyzers.pyshark.baseline.auth_assoc_flow import PySharkAuthAssocFlowAnalyzer
from ..analyzers.pyshark.baseline.capture_validator import PySharkCaptureQualityAnalyzer
from ..analyzers.pyshark.baseline.eapol_pmf import PySharkEAPOLPMFAnalyzer
from ..analyzers.pyshark.baseline.probe_behavior import PySharkProbeBehaviorAnalyzer
from ..analyzers.pyshark.baseline.signal_quality import PySharkSignalQualityAnalyzer
from ..analyzers.pyshark.security.deauth_detector import PySharkDeauthFloodDetector
from ..analyzers.pyshark.security.wpa_security_posture import PySharkWPASecurityPostureAnalyzer
from ..analyzers.pyshark.security.rogue_ap_threats import PySharkRogueAPSecurityAnalyzer
from ..analyzers.pyshark.security.enterprise_security import PySharkEnterpriseSecurityAnalyzer


@dataclass
class AnalyzerPair:
    """A pair of corresponding Scapy and PyShark analyzers."""
    name: str
    category: str
    scapy_class: Type
    pyshark_class: Type
    description: str
    enabled: bool = True
    analysis_order: int = 100


class AnalyzerRegistry:
    """
    Registry for managing analyzer pairs and their execution.
    
    This class maintains pairs of corresponding Scapy and PyShark analyzers,
    enabling parallel analysis and result comparison.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self._analyzer_pairs: Dict[str, AnalyzerPair] = {}
        self._initialize_analyzer_pairs()
    
    def _initialize_analyzer_pairs(self):
        """Initialize all analyzer pairs."""

        self.logger.info("Initializing analyzer pairs...")

        # Baseline analyzers
        self._register_pair(
            "beacon_inventory",
            "baseline",
            ScapyBeaconInventoryAnalyzer,
            PySharkBeaconInventoryAnalyzer,
            "Beacon frame inventory and BSS analysis",
            analysis_order=10
        )

        self._register_pair(
            "beacon_analyzer",
            "baseline",
            ScapyBeaconAnalyzer,
            PySharkBeaconAnalyzer,
            "Beacon frame content and capabilities analysis",
            analysis_order=15
        )

        self._register_pair(
            "auth_assoc_flow",
            "baseline",
            ScapyAuthAssocFlowAnalyzer,
            PySharkAuthAssocFlowAnalyzer,
            "Authentication and association flow analysis",
            analysis_order=20
        )
        
        self._register_pair(
            "capture_validator",
            "baseline",
            ScapyCaptureQualityAnalyzer,
            PySharkCaptureQualityAnalyzer,
            "Capture quality validation and monitor mode verification",
            analysis_order=30
        )
        
        self._register_pair(
            "eapol_pmf",
            "baseline",
            ScapyEAPOLPMFAnalyzer,
            PySharkEAPOLPMFAnalyzer,
            "EAPOL and PMF security analysis",
            analysis_order=40
        )
        
        self._register_pair(
            "probe_behavior",
            "baseline",
            ScapyProbeBehaviorAnalyzer,
            PySharkProbeBehaviorAnalyzer,
            "Probe request behavior and privacy analysis",
            analysis_order=50
        )
        
        self._register_pair(
            "signal_quality",
            "baseline",
            ScapySignalQualityAnalyzer,
            PySharkSignalQualityAnalyzer,
            "RF signal quality and channel analysis",
            analysis_order=60
        )
        
        # Security analyzers
        self._register_pair(
            "deauth_detector",
            "security",
            ScapyDeauthFloodDetector,
            PySharkDeauthFloodDetector,
            "Deauthentication attack detection",
            analysis_order=70
        )
        
        self._register_pair(
            "wpa_security_posture",
            "security",
            ScapyWPASecurityPostureAnalyzer,
            PySharkWPASecurityPostureAnalyzer,
            "WPA2/WPA3 security posture analysis",
            analysis_order=80
        )
        
        self._register_pair(
            "rogue_ap_threats",
            "security",
            ScapyRogueAPSecurityAnalyzer,
            PySharkRogueAPSecurityAnalyzer,
            "Rogue AP and security threat detection",
            analysis_order=90
        )
        
        self._register_pair(
            "enterprise_security",
            "security",
            ScapyEnterpriseSecurityAnalyzer,
            PySharkEnterpriseSecurityAnalyzer,
            "Enterprise 802.1X/EAP security analysis",
            analysis_order=100
        )
        
        self.logger.info(f"Registered {len(self._analyzer_pairs)} analyzer pairs")
    
    def _register_pair(
        self,
        name: str,
        category: str,
        scapy_class: Type,
        pyshark_class: Type,
        description: str,
        enabled: bool = True,
        analysis_order: int = 100
    ):
        """Register an analyzer pair."""
        pair = AnalyzerPair(
            name=name,
            category=category,
            scapy_class=scapy_class,
            pyshark_class=pyshark_class,
            description=description,
            enabled=enabled,
            analysis_order=analysis_order
        )
        self._analyzer_pairs[name] = pair
    
    def get_analyzer_pairs(self, enabled_only: bool = True) -> Dict[str, AnalyzerPair]:
        """Get all analyzer pairs, optionally filtered by enabled status."""
        if enabled_only:
            return {name: pair for name, pair in self._analyzer_pairs.items() if pair.enabled}
        return dict(self._analyzer_pairs)
    
    def get_analyzer_pair(self, name: str) -> Optional[AnalyzerPair]:
        """Get a specific analyzer pair by name."""
        return self._analyzer_pairs.get(name)
    
    def get_scapy_analyzers(self, enabled_only: bool = True) -> Dict[str, Type]:
        """Get all Scapy analyzer classes."""
        pairs = self.get_analyzer_pairs(enabled_only)
        return {name: pair.scapy_class for name, pair in pairs.items()}
    
    def get_pyshark_analyzers(self, enabled_only: bool = True) -> Dict[str, Type]:
        """Get all PyShark analyzer classes."""
        pairs = self.get_analyzer_pairs(enabled_only)
        return {name: pair.pyshark_class for name, pair in pairs.items()}
    
    def create_scapy_analyzers(
        self, 
        enabled_only: bool = True,
        filter_categories: Optional[List[str]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Create instances of all Scapy analyzers."""
        pairs = self.get_analyzer_pairs(enabled_only)
        analyzers = {}
        
        for name, pair in pairs.items():
            if filter_categories and pair.category not in filter_categories:
                continue
                
            try:
                analyzer = pair.scapy_class(**kwargs)
                analyzers[name] = analyzer
                self.logger.debug(f"Created Scapy analyzer: {name}")
            except Exception as e:
                self.logger.error(f"Failed to create Scapy analyzer {name}: {e}")
        
        return analyzers
    
    def create_pyshark_analyzers(
        self, 
        enabled_only: bool = True,
        filter_categories: Optional[List[str]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Create instances of all PyShark analyzers."""
        pairs = self.get_analyzer_pairs(enabled_only)
        analyzers = {}
        
        for name, pair in pairs.items():
            if filter_categories and pair.category not in filter_categories:
                continue
                
            try:
                analyzer = pair.pyshark_class(**kwargs)
                analyzers[name] = analyzer
                self.logger.debug(f"Created PyShark analyzer: {name}")
            except Exception as e:
                self.logger.error(f"Failed to create PyShark analyzer {name}: {e}")
        
        return analyzers
    
    def enable_analyzer(self, name: str) -> bool:
        """Enable a specific analyzer pair."""
        if name in self._analyzer_pairs:
            self._analyzer_pairs[name].enabled = True
            self.logger.info(f"Enabled analyzer pair: {name}")
            return True
        return False
    
    def disable_analyzer(self, name: str) -> bool:
        """Disable a specific analyzer pair."""
        if name in self._analyzer_pairs:
            self._analyzer_pairs[name].enabled = False
            self.logger.info(f"Disabled analyzer pair: {name}")
            return True
        return False
    
    def get_analysis_categories(self) -> List[str]:
        """Get all unique analysis categories."""
        categories = set()
        for pair in self._analyzer_pairs.values():
            categories.add(pair.category)
        return sorted(list(categories))
    
    def get_registry_summary(self) -> Dict[str, Any]:
        """Get summary of the analyzer registry."""
        pairs = self.get_analyzer_pairs(enabled_only=False)
        enabled_pairs = self.get_analyzer_pairs(enabled_only=True)
        
        categories = {}
        for pair in pairs.values():
            if pair.category not in categories:
                categories[pair.category] = {"total": 0, "enabled": 0}
            categories[pair.category]["total"] += 1
            if pair.enabled:
                categories[pair.category]["enabled"] += 1
        
        return {
            "total_analyzer_pairs": len(pairs),
            "enabled_analyzer_pairs": len(enabled_pairs),
            "categories": categories,
            "analyzer_list": {
                name: {
                    "category": pair.category,
                    "description": pair.description,
                    "enabled": pair.enabled,
                    "analysis_order": pair.analysis_order
                }
                for name, pair in pairs.items()
            }
        }


# Global registry instance
analyzer_registry = AnalyzerRegistry()