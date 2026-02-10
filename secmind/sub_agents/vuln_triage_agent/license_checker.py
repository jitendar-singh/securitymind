"""
License checking functionality for multiple package ecosystems.
"""

import logging
from typing import Optional, Dict, Any
from functools import lru_cache
from .models import LicenseResult, Ecosystem
from .utils import is_copyleft_license, detect_ecosystem
from .http_client import get_http_client
from .constants import APIEndpoints, COPYLEFT_LICENSES

logger = logging.getLogger(__name__)


class EcosystemHandler:
    """Base class for ecosystem-specific license handlers."""
    
    def __init__(self, http_client):
        """Initialize handler with HTTP client."""
        self.http_client = http_client
    
    def get_license(self, package_name: str) -> Optional[str]:
        """
        Get license for a package.
        
        Args:
            package_name: Package name
            
        Returns:
            License identifier or None
        """
        raise NotImplementedError


class PyPIHandler(EcosystemHandler):
    """Handler for Python Package Index (PyPI)."""
    
    def get_license(self, package_name: str) -> Optional[str]:
        """Get license from PyPI."""
        url = APIEndpoints.PYPI.format(package=package_name)
        logger.debug(f"Checking PyPI for {package_name}")
        
        data = self.http_client.get_json(url)
        if data and 'info' in data:
            license_info = data['info'].get('license', 'Unknown')
            logger.info(f"PyPI license for {package_name}: {license_info}")
            return license_info
        
        return None


class NPMHandler(EcosystemHandler):
    """Handler for Node Package Manager (NPM)."""
    
    def get_license(self, package_name: str) -> Optional[str]:
        """Get license from NPM registry."""
        url = APIEndpoints.NPM.format(package=package_name)
        logger.debug(f"Checking NPM for {package_name}")
        
        data = self.http_client.get_json(url)
        if data:
            license_info = data.get('license', 'Unknown')
            
            # Handle complex license structures
            if isinstance(license_info, dict):
                license_info = license_info.get('type', 'Unknown')
            
            logger.info(f"NPM license for {package_name}: {license_info}")
            return license_info
        
        return None


class MavenHandler(EcosystemHandler):
    """Handler for Maven Central."""
    
    def get_license(self, package_name: str) -> Optional[str]:
        """Get license from Maven Central."""
        # Parse group:artifact format
        if ':' in package_name:
            group, artifact = package_name.split(':', 1)
        else:
            # Assume last part is artifact
            parts = package_name.split('.')
            artifact = parts[-1]
            group = '.'.join(parts[:-1])
        
        logger.debug(f"Checking Maven Central for {group}:{artifact}")
        
        # Query Maven Central search API
        params = {
            'q': f'g:"{group}" AND a:"{artifact}"',
            'rows': 1,
            'wt': 'json'
        }
        
        data = self.http_client.get_json(APIEndpoints.MAVEN_CENTRAL, params=params)
        
        if data and 'response' in data and 'docs' in data['response']:
            docs = data['response']['docs']
            if docs:
                # Maven Central doesn't directly provide license in search API
                # Would need to fetch POM file for accurate license
                logger.warning(f"Maven license lookup requires POM parsing for {package_name}")
                return "Requires POM analysis"
        
        return None


class ClearlyDefinedHandler:
    """Handler for ClearlyDefined API (fallback)."""
    
    def __init__(self, http_client):
        """Initialize handler with HTTP client."""
        self.http_client = http_client
    
    def get_license(self, package_name: str, ecosystem: str) -> Optional[str]:
        """
        Get license from ClearlyDefined.
        
        Args:
            package_name: Package name
            ecosystem: Package ecosystem
            
        Returns:
            License identifier or None
        """
        # ClearlyDefined uses format: type/provider/namespace/name/revision
        # Simplified approach for common cases
        url = APIEndpoints.CLEARLY_DEFINED.format(
            ecosystem=ecosystem,
            package=package_name
        )
        
        logger.debug(f"Checking ClearlyDefined for {ecosystem}/{package_name}")
        
        data = self.http_client.get_json(url)
        if data and 'licensed' in data:
            license_info = data['licensed'].get('declared', 'Unknown')
            logger.info(f"ClearlyDefined license for {package_name}: {license_info}")
            return license_info
        
        return None


class LicenseChecker:
    """Main license checking orchestrator."""
    
    def __init__(self, search_agent=None):
        """
        Initialize license checker with ecosystem handlers.
        
        Args:
            search_agent: Optional search agent for Google searches
        """
        self.http_client = get_http_client()
        self.search_agent = search_agent
        
        self.handlers = {
            Ecosystem.PYPI: PyPIHandler(self.http_client),
            Ecosystem.NPM: NPMHandler(self.http_client),
            Ecosystem.MAVEN: MavenHandler(self.http_client),
        }
        
        self.fallback_handler = ClearlyDefinedHandler(self.http_client)
    
    def check(self, package_name: str, ecosystem: Optional[str] = None) -> LicenseResult:
        """
        Check license for a package.
        
        Args:
            package_name: Package name
            ecosystem: Package ecosystem (auto-detected if None)
            
        Returns:
            LicenseResult with license info and copyleft status
        """
        # Auto-detect ecosystem if not provided
        if not ecosystem:
            ecosystem = detect_ecosystem(package_name)
            logger.info(f"Auto-detected ecosystem for {package_name}: {ecosystem}")
        
        ecosystem_lower = ecosystem.lower()
        
        # Try ecosystem-specific handler
        license_info = self._try_ecosystem_handler(package_name, ecosystem_lower)
        
        # Fallback to ClearlyDefined
        if not license_info or license_info == 'Unknown':
            logger.info(f"Trying ClearlyDefined fallback for {package_name}")
            license_info = self.fallback_handler.get_license(package_name, ecosystem_lower)
        
        # Final fallback - just return Unknown, don't try to search here
        # The agent will handle the search separately
        if not license_info:
            license_info = 'Unknown'
        
        # Check if copyleft
        is_copyleft = is_copyleft_license(license_info, COPYLEFT_LICENSES)
        
        result: LicenseResult = {
            "license": license_info,
            "ecosystem": ecosystem_lower,
            "is_copyleft": is_copyleft
        }
        
        logger.info(f"License check result for {package_name}: {result}")
        return result
    
    def _try_ecosystem_handler(self, package_name: str, ecosystem: str) -> Optional[str]:
        """
        Try to get license using ecosystem-specific handler.
        
        Args:
            package_name: Package name
            ecosystem: Package ecosystem
            
        Returns:
            License identifier or None
        """
        try:
            ecosystem_enum = Ecosystem(ecosystem)
        except ValueError:
            logger.warning(f"Unknown ecosystem: {ecosystem}")
            return None
        
        handler = self.handlers.get(ecosystem_enum)
        if not handler:
            logger.warning(f"No handler for ecosystem: {ecosystem}")
            return None
        
        try:
            return handler.get_license(package_name)
        except Exception as e:
            logger.error(f"Handler failed for {package_name} ({ecosystem}): {e}")
            return None


# Global license checker instance
_license_checker: Optional[LicenseChecker] = None


def set_search_agent(search_agent):
    """
    Set the search agent for license lookups.
    
    Args:
        search_agent: The search agent instance
    """
    global _license_checker
    _license_checker = LicenseChecker(search_agent=search_agent)


def get_license_checker() -> LicenseChecker:
    """Get or create global license checker instance."""
    global _license_checker
    if _license_checker is None:
        _license_checker = LicenseChecker()
    return _license_checker


# Create tool function for agent
@lru_cache(maxsize=1000)
def check_package_license(package_name: str, ecosystem: Optional[str] = None) -> dict:
    """
    Check the license for a package across multiple ecosystems.
    
    This function:
    1. Detects the ecosystem if not provided
    2. Checks package registries (PyPI, NPM, Maven)
    3. Falls back to ClearlyDefined API
    4. Returns Unknown if not found (agent will then search)
    
    This is the main entry point used by the agent.
    
    Args:
        package_name: Name of the package
        ecosystem: Package ecosystem (optional, auto-detected if not provided)
        
    Returns:
        Dictionary with license, ecosystem, and copyleft status
    """
    checker = get_license_checker()
    return checker.check(package_name, ecosystem)
