"""
SBOM (Software Bill of Materials) parsing functionality.
Optimized for large files with streaming and chunked processing.
"""

import json
import logging
from typing import Dict, List, Any, Optional, Iterator
from collections import defaultdict
from .models import SBOMPackage, SBOMResult
from .utils import is_copyleft_license
from .constants import COPYLEFT_LICENSES

logger = logging.getLogger(__name__)


class SBOMParser:
    """Parser for Software Bill of Materials (SBOM) files with large file support."""
    
    # Limits for processing
    MAX_PACKAGES_FULL_DETAIL = 100  # Show full details for up to 100 packages
    MAX_PACKAGES_SUMMARY = 1000     # Show summary for up to 1000 packages
    CHUNK_SIZE = 50                  # Process packages in chunks
    
    def __init__(self):
        """Initialize SBOM parser."""
        self.supported_formats = ['CycloneDX', 'SPDX']
    
    def parse(self, sbom_content: str) -> SBOMResult:
        """
        Parse SBOM content and extract package information.
        Optimized for large files with chunked processing.
        
        Args:
            sbom_content: SBOM file content as a JSON string
            
        Returns:
            SBOMResult with parsed packages and summary
        """
        try:
            # Parse JSON content
            logger.info("Parsing SBOM JSON content...")
            sbom_data = json.loads(sbom_content)
            
            # Detect format
            sbom_format = self._detect_format(sbom_data)
            logger.info(f"Detected SBOM format: {sbom_format}")
            
            if not sbom_format:
                return {
                    "status": "error",
                    "message": f"Unsupported SBOM format. Supported: {self.supported_formats}",
                    "packages": []
                }
            
            # Parse based on format with streaming
            if sbom_format == 'CycloneDX':
                packages = self._parse_cyclonedx_optimized(sbom_data)
            elif sbom_format == 'SPDX':
                packages = self._parse_spdx_optimized(sbom_data)
            else:
                return {
                    "status": "error",
                    "message": f"Unsupported SBOM format: {sbom_format}",
                    "packages": []
                }
            
            total_packages = len(packages)
            logger.info(f"Parsed {total_packages} packages from SBOM")
            
            # Generate summary (always fast)
            summary = self._generate_summary_optimized(packages)
            
            # For large SBOMs, limit detailed package list
            if total_packages > self.MAX_PACKAGES_FULL_DETAIL:
                logger.info(f"Large SBOM detected ({total_packages} packages). Limiting detailed output.")
                # Keep only high-risk packages (copyleft + unknown)
                filtered_packages = self._filter_high_risk_packages(packages)
                summary['note'] = (
                    f"Large SBOM with {total_packages} packages. "
                    f"Showing {len(filtered_packages)} high-risk packages only. "
                    f"See summary for complete statistics."
                )
                packages = filtered_packages
            
            result: SBOMResult = {
                "status": "success",
                "format": sbom_format,
                "packages": packages,
                "summary": summary
            }
            
            logger.info(f"Successfully parsed SBOM with {total_packages} total packages")
            return result
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in SBOM content: {e}")
            return {
                "status": "error",
                "message": f"Invalid JSON format: {str(e)}. Please ensure the SBOM is valid JSON.",
                "packages": []
            }
        except MemoryError as e:
            logger.error(f"Out of memory parsing SBOM: {e}")
            return {
                "status": "error",
                "message": "SBOM file too large to process. Please try with a smaller file or contact support.",
                "packages": []
            }
        except Exception as e:
            logger.error(f"SBOM parsing failed: {e}", exc_info=True)
            return {
                "status": "error",
                "message": f"Parsing failed: {str(e)}",
                "packages": []
            }
    
    def _detect_format(self, sbom_data: Dict[str, Any]) -> Optional[str]:
        """
        Detect SBOM format from data structure.
        
        Args:
            sbom_data: Parsed SBOM JSON data
            
        Returns:
            Format name or None
        """
        # Check for CycloneDX
        if 'bomFormat' in sbom_data and sbom_data['bomFormat'] == 'CycloneDX':
            return 'CycloneDX'
        
        # Check for SPDX
        if 'spdxVersion' in sbom_data or 'SPDXID' in sbom_data:
            return 'SPDX'
        
        return None
    
    def _parse_cyclonedx_optimized(self, sbom_data: Dict[str, Any]) -> List[SBOMPackage]:
        """
        Parse CycloneDX format SBOM with memory optimization.
        
        Args:
            sbom_data: Parsed CycloneDX JSON data
            
        Returns:
            List of parsed packages
        """
        packages = []
        components = sbom_data.get('components', [])
        total = len(components)
        
        logger.info(f"Processing {total} CycloneDX components...")
        
        # Process in chunks to avoid memory issues
        for i, component in enumerate(components):
            if i % 100 == 0 and i > 0:
                logger.debug(f"Processed {i}/{total} components...")
            
            try:
                package: SBOMPackage = {
                    "name": component.get('name', 'Unknown'),
                    "version": component.get('version', 'Unknown'),
                    "license": self._extract_cyclonedx_license(component),
                    "is_copyleft": False,
                    "purl": component.get('purl', '')
                }
                
                # Check if copyleft
                package['is_copyleft'] = is_copyleft_license(
                    package['license'], 
                    COPYLEFT_LICENSES
                )
                
                packages.append(package)
            except Exception as e:
                logger.warning(f"Failed to parse component {i}: {e}")
                continue
        
        return packages
    
    def _extract_cyclonedx_license(self, component: Dict[str, Any]) -> str:
        """
        Extract license from CycloneDX component.
        
        Args:
            component: CycloneDX component data
            
        Returns:
            License identifier
        """
        licenses = component.get('licenses', [])
        
        if not licenses:
            return 'Unknown'
        
        # Try to get license from first entry
        first_license = licenses[0]
        
        # Check for license object
        if 'license' in first_license:
            license_obj = first_license['license']
            
            # Prefer SPDX ID
            if 'id' in license_obj:
                return license_obj['id']
            
            # Fall back to name
            if 'name' in license_obj:
                return license_obj['name']
        
        # Check for expression
        if 'expression' in first_license:
            return first_license['expression']
        
        return 'Unknown'
    
    def _parse_spdx_optimized(self, sbom_data: Dict[str, Any]) -> List[SBOMPackage]:
        """
        Parse SPDX format SBOM with memory optimization.
        
        Args:
            sbom_data: Parsed SPDX JSON data
            
        Returns:
            List of parsed packages
        """
        packages = []
        spdx_packages = sbom_data.get('packages', [])
        total = len(spdx_packages)
        
        logger.info(f"Processing {total} SPDX packages...")
        
        # Process in chunks
        for i, pkg in enumerate(spdx_packages):
            if i % 100 == 0 and i > 0:
                logger.debug(f"Processed {i}/{total} packages...")
            
            try:
                package: SBOMPackage = {
                    "name": pkg.get('name', 'Unknown'),
                    "version": pkg.get('versionInfo', 'Unknown'),
                    "license": self._extract_spdx_license(pkg),
                    "is_copyleft": False,
                    "purl": ''
                }
                
                # Extract PURL from external refs
                external_refs = pkg.get('externalRefs', [])
                for ref in external_refs:
                    if ref.get('referenceType') == 'purl':
                        package['purl'] = ref.get('referenceLocator', '')
                        break
                
                # Check if copyleft
                package['is_copyleft'] = is_copyleft_license(
                    package['license'], 
                    COPYLEFT_LICENSES
                )
                
                packages.append(package)
            except Exception as e:
                logger.warning(f"Failed to parse package {i}: {e}")
                continue
        
        return packages
    
    def _extract_spdx_license(self, package: Dict[str, Any]) -> str:
        """
        Extract license from SPDX package.
        
        Args:
            package: SPDX package data
            
        Returns:
            License identifier
        """
        # Try licenseConcluded first
        license_concluded = package.get('licenseConcluded', '')
        if license_concluded and license_concluded != 'NOASSERTION':
            return license_concluded
        
        # Fall back to licenseDeclared
        license_declared = package.get('licenseDeclared', '')
        if license_declared and license_declared != 'NOASSERTION':
            return license_declared
        
        return 'Unknown'
    
    def _generate_summary_optimized(self, packages: List[SBOMPackage]) -> Dict[str, Any]:
        """
        Generate summary statistics for parsed packages (optimized for large lists).
        
        Args:
            packages: List of parsed packages
            
        Returns:
            Summary dictionary
        """
        total = len(packages)
        copyleft = 0
        unknown = 0
        
        # Use defaultdict for efficient counting
        licenses = defaultdict(int)
        copyleft_packages = []
        unknown_packages = []
        
        # Single pass through packages
        for pkg in packages:
            lic = pkg['license']
            licenses[lic] += 1
            
            if pkg['is_copyleft']:
                copyleft += 1
                # Only keep first 50 copyleft packages for display
                if len(copyleft_packages) < 50:
                    copyleft_packages.append(f"{pkg['name']} v{pkg['version']}")
            
            if lic == 'Unknown':
                unknown += 1
                # Only keep first 50 unknown packages for display
                if len(unknown_packages) < 50:
                    unknown_packages.append(f"{pkg['name']} v{pkg['version']}")
        
        # Convert defaultdict to regular dict and sort by count
        license_dist = dict(sorted(licenses.items(), key=lambda x: x[1], reverse=True))
        
        # Limit license distribution to top 20 for readability
        if len(license_dist) > 20:
            top_licenses = dict(list(license_dist.items())[:20])
            other_count = sum(list(license_dist.values())[20:])
            top_licenses['Other'] = other_count
            license_dist = top_licenses
        
        summary = {
            "total_packages": total,
            "copyleft_packages": copyleft,
            "unknown_licenses": unknown,
            "unique_licenses": len(licenses),
            "license_distribution": license_dist,
            "sample_copyleft_packages": copyleft_packages,
            "sample_unknown_packages": unknown_packages
        }
        
        # Add risk assessment
        risk_level = "Low"
        if copyleft > total * 0.3:  # More than 30% copyleft
            risk_level = "High"
        elif copyleft > total * 0.1:  # More than 10% copyleft
            risk_level = "Medium"
        
        summary["risk_level"] = risk_level
        
        return summary
    
    def _filter_high_risk_packages(self, packages: List[SBOMPackage]) -> List[SBOMPackage]:
        """
        Filter packages to show only high-risk ones (copyleft and unknown licenses).
        
        Args:
            packages: Full list of packages
            
        Returns:
            Filtered list of high-risk packages
        """
        high_risk = []
        
        for pkg in packages:
            if pkg['is_copyleft'] or pkg['license'] == 'Unknown':
                high_risk.append(pkg)
                
                # Limit to reasonable number for display
                if len(high_risk) >= self.MAX_PACKAGES_FULL_DETAIL:
                    break
        
        return high_risk


# Global parser instance
_sbom_parser: Optional[SBOMParser] = None


def get_sbom_parser() -> SBOMParser:
    """Get or create global SBOM parser instance."""
    global _sbom_parser
    if _sbom_parser is None:
        _sbom_parser = SBOMParser()
    return _sbom_parser


# Create tool function for agent
def parse_sbom(sbom_content: str) -> dict:
    """
    Parse a Software Bill of Materials (SBOM) file.
    
    Supports CycloneDX and SPDX formats in JSON.
    Optimized for large files with thousands of packages.
    
    IMPORTANT: The user should paste the SBOM JSON content directly in their message.
    Do NOT ask the user to attach a file - ask them to paste the JSON content.
    
    For large SBOMs (>100 packages), only high-risk packages (copyleft and unknown licenses)
    are returned in detail. Complete statistics are always available in the summary.
    
    Args:
        sbom_content: The SBOM file content as a JSON string
        
    Returns:
        Dictionary with parsed packages and summary:
        {
            "status": "success" or "error",
            "format": "CycloneDX" or "SPDX",
            "packages": [
                {
                    "name": "package-name",
                    "version": "1.0.0",
                    "license": "MIT",
                    "is_copyleft": False,
                    "purl": "pkg:npm/package@1.0.0"
                },
                ...
            ],
            "summary": {
                "total_packages": 1000,
                "copyleft_packages": 50,
                "unknown_licenses": 10,
                "unique_licenses": 25,
                "risk_level": "Medium",
                "license_distribution": {"MIT": 500, "Apache-2.0": 300, ...},
                "sample_copyleft_packages": ["pkg1 v1.0", "pkg2 v2.0", ...],
                "sample_unknown_packages": ["pkg3 v1.5", ...]
            }
        }
        
    Example:
        >>> sbom_json = '{"bomFormat": "CycloneDX", "components": [...]}'
        >>> result = parse_sbom(sbom_json)
        >>> print(result["summary"]["total_packages"])
        1000
        >>> print(result["summary"]["risk_level"])
        "Medium"
    """
    parser = get_sbom_parser()
    return parser.parse(sbom_content)
