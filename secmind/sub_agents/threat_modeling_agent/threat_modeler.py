"""
Threat modeling functionality using Gemini AI.
"""

import os
import json
import logging
from typing import Dict, Any, Optional
import google.generativeai as genai
from .models import ThreatModelResult, ThreatModelReport
from .prompt_builder import ThreatModelPromptBuilder
from .constants import DEFAULT_MODEL, GENERATION_TEMPERATURE, MAX_RETRIES
from secmind.memory_manager import MemoryManager
from .dfd_generator import DFDGenerator
from . import report_generator

logger = logging.getLogger(__name__)


class ThreatModeler:
    """Handles threat modeling operations with Gemini AI."""
    
    def __init__(self, model: str = DEFAULT_MODEL, memory_manager: Optional[MemoryManager] = None):
        """
        Initialize threat modeler.
        
        Args:
            model: Gemini model to use
            memory_manager: Instance of MemoryManager for caching
        """
        self.model_name = model
        self.prompt_builder = ThreatModelPromptBuilder()
        self.memory = memory_manager or MemoryManager()
        self.client = genai.GenerativeModel(self.model_name)

        logger.info(f"Initialized ThreatModeler with model: {self.model_name}")

    def generate_threat_model(self, app_details: Dict[str, Any]) -> ThreatModelResult:
        """
        Generate a threat model report for an application, with caching.

        Args:
            app_details: Dictionary containing application details

        Returns:
            ThreatModelResult with status and report
        """
        # Check cache first
        cached_report = self.memory.get_threat_model(app_details)
        if cached_report:
            return {
                "status": "success",
                "report": cached_report,
                "message": "Report retrieved from cache."
            }

        try:
            logger.info("Generating threat model...")

            # Validate input
            if not app_details:
                return {
                    "status": "error",
                    "message": "Application details cannot be empty.",
                    "report": None
                }

            # Generate DFD
            dfd_generator = DFDGenerator(app_details)
            dfd = dfd_generator.generate_dfd()

            # Build prompt
            prompt = self.prompt_builder.build_threat_model_prompt(app_details)
            logger.debug(f"Generated prompt (length: {len(prompt)} chars)")

            # Generate content with retries
            report_data = self._generate_with_retry(prompt)

            if not report_data:
                return {
                    "status": "error",
                    "message": "Failed to generate threat model after retries.",
                    "report": None
                }

            # Validate report structure
            validated_report = self._validate_report(report_data, dfd=dfd)

            # Add to cache
            self.memory.add_threat_model(app_details, validated_report)

            logger.info("Threat model generated successfully")
            return {
                "status": "success",
                "report": validated_report,
                "message": None
            }

        except json.JSONDecodeError as e:
            logger.error(f"JSON parsing error: {e}")
            return {
                "status": "error",
                "message": f"Invalid JSON response from AI: {str(e)}",
                "report": None
            }
        except Exception as e:
            logger.error(f"Threat modeling failed: {e}", exc_info=True)
            return {
                "status": "error",
                "message": f"Failed to generate threat model: {str(e)}",
                "report": None
            }

    def _generate_with_retry(self, prompt: str, retries: int = MAX_RETRIES) -> Optional[Dict[str, Any]]:
        """
        Generate content with retry logic.

        Args:
            prompt: Prompt to send to the model
            retries: Number of retries

        Returns:
            Parsed JSON response or None
        """
        for attempt in range(retries):
            try:
                logger.debug(f"Generation attempt {attempt + 1}/{retries}")

                generation_config = genai.types.GenerationConfig(
                    response_mime_type="application/json",
                    temperature=GENERATION_TEMPERATURE,
                )
                response = self.client.generate_content(
                    prompt,
                    generation_config=generation_config
                )

                # Parse response
                json_str = response.text.strip()
                report_data = json.loads(json_str)

                return report_data

            except json.JSONDecodeError as e:
                logger.warning(f"Attempt {attempt + 1} - JSON decode error: {e}")
                if attempt == retries - 1:
                    raise
                continue

            except Exception as e:
                logger.warning(f"Attempt {attempt + 1} - Error: {e}")
                if attempt == retries - 1:
                    raise
                continue
        
        return None
    
    def _validate_report(self, report_data: Dict[str, Any], dfd: Optional[str] = None) -> ThreatModelReport:
        """
        Validate and normalize report structure.
        
        Args:
            report_data: Raw report data from AI
            dfd: Path to the DFD image file
            
        Returns:
            Validated ThreatModelReport
        """
        # Ensure required fields exist
        validated: ThreatModelReport = {
            "overview": report_data.get("overview", "No overview provided"),
            "risk_score": min(100, max(0, report_data.get("risk_score", 50))),
            "identified_threats": report_data.get("identified_threats", []),
            "vulnerabilities": report_data.get("vulnerabilities", []),
            "recommendations": report_data.get("recommendations", {}),
            "compliance_notes": report_data.get("compliance_notes"),
            "dfd": dfd
        }
        
        # Validate threats
        for threat in validated["identified_threats"]:
            if "affected_components" not in threat:
                threat["affected_components"] = []
        
        # Validate vulnerabilities
        for vuln in validated["vulnerabilities"]:
            if "cwe_id" not in vuln:
                vuln["cwe_id"] = None
        
        return validated


# Global threat modeler instance
_threat_modeler: Optional[ThreatModeler] = None


def get_threat_modeler() -> ThreatModeler:
    """Get or create global threat modeler instance."""
    global _threat_modeler
    if _threat_modeler is None:
        _threat_modeler = ThreatModeler()
    return _threat_modeler


def generate_threat_model_report(app_details: str) -> str:
    """
    Generate a threat modeling report based on application details.
    
    This is the tool function exposed to the agent.
    
    Args:
        app_details: JSON string with application details
        
    Returns:
        A string indicating the success or failure of the report generation.
        
    Example:
        >>> details = json.dumps({
        ...     "framework": "Django",
        ...     "deployment_env": "AWS",
        ...     "cloud_config": "EC2 + RDS"
        ... })
        >>> result = generate_threat_model_report(details)
        >>> print(result)
        "Successfully generated threat model report: threat_model_report.html"
    """
    try:
        # Parse JSON string
        if isinstance(app_details, str):
            app_details_dict = json.loads(app_details)
        else:
            app_details_dict = app_details
        
        # Get threat modeler and generate report
        modeler = get_threat_modeler()
        result = modeler.generate_threat_model(app_details_dict)

        if result["status"] == "error":
            return f"Failed to generate threat model: {result['message']}"

        # Generate HTML report
        html_report = report_generator.generate_html_report(result["report"])

        # Save the report
        report_path = "threat_model_report.html"
        with open(report_path, "w") as f:
            f.write(html_report)
        
        return f"Successfully generated threat model report: {report_path}"
        
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in app_details: {e}")
        return f"Error: Invalid JSON format: {str(e)}"
    except Exception as e:
        logger.error(f"Error in generate_threat_model_report: {e}")
        return f"Error: {str(e)}"
