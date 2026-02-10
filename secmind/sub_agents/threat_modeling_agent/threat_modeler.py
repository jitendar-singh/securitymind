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

logger = logging.getLogger(__name__)


class ThreatModeler:
    """Handles threat modeling operations with Gemini AI."""
    
    def __init__(self, api_key: Optional[str] = None, model: str = DEFAULT_MODEL):
        """
        Initialize threat modeler.
        
        Args:
            api_key: Google API key (defaults to GOOGLE_API_KEY env var)
            model: Gemini model to use
        """
        self.api_key = api_key or os.getenv("GOOGLE_API_KEY")
        self.model_name = model
        self.prompt_builder = ThreatModelPromptBuilder()
        
        if not self.api_key:
            raise ValueError("Google API key not set. Set GOOGLE_API_KEY environment variable.")
        
        genai.configure(api_key=self.api_key)
        self.model = genai.GenerativeModel(self.model_name)
        logger.info(f"Initialized ThreatModeler with model: {self.model_name}")
    
    def generate_threat_model(self, app_details: Dict[str, Any]) -> ThreatModelResult:
        """
        Generate a threat model report for an application.
        
        Args:
            app_details: Dictionary containing application details
            
        Returns:
            ThreatModelResult with status and report
        """
        try:
            logger.info("Generating threat model...")
            
            # Validate input
            if not app_details:
                return {
                    "status": "error",
                    "message": "Application details cannot be empty.",
                    "report": None
                }
            
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
            validated_report = self._validate_report(report_data)
            
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
                
                response = self.model.generate_content(
                    prompt,
                    generation_config=genai.GenerationConfig(
                        response_mime_type="application/json",
                        temperature=GENERATION_TEMPERATURE
                    )
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
    
    def _validate_report(self, report_data: Dict[str, Any]) -> ThreatModelReport:
        """
        Validate and normalize report structure.
        
        Args:
            report_data: Raw report data from AI
            
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
            "compliance_notes": report_data.get("compliance_notes")
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


def generate_threat_model_report(app_details: str) -> dict:
    """
    Generate a threat modeling report based on application details.
    
    This is the tool function exposed to the agent.
    
    Args:
        app_details: JSON string with application details
        
    Returns:
        Dictionary with status and report
        
    Example:
        >>> details = json.dumps({
        ...     "framework": "Django",
        ...     "deployment_env": "AWS",
        ...     "cloud_config": "EC2 + RDS"
        ... })
        >>> result = generate_threat_model_report(details)
        >>> print(result["status"])
        "success"
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
        
        return result
        
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in app_details: {e}")
        return {
            "status": "error",
            "message": f"Invalid JSON format: {str(e)}",
            "report": None
        }
    except Exception as e:
        logger.error(f"Error in generate_threat_model_report: {e}")
        return {
            "status": "error",
            "message": f"Error: {str(e)}",
            "report": None
        }
