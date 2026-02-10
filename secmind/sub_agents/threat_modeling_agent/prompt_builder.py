"""
Prompt builder for threat modeling with Gemini AI.
"""

import json
from typing import Dict, Any
from .constants import STRIDE_CATEGORIES, RECOMMENDATION_CATEGORIES


class ThreatModelPromptBuilder:
    """Builds structured prompts for threat modeling."""
    
    @staticmethod
    def build_threat_model_prompt(app_details: Dict[str, Any]) -> str:
        """
        Build a comprehensive threat modeling prompt.
        
        Args:
            app_details: Dictionary with application details
            
        Returns:
            Formatted prompt string
        """
        # Format app details nicely
        details_str = json.dumps(app_details, indent=2)
        
        prompt = f"""You are an expert application security architect performing threat modeling.

**Application Details:**
{details_str}

**Task:**
Perform comprehensive threat modeling for this application using the STRIDE methodology.

**STRIDE Categories:**
{', '.join(STRIDE_CATEGORIES)}

**Analysis Requirements:**

1. **Overview:**
   - Summarize the application architecture
   - Identify high-level security posture
   - Calculate overall risk score (0-100, where 100 is highest risk)

2. **Identified Threats:**
   For each threat, provide:
   - Threat name and description
   - STRIDE category (one of: {', '.join(STRIDE_CATEGORIES)})
   - Likelihood (High/Medium/Low)
   - Impact (High/Medium/Low)
   - Affected components

3. **Vulnerabilities:**
   For each vulnerability, provide:
   - Vulnerability name and description
   - Severity (Critical/High/Medium/Low/Info)
   - Affected component
   - CWE ID (if applicable)
   - Specific remediation steps

4. **Recommendations:**
   Provide actionable recommendations in these categories:
   {', '.join(RECOMMENDATION_CATEGORIES)}
   
   Each recommendation should be:
   - Specific and actionable
   - Prioritized by risk
   - Technically feasible

5. **Compliance Notes:**
   If compliance requirements are specified, note relevant controls needed.

**Output Format:**
Return ONLY valid JSON matching this exact structure:
{{
  "overview": "string - comprehensive summary",
  "risk_score": number (0-100),
  "identified_threats": [
    {{
      "threat": "string",
      "description": "string",
      "stride_category": "string (one of STRIDE)",
      "likelihood": "High|Medium|Low",
      "impact": "High|Medium|Low",
      "affected_components": ["string"]
    }}
  ],
  "vulnerabilities": [
    {{
      "vulnerability": "string",
      "description": "string",
      "severity": "Critical|High|Medium|Low|Info",
      "component": "string",
      "cwe_id": "CWE-XXX or null",
      "remediation": "string"
    }}
  ],
  "recommendations": {{
    "authentication": ["string"],
    "authorization": ["string"],
    "data_protection": ["string"],
    "cloud_security": ["string"],
    "networking": ["string"],
    "input_validation": ["string"],
    "logging_monitoring": ["string"],
    "general": ["string"]
  }},
  "compliance_notes": ["string"] or null
}}

**Important:**
- Focus on realistic, high-impact threats
- Prioritize findings by risk (likelihood × impact)
- Provide specific, actionable recommendations
- Consider the deployment environment and cloud configuration
- Return ONLY the JSON object, no additional text
"""
        return prompt
    
    @staticmethod
    def build_followup_prompt(question: str, context: Dict[str, Any]) -> str:
        """
        Build a prompt for follow-up questions.
        
        Args:
            question: User's follow-up question
            context: Previous conversation context
            
        Returns:
            Formatted prompt string
        """
        context_str = json.dumps(context, indent=2)
        
        prompt = f"""You are an application security expert. The user has a follow-up question about their threat model.

**Previous Context:**
{context_str}

**User Question:**
{question}

**Instructions:**
- Provide a clear, detailed answer
- Reference specific threats or vulnerabilities from the context
- Suggest additional security controls if relevant
- Keep the response focused and actionable
"""
        return prompt
