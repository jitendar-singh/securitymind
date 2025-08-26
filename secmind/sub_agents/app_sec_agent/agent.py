# secmind/sub_agents/app_sec_review/agent.py (new file)

import os
import json
import google.generativeai as genai
from google.adk.agents import Agent



def generate_threat_model_report(app_details: str) -> dict:
    """
    Generates a threat modeling report based on provided application details using Gemini AI.
    app_details: JSON string with keys like 'framework', 'networking', 'deployment_env', 'cloud_config', etc.
    Returns a structured report with sections.
    """
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        return {"status": "error", "message": "Google API key not set."}
    
    genai.configure(api_key=api_key)
    
    model = genai.GenerativeModel('gemini-1.5-flash')
    
    prompt = f"""
        Perform threat modeling for the application based on these details:

        {app_details}

        Identify potential threats, vulnerabilities, and mitigations. Structure the response as JSON with these sections:
        - "overview": Summary of the app and high-level risks.
        - "identified_threats": List of threats (e.g., [{{"threat": "SQL Injection", "description": "...", "likelihood": "High/Medium/Low", "impact": "High/Medium/Low"}}]).
        - "vulnerabilities": List of vulns tied to components (framework, networking, deployment, cloud).
        - "recommendations": Sectioned list: {{"authentication": ["..."], "data_protection": ["..."], "cloud_security": ["..."], "networking": ["..."], "general": ["..."]}}.

        Use STRIDE model (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) for threats.
        Ensure recommendations are actionable and prioritized.
    """
    
    try:
        response = model.generate_content(
            prompt,
            generation_config=genai.GenerationConfig(
                response_mime_type="application/json",
                temperature=0.5
            )
        )
        json_str = response.text.strip()
        report_data = json.loads(json_str)
        return {"status": "success", "report": report_data}
    except Exception as e:
        return {"status": "error", "message": f"Failed to generate report: {str(e)}"}

app_sec_agent = Agent(
    name="app_sec_agent",
    model="gemini-2.5-flash",
    description="Performs threat modeling for applications based on development details.",
    instruction="""You are an application security agent specializing in threat modeling.
    If the user requests a review, first gather details by asking questions about:
    - Application framework and technologies used.
    - Networking setup (e.g., APIs, ports, firewalls).
    - Deployment environment (e.g., on-prem, cloud provider like GCP/AWS).
    - Cloud-specific configs (e.g., IAM roles, storage buckets, VPCs).
    - Other relevant info (e.g., auth methods, data flows).

    Once details are provided, format them as a JSON string and call generate_threat_model_report.
    Output the report in a readable format with sections.""",
    tools=[generate_threat_model_report]
)