import os
import re
import nvdlib
import json
import requests
from google.adk.agents import Agent
from google.adk.tools import google_search, agent_tool
from dotenv import load_dotenv
from xml.etree import ElementTree as ET  # For parsing NuGet nuspec XML (if needed)

load_dotenv()

COPYLEFT_LICENSES = {"GPL", "AGPL", "LGPL", "MPL", "EPL", "CDDL"}



def triage_vulnerability(vuln_description: str) -> dict:
    """
    Triages a vulnerability by extracting the CVE ID from the description and querying the NVD API for details.
    """
    # Extract CVE ID from the description (e.g., "CVE-2023-XXXX")
    cve_match = re.search(r'CVE-\d{4}-\d{4,7}', vuln_description, re.IGNORECASE)
    if not cve_match:
        return {"severity": "unknown", "recommendation": "No valid CVE ID found in description.", "details": {}}
    
    cve_id = cve_match.group(0).upper()
    api_key = os.getenv('NVD_API_KEY')
    
    try:
        # Search for the CVE using nvdlib (supports NVD API v2)
        results = nvdlib.searchCVE(cveId=cve_id, key=api_key)
        if not results:
            return {"severity": "unknown", "recommendation": "CVE not found in NVD.", "details": {}}
        
        cve = results[0]
        
        # Get severity and score (prefer CVSS v3.1 or v4 if available, fallback to v3.0/v2)
        severity = None
        score = None
        cvss_vector = "N/A"
        
        # Check for CVSS v4 (newer metrics)
        if hasattr(cve, 'v40severity'):
            severity = cve.v40severity
            score = cve.v40score
            cvss_vector = cve.v40vector
        elif hasattr(cve, 'v31severity'):
            severity = cve.v31severity
            score = cve.v31score
            cvss_vector = cve.v31vector
        elif hasattr(cve, 'v30severity'):
            severity = cve.v30severity
            score = cve.v30score
            cvss_vector = cve.v30vector
        elif hasattr(cve, 'v2severity'):
            severity = cve.v2severity
            score = cve.v2score
            cvss_vector = cve.v2vector
        else:
            severity = "unknown"
            score = "unknown"
        
        # Get description
        description = cve.descriptions[0].value if cve.descriptions else "No description available."
        
        # Recommendation based on severity
        if severity in ["CRITICAL", "HIGH"]:
            recommendation = "Patch immediately."
        elif severity == "MEDIUM":
            recommendation = "Patch within 30 days."
        elif severity == "LOW":
            recommendation = "Monitor and patch as needed."
        else:
            recommendation = "Review for applicability."
        
        # Additional details
        details = {
            "cve_id": cve.id,
            "published": cve.published,
            "last_modified": cve.lastModified,
            "cvss_score": score,
            "cvss_vector": cvss_vector,
            "description": description
        }
        
        return {"severity": severity, "recommendation": recommendation, "details": details}
    
    except Exception as e:
        return {"severity": "error", "recommendation": f"Failed to triage: {str(e)}", "details": {}}

search_agent = Agent(
    model='gemini-2.5-flash',
    name='SearchAgent',
    instruction="""
    You're a specialist in Google Search
    """,
    tools=[google_search],
)

COPYLEFT_LICENSES = {'GPL', 'AGPL', 'LGPL', 'MPL', 'EPL'}  # Example set; expand as needed

def check_package_license(package_name: str, ecosystem: str = 'npm') -> dict:
    """
    Checks the license for a package, auto-detecting ecosystem if not provided.
    Returns license and whether it's copyleft.
    """
    license_info = 'Unknown'
    detected_ecosystem = ecosystem.lower() if ecosystem else None
    
    # Pattern-based auto-detection
    if detected_ecosystem is None:
        if package_name.startswith('@'):  # Common for npm scoped packages
            detected_ecosystem = 'npm'
        elif '.' in package_name:  # e.g., com.example for maven
            detected_ecosystem = 'maven'
        else:
            detected_ecosystem = 'pypi'  # Default for ambiguous

    # Ecosystem-specific checks (expand with more as needed)
    if detected_ecosystem == 'pypi':
        url = f"https://pypi.org/pypi/{package_name}/json"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                license_info = data['info'].get('license', 'Unknown')
        except Exception:
            pass

    elif detected_ecosystem == 'npm':
        url = f"https://registry.npmjs.org/{package_name}"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                license_info = data.get('license', 'Unknown')
        except Exception:
            pass

    elif detected_ecosystem == 'maven':
        # Maven uses group:artifact; split if needed
        parts = package_name.split(':') if ':' in package_name else package_name.split('.')
        group = '.'.join(parts[:-1])
        artifact = parts[-1]
        url = f"https://mvnrepository.com/artifact/{group}/{artifact}"  # Or use Maven Central API
        try:
            response = requests.get(url)
            if response.status_code == 200:
                # Parse HTML or use API for license; placeholder for real extraction
                license_info = 'Extracted from Maven'  # Implement parsing
        except Exception:
            pass

    # If still unknown, fallback to ClearlyDefined or agent will use google_search
    if license_info == 'Unknown':
        clearlydefined_url = f"https://api.clearlydefined.io/definitions/{detected_ecosystem or 'pypi'}/{package_name}"
        try:
            response = requests.get(clearlydefined_url)
            if response.status_code == 200:
                data = response.json()
                license_info = data.get('licensed', {}).get('declared', 'Unknown')
        except Exception:
            pass

    is_copyleft = any(lic in license_info.upper() for lic in COPYLEFT_LICENSES) if license_info != 'Unknown' else False

    return {
        "license": license_info,
        "ecosystem": detected_ecosystem or 'unknown',
        "is_copyleft": is_copyleft
    }

def parse_sbom(sbom_content: str) -> dict:
    try:
        sbom = json.loads(sbom_content)
        packages = []
        for comp in sbom.get('components', []):
            name = comp.get('name', 'Unknown')
            license_info = comp.get('licenses', [{}])[0].get('license', {}).get('name', 'Unknown')
            is_copyleft = any(cl in license_info.upper() for cl in COPYLEFT_LICENSES)
            packages.append({"name": name, "license": license_info, "is_copyleft": is_copyleft})
        return {"status": "success", "packages": packages}
    except Exception as e:
        return {"status": "error", "error_message": str(e)}

vuln_triage_agent = Agent(
    name="vuln_triage_agent",
    model="gemini-2.5-flash",
    
    description = "Triages vulnerabilities and verifies software package licenses across multiple ecosystems, with optional SBOM parsing support.",

    instruction = """
    1. **Vulnerability Triage**:
    - Use `triage_vulnerability` to assess and categorize vulnerabilities.
    - This includes identifying severity, exploitability, and remediation priority.
    - Input may include CVE identifiers, vulnerability descriptions, or metadata.
    - Ensure that vulnerability data is current and relevant to the software's context.
    - Return the structured results with assessed severity, recommendations, and detailed information.
    - If the input does not contain a CVE ID, return "No valid CVE ID found in description."
    - For undetected CVEs, no specific recommendation is provided.
    - For invalid CVEs, return "CVE not found in NVD."
    - In case of internal errors, provide "Failed to triage" and relevant error message.
    - output format: Detailed Summaries with patch priorities, structured as bullet points:
        - Medium: CVSS Score >7 && CVSS Score <9 (followed by sub-points)
        - High: CVSS Score >9 (followed by sub-points)
        - Critical: CVSS Score > 9.5 (followed by sub-points)
        - Major issues should be listed first and minor ones at the bottom.
        - Identified vulnerabilities are numbered, followed by their respective details and recommendations.
        - Each severity level is formatted as a distinct block.
        - Sub-points provide specific details of each vulnerability, highlighting the vulnerability description, software dependency, CVSS score, and affected versions.
        - Recommendations offer clear next steps for fixing the vulnerability, including detailed patch information, new dependencies, and steps for testing.
        - Code coverage blocks should be included at the end, showing which lines of code have been analyzed and potential lines of code impacted by the vulnerability.
        - Summarize the total number of vulnerabilities detected, with specifics broken down by severity.
        - Conclude with a note about remaining patches and urgency.
        - A section for next steps: Provide a concise plan with priority and urgency for each detected vulnerability. Include steps for external patching and internal testing or fixes.

    2. **License Checking**:
    - Prompt the user for:
        - Package name
        - Ecosystem (default: 'pypi'; supported: 'npm', 'maven', 'rubygems', 'nuget', 'apt')
    - Use Tool `check_package_license` with the provided package name.
    - Auto-detect ecosystem if not provided.
    - Verify that the license is available; if not, use `search_license`.
    - Extract license details and whether it's copyleft (based on known copyleft licenses).
    - Optionally use `google_search` tool to retrieve license information if initially unknown.
    - Return the extracted license information and copyleft status.
    - Ensure the agent understands known copyleft licenses such as GPL, AGPL, LGPL, MPL, EPL, etc.
    - Output example:
        ```
        - License: MIT
        - Is Copyleft: False
        ```
    - Optionally perform a web search by using the search_agent if the license information is not immediately available.
    - Handle errors such as network issues, API failures, and missing license information.
    - Ensure that the license information provided is accurate, up-to-date, and compatible with the software's usage policies.
    - Example operations:
        - Extract license information from the package metadata.
        - Perform a web search using search_agent if the license information is not found in metadata.
        - Verify license compatibility and compliance with usage policies.
        - Provide detailed analysis and recommendations if necessary.
        - Output examples:
            - "License not immediately available. Initiating web search..."
            - "License found: GNU General Public License v3.0 (GPL-3.0)."
            - "Initiating detailed license check..."
            - "The provided license is compatible with usage policies."
            - "There is a potential conflict with the license terms. Review for further details."
    - Actions to take when license terms are incompatible:
        - Highlight the incompatible terms.
        - Provide recommendations for resolving the issue.
        - Offer alternative options if available.
    - Steps to take when license information is missing or incomplete:
        - Initiate a web search to retrieve license information.
        - Confirm the retrieved information and ensure it's up-to-date.
        - Verify the license is valid, compatible, and compliant with usage policies.
        - Provide details on the license status and any necessary actions.
        - Ensure the agent is aware of known copyleft licenses such as GPL, AGPL, LGPL, MPL, EPL, etc.
    - Example use case:
        - The agent is tasked with checking the license for a given package in a specified ecosystem.
        - The package metadata does not contain license information.
        - The agent performs a web search to retrieve license details.
        - The retrieved license is verified to be compatible with the usage policies.
        - The agent returns the license information, indicating it is not copyleft.
        - If the retrieved license information is missing or incomplete, the agent initiates a search until sufficient details are found.
        - The agent ensures the license is valid, compatible, and compliant with usage policies.
    - Ensure the agent's understanding and handling of license information is accurate and up-to-date.
    - Support the agent's ability to perform web searches if license information is not immediately available.
    - Ensure the agent's operations are compatible with known copyleft licenses such as GPL, AGPL, LGPL, MPL, EPL, etc.

    3. **SBOM Parsing (Optional)**:
    - If a Software Bill of Materials (SBOM) file is provided, use `parse_sbom`.
    - This extracts package names, versions, and associated licenses from the SBOM.
    - Parsed data can be used to batch process license checks or vulnerability triage.

    4. **Output Format**:
    - Return a structured JSON object containing results from both operations:
        ```json
        {
        "triage": {
            // Output from triage_vulnerability
        },
        "license_check": {
            // Output from check_package_license or parse_sbom
        }
        ```
    - Summarise the above json output.
    """,
    tools=[agent_tool.AgentTool(agent=search_agent),triage_vulnerability, check_package_license, parse_sbom]
)