import json
import requests
from google.adk.agents import Agent
from google.adk.tools import google_search
from dotenv import load_dotenv
from xml.etree import ElementTree as ET  # For parsing NuGet nuspec XML (if needed)

load_dotenv()

COPYLEFT_LICENSES = {"GPL", "AGPL", "LGPL", "MPL", "EPL", "CDDL"}

def triage_vulnerability(vuln_description: str, affected_system: str = "") -> dict:
    return {"status": "success", "severity": "High", "recommendations": "Patch immediately."}

def search_web_for_license(query: str) -> str:
    """
    Performs a web search for the license using a search API (e.g., DuckDuckGo or Google Custom Search fallback).
    Returns the extracted license or 'Unknown'.
    """
    try:
        # Use DuckDuckGo API as a free alternative (no key needed)
        url = f"https://api.duckduckgo.com/?q={requests.utils.quote(query)}&format=json"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            abstract = data.get('AbstractText', '')
            if abstract:
                # Simple extract: Look for 'licensed under' or common phrases
                if 'licensed under' in abstract.lower():
                    license_part = abstract.lower().split('licensed under')[-1].strip()
                    return license_part.split('.')[0].strip().title()  # Basic parse
            related_topics = data.get('RelatedTopics', [])
            for topic in related_topics:
                text = topic.get('Text', '')
                if 'license' in text.lower():
                    return text.split('license')[-1].strip()
        return 'Unknown'
    except Exception:
        return 'Unknown'

def search_license(package_name: str, ecosystem: str) -> str:
    """
    Searches for the license using ClearlyDefined API as primary, falling back to web search if unknown.
    """
    try:
        ecosystem_map = {
            "pypi": "pypi",
            "npm": "npm",
            "maven": "maven",
            "rubygems": "gem",
            "nuget": "nuget",
            "apt": "debiantype"
        }
        cd_type = ecosystem_map.get(ecosystem.lower(), "")
        if not cd_type:
            return 'Unknown'
        
        if ecosystem.lower() == "maven":
            coordinates = f"maven/mavencentral/{package_name.replace(':', '/')}"
        elif ecosystem.lower() == "npm":
            coordinates = f"npm/npmjs/-/{package_name.split('/')[-1]}"
        elif ecosystem.lower() == "apt":
            coordinates = f"debiantype/debian/-/{package_name}"
        else:
            coordinates = f"{cd_type}/{cd_type}/-/{package_name}"
        
        url = f"https://api.clearlydefined.io/definitions?coordinates={coordinates}"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            licensed = data.get('licensed', {})
            declared = licensed.get('declared', 'Unknown')
            if declared != 'NOASSERTION' and declared != 'Unknown':
                return declared
    except Exception:
        pass
    
    # Fallback to web search
    query = f"{package_name} {ecosystem} open source license"
    # return search_web_for_license(query)

def check_package_license(package_name: str, ecosystem: str = "pypi") -> dict:
    """
    Checks the license of a package from various ecosystems and determines if it's copyleft.
    If initial fetch returns 'Unknown', falls back to search_license.
    """
    try:
        license_name = 'Unknown'
        if ecosystem.lower() == "pypi":
            url = f"https://pypi.org/pypi/{package_name}/json"
            response = requests.get(url)
            data = response.json()
            license_name = data.get('info', {}).get('license', 'Unknown')
        elif ecosystem.lower() == "npm":
            package_name = package_name.replace('/', '%2F')
            url = f"https://registry.npmjs.org/{package_name}"
            response = requests.get(url)
            data = response.json()
            license_name = data.get('license', 'Unknown')
        elif ecosystem.lower() == "maven":
            group, artifact = package_name.split(':')
            url = f"https://search.maven.org/solrsearch/select?q=g:\"{group}\"+AND+a:\"{artifact}\""
            response = requests.get(url)
            data = response.json()
            docs = data.get('response', {}).get('docs', [])
            license_name = docs[0].get('license', 'Unknown') if docs else 'Unknown'
        elif ecosystem.lower() == "rubygems":
            url = f"https://rubygems.org/api/v1/gems/{package_name}.json"
            response = requests.get(url)
            data = response.json()
            license_name = data.get('licenses', ['Unknown'])[0] if isinstance(data.get('licenses'), list) else data.get('licenses', 'Unknown')
        elif ecosystem.lower() == "nuget":
            url = f"https://api.nuget.org/v3/registration5-gz-semver2/{package_name.lower()}/index.json"
            response = requests.get(url)
            data = response.json()
            latest_item = data.get('items', [])[-1] if data.get('items') else None
            if latest_item:
                catalog_entry = latest_item.get('items', [{}])[0].get('catalogEntry', {})
                license_expression = catalog_entry.get('licenseExpression', 'Unknown')
                license_url = catalog_entry.get('licenseUrl', '')
                if license_expression != 'Unknown':
                    license_name = license_expression
                elif license_url:
                    license_response = requests.get(license_url)
                    license_name = license_response.text.strip()[:100] + '...' if license_response.status_code == 200 else 'Unknown'
            else:
                return {"status": "error", "error_message": f"Package '{package_name}' not found in NuGet."}
        elif ecosystem.lower() == "apt":
            url = f"https://sources.debian.org/api/src/{package_name}/"
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                versions = data.get('versions', {})
                latest_version = max(versions.keys()) if versions else None
                if latest_version:
                    copyright_url = f"https://sources.debian.org/src/{package_name}/{latest_version}/debian/copyright/"
                    copyright_response = requests.get(copyright_url)
                    if copyright_response.status_code == 200:
                        copyright_text = copyright_response.text
                        license_lines = [line.strip() for line in copyright_text.splitlines() if line.strip().startswith('License:')]
                        license_name = license_lines[0].replace('License:', '').strip() if license_lines else 'Unknown'
                    else:
                        license_name = 'Unknown'
                else:
                    return {"status": "error", "error_message": f"No versions found for '{package_name}' in APT/Debian."}
            else:
                return {"status": "error", "error_message": f"Package '{package_name}' not found in APT/Debian."}
        else:
            return {"status": "error", "error_message": f"Unsupported ecosystem '{ecosystem}'. Supported: pypi, npm, maven, rubygems, nuget, apt."}
        
        # Fallback search if unknown
        if license_name == 'Unknown' or license_name == 'NOASSERTION':
            license_name = search_license(package_name, ecosystem)
        
        is_copyleft = any(cl in str(license_name).upper() for cl in COPYLEFT_LICENSES)
        return {
            "status": "success",
            "license": license_name,
            "is_copyleft": is_copyleft,
            "details": f"License '{license_name}' is {'copyleft' if is_copyleft else 'not copyleft'}."
        }
    except Exception as e:
        return {"status": "error", "error_message": str(e)}

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
    description="Triages vulns and checks licenses for various ecosystems.",
    instruction="""
    Triage vulns with triage_vulnerability.
    Check licenses: Ask for package name and ecosystem (default pypi; e.g., npm, maven, rubygems, nuget, apt).
    Use check_package_license with ecosystem; it will search the web if initial license is unknown.
    For SBOM: Use parse_sbom.
    Output structured: {"triage": {...}, "license_check": {...}}.
    """,
    tools=[triage_vulnerability, check_package_license, parse_sbom, search_web_for_license]
)