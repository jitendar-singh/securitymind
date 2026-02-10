# Application Security Agent - Refactored

A comprehensive application security agent that performs threat modeling and security architecture review using the STRIDE methodology and Gemini AI.

## 🎯 Features

- **Comprehensive Threat Modeling** using STRIDE framework
- **Vulnerability Assessment** with CWE mapping
- **Risk Scoring** (0-100 scale)
- **Actionable Recommendations** across 8 security categories
- **Compliance Mapping** (GDPR, HIPAA, PCI-DSS, SOC 2, etc.)
- **Interactive Information Gathering** with smart questioning
- **Structured Reporting** with executive summaries

## 📋 STRIDE Methodology

The agent analyzes threats across six categories:
- **S**poofing - Identity verification issues
- **T**ampering - Data integrity issues
- **R**epudiation - Audit and logging issues
- **I**nformation Disclosure - Data confidentiality issues
- **D**enial of Service - Availability issues
- **E**levation of Privilege - Authorization issues

## 🏗️ Architecture

### Module Structure

```
app_sec_agent/
├── agent_refactored.py          # Main agent definition
├── threat_modeler.py            # Threat modeling with Gemini AI
├── prompt_builder.py            # Prompt construction
├── instruction_builder.py       # Agent instructions
├── models.py                    # Type definitions
├── constants.py                 # Configuration constants
└── README.md                    # Documentation
```

### Key Components

#### 1. Threat Modeler (`threat_modeler.py`)
- Interfaces with Gemini AI for threat analysis
- Retry logic for reliability
- Response validation and normalization
- Error handling and logging

#### 2. Prompt Builder (`prompt_builder.py`)
- Constructs structured prompts for AI
- Ensures consistent output format
- Includes STRIDE methodology guidance
- Handles follow-up questions

#### 3. Instruction Builder (`instruction_builder.py`)
- Defines agent behavior and workflow
- Question templates for information gathering
- Output formatting guidelines
- Error handling instructions

#### 4. Models (`models.py`)
- TypedDict definitions for type safety
- Structured data models for:
  - Threats
  - Vulnerabilities
  - Recommendations
  - Reports

## 🚀 Installation

```bash
pip install google-adk
pip install google-generativeai
```

## ⚙️ Configuration

Set your Google API key:

```bash
export GOOGLE_API_KEY="your-api-key-here"
```

Or create a `.env` file:

```env
GOOGLE_API_KEY=your-api-key-here
```

## 💻 Usage

### Basic Usage

```python
from app_sec_agent import app_sec_agent

# Start a conversation
response = app_sec_agent.send_message(
    "I need a security review for my Django web application"
)
print(response)
```

### Complete Example

```python
import json
from app_sec_agent import generate_threat_model_report

# Prepare application details
app_details = {
    "framework": "Django 4.2",
    "language": "Python 3.11",
    "deployment_env": "AWS",
    "cloud_provider": "AWS",
    "cloud_config": "EC2 + RDS PostgreSQL + S3",
    "networking": "Application Load Balancer, VPC with public/private subnets",
    "authentication": "Django auth + OAuth2 for API",
    "authorization": "Django permissions + custom RBAC",
    "data_storage": "PostgreSQL (RDS), S3 for file uploads",
    "apis": "REST API with Django REST Framework",
    "third_party_services": ["Stripe for payments", "SendGrid for email"],
    "compliance_requirements": ["GDPR", "PCI-DSS"],
    "existing_security_controls": ["WAF", "CloudTrail", "GuardDuty"]
}

# Generate threat model
result = generate_threat_model_report(json.dumps(app_details))

if result["status"] == "success":
    report = result["report"]
    print(f"Risk Score: {report['risk_score']}/100")
    print(f"Threats Found: {len(report['identified_threats'])}")
    print(f"Vulnerabilities: {len(report['vulnerabilities'])}")
else:
    print(f"Error: {result['message']}")
```

## 📊 Output Format

### Threat Model Report Structure

```json
{
  "overview": "Comprehensive summary of the application and security posture",
  "risk_score": 65,
  "identified_threats": [
    {
      "threat": "SQL Injection",
      "description": "Unsanitized user input in database queries",
      "stride_category": "Tampering",
      "likelihood": "High",
      "impact": "High",
      "affected_components": ["Database layer", "API endpoints"]
    }
  ],
  "vulnerabilities": [
    {
      "vulnerability": "SQL Injection in user search",
      "description": "User search endpoint vulnerable to SQL injection",
      "severity": "Critical",
      "component": "Search API",
      "cwe_id": "CWE-89",
      "remediation": "Implement parameterized queries and input validation"
    }
  ],
  "recommendations": {
    "authentication": [
      "Implement MFA for all user accounts",
      "Enforce strong password policy"
    ],
    "data_protection": [
      "Enable encryption at rest for RDS",
      "Use TLS 1.3 for all connections"
    ],
    "cloud_security": [
      "Enable VPC Flow Logs",
      "Implement least privilege IAM policies"
    ]
  },
  "compliance_notes": [
    "GDPR: Implement data retention policies",
    "PCI-DSS: Encrypt cardholder data at rest and in transit"
  ]
}
```

## 🔍 Information Gathering

The agent asks targeted questions about:

### Application Architecture
- Framework and language
- Application type
- Key features

### Infrastructure
- Deployment environment
- Cloud provider and services
- Container orchestration

### Networking
- Network architecture
- API endpoints
- External integrations

### Security Controls
- Authentication mechanisms
- Authorization model
- Encryption methods
- Security tools

### Data Handling
- Data types (PII, financial, health)
- Storage solutions
- Data flows

### Compliance
- Regulatory requirements
- Industry standards

### Third-Party Services
- External APIs
- Libraries and dependencies
- Service providers

## 📈 Risk Scoring

Risk scores are calculated on a 0-100 scale:

- **0-25**: Low Risk - Minor security concerns
- **26-50**: Medium Risk - Some security gaps
- **51-75**: High Risk - Significant vulnerabilities
- **76-100**: Critical Risk - Severe security issues

## 🎯 Recommendation Categories

1. **Authentication** - Identity verification
2. **Authorization** - Access control
3. **Data Protection** - Encryption and privacy
4. **Cloud Security** - Cloud-specific controls
5. **Networking** - Network security
6. **Input Validation** - Input sanitization
7. **Logging & Monitoring** - Audit and detection
8. **General** - Other security practices

## 🔧 Advanced Configuration

### Custom Model

```python
from app_sec_agent.threat_modeler import ThreatModeler

modeler = ThreatModeler(
    api_key="your-key",
    model="gemini-2.0-flash-exp"
)
```

### Logging

```python
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("app_sec_agent")
```

## 🧪 Testing

```python
# Test with minimal details
minimal_details = {
    "framework": "Express.js",
    "deployment_env": "Heroku"
}

result = generate_threat_model_report(json.dumps(minimal_details))
assert result["status"] == "success"
```

## 🐛 Error Handling

The agent handles various error scenarios:

- **Missing API Key**: Clear error message
- **Invalid JSON**: JSON parsing errors
- **AI Generation Failure**: Retry logic (3 attempts)
- **Malformed Response**: Response validation
- **Network Issues**: Timeout and retry

## 📝 Best Practices

1. **Provide Detailed Information**: More details = better threat model
2. **Be Specific**: Mention exact versions and configurations
3. **Include Compliance**: Specify regulatory requirements
4. **List Existing Controls**: Mention current security measures
5. **Ask Follow-ups**: Clarify recommendations as needed

## 🔐 Security Considerations

- API keys are read from environment variables
- No sensitive data is logged
- All communication uses HTTPS
- Responses are validated before processing

## 📚 References

- [STRIDE Threat Modeling](https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Database](https://cwe.mitre.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

## 🤝 Contributing

This is a refactored version with improvements:
- Modular architecture
- Type safety with TypedDict
- Comprehensive error handling
- Detailed logging
- Retry logic
- Response validation

## 📄 License

Part of the Security Mind Team toolkit.

## 🆚 Version History

- **2.0.0** - Complete refactor with modular architecture
  - Separated concerns into modules
  - Added type definitions
  - Improved error handling
  - Enhanced prompt engineering
  - Better documentation

- **1.0.0** - Initial version
  - Basic threat modeling
  - STRIDE methodology
  - Gemini AI integration

## 💡 Example Interaction

```
User: "I need a security review for my web app"

Agent: "I'd be happy to help! To provide a comprehensive threat model, 
I need to understand your application better. Let me start with a few questions:

1. What framework and programming language is your web application built with?
2. Where is it deployed (cloud provider, on-premises, or hybrid)?
3. What type of data does your application handle?
4. What authentication method are you currently using?
5. Are there any specific compliance requirements?

Feel free to provide as much detail as you're comfortable sharing!"

User: "It's a Django app on AWS, handles user data and payments, 
uses OAuth2, and needs to be PCI-DSS compliant"

Agent: "Great! A few more details:

1. Which AWS services are you using (EC2, RDS, S3, etc.)?
2. How is payment data processed (direct integration or via payment gateway)?
3. What's your database setup?
4. Do you have any existing security controls (WAF, monitoring, etc.)?"

User: [provides details]

Agent: [generates comprehensive threat model with STRIDE analysis, 
vulnerabilities, and prioritized recommendations]
```

## 🆘 Support

For issues or questions:
1. Check the error message for specific guidance
2. Review the logs for detailed information
3. Ensure API key is properly configured
4. Verify input format matches expected structure

## 🎓 Learning Resources

- STRIDE methodology overview
- Common web application vulnerabilities
- Cloud security best practices
- Compliance requirements (GDPR, HIPAA, PCI-DSS)
- Secure coding guidelines
