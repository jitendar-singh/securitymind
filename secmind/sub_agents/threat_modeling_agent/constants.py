"""
Constants for Application Security Agent.
"""

# Threat modeling frameworks
STRIDE_CATEGORIES = [
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege"
]

# Risk levels
RISK_LEVELS = ["Critical", "High", "Medium", "Low", "Info"]
LIKELIHOOD_LEVELS = ["High", "Medium", "Low"]
IMPACT_LEVELS = ["High", "Medium", "Low"]

# Application components to assess
APP_COMPONENTS = [
    "framework",
    "networking",
    "deployment_env",
    "cloud_config",
    "authentication",
    "data_storage",
    "apis",
    "third_party_services"
]

# Recommendation categories
RECOMMENDATION_CATEGORIES = [
    "authentication",
    "authorization",
    "data_protection",
    "cloud_security",
    "networking",
    "input_validation",
    "logging_monitoring",
    "general"
]

# Gemini model configuration
DEFAULT_MODEL = "gemini-1.5-flash"
GENERATION_TEMPERATURE = 0.5
MAX_RETRIES = 3
REQUEST_TIMEOUT = 30
