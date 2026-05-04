"""Constants for the Threat Modeling Agent."""

# Risk levels
RISK_LEVELS = ["Critical", "High", "Medium", "Low", "Info"]
LIKELIHOOD_LEVELS = ["High", "Medium", "Low"]
IMPACT_LEVELS = ["High", "Medium", "Low"]

# Recommendation categories — shared across frameworks for the merged recommendations dict
RECOMMENDATION_CATEGORIES = [
    "authentication",
    "authorization",
    "data_protection",
    "cloud_security",
    "networking",
    "input_validation",
    "logging_monitoring",
    "general",
]

# Gemini model configuration
DEFAULT_MODEL = "gemini-2.5-pro"
GENERATION_TEMPERATURE = 0.5
MAX_RETRIES = 3
REQUEST_TIMEOUT = 30
