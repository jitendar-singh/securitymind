"""
Configuration management for Security Mind agent.

This module provides environment-based configuration with fallback defaults.
"""

import os
from typing import Dict, List
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Main configuration class with environment variable support."""
    
    # Agent Configuration
    AGENT_NAME = os.getenv("SECMIND_AGENT_NAME", "secmind")
    AGENT_MODEL = os.getenv("SECMIND_MODEL", "gemini-2.5-flash")
    AGENT_DESCRIPTION = os.getenv(
        "SECMIND_DESCRIPTION", 
        "Master security agent that delegates tasks."
    )
    
    # Logging Configuration
    LOG_LEVEL = os.getenv("SECMIND_LOG_LEVEL", "INFO")
    LOG_FORMAT = os.getenv(
        "SECMIND_LOG_FORMAT",
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    ENABLE_LOGGING = os.getenv("SECMIND_ENABLE_LOGGING", "true").lower() == "true"
    
    # Feature Flags
    ENABLE_VALIDATION = os.getenv("SECMIND_ENABLE_VALIDATION", "true").lower() == "true"
    STRICT_MODE = os.getenv("SECMIND_STRICT_MODE", "false").lower() == "true"
    
    # Task Priorities
    @staticmethod
    def get_task_priorities() -> Dict[str, int]:
        """Get task priorities from environment or use defaults."""
        return {
            "vulnerability_triage": int(os.getenv("PRIORITY_VULN_TRIAGE", "1")),
            "license_checks": int(os.getenv("PRIORITY_LICENSE", "1")),
            "policy_reviews": int(os.getenv("PRIORITY_POLICY", "2")),
            "code_reviews": int(os.getenv("PRIORITY_CODE_REVIEW", "3")),
            "cloud_compliance": int(os.getenv("PRIORITY_CLOUD", "4")),
            "application_security": int(os.getenv("PRIORITY_APP_SEC", "5")),
            "jira_tickets": int(os.getenv("PRIORITY_JIRA", "6")),
        }
    
    # Agent Capabilities
    @staticmethod
    def get_capabilities() -> List[str]:
        """Get agent capabilities."""
        custom_capabilities = os.getenv("SECMIND_CAPABILITIES")
        
        if custom_capabilities:
            return [cap.strip() for cap in custom_capabilities.split(",")]
        
        return [
            "Vulnerability triage and assessment",
            "Code reviews and license checks",
            "Cloud compliance checks",
            "Threat Modelling as per STRIDE",
            "Policy interpretation",
            "Jira ticket creation",
        ]


class DevelopmentConfig(Config):
    """Development environment configuration."""
    LOG_LEVEL = "DEBUG"
    ENABLE_VALIDATION = True
    STRICT_MODE = False


class ProductionConfig(Config):
    """Production environment configuration."""
    LOG_LEVEL = "WARNING"
    ENABLE_VALIDATION = True
    STRICT_MODE = True


class TestConfig(Config):
    """Test environment configuration."""
    LOG_LEVEL = "DEBUG"
    ENABLE_VALIDATION = False
    STRICT_MODE = False
    AGENT_MODEL = "mock-model"


def get_config(env: str = None) -> Config:
    """
    Get configuration based on environment.
    
    Args:
        env: Environment name (development, production, test)
        
    Returns:
        Configuration instance
    """
    if env is None:
        env = os.getenv("SECMIND_ENV", "development")
    
    configs = {
        "development": DevelopmentConfig,
        "production": ProductionConfig,
        "test": TestConfig,
    }
    
    return configs.get(env.lower(), Config)()
