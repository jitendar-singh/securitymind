"""
HTTP client with retry logic, timeout, and error handling.
"""

import requests
import logging
import time
from typing import Optional, Dict, Any
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


class HTTPClient:
    """
    HTTP client with automatic retry, timeout, and error handling.
    """
    
    def __init__(self, timeout: int = 10, max_retries: int = 3):
        """
        Initialize HTTP client.
        
        Args:
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
        """
        self.timeout = timeout
        self.max_retries = max_retries
        self.session = self._create_session()
    
    def _create_session(self) -> requests.Session:
        """Create a requests session with retry logic."""
        session = requests.Session()
        
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session
    
    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        """
        Perform GET request with error handling.
        
        Args:
            url: URL to request
            **kwargs: Additional arguments for requests.get
            
        Returns:
            Response object or None on error
        """
        try:
            logger.debug(f"GET request to: {url}")
            response = self.session.get(url, timeout=self.timeout, **kwargs)
            response.raise_for_status()
            logger.debug(f"GET successful: {url} (status: {response.status_code})")
            return response
        
        except requests.exceptions.Timeout:
            logger.error(f"Request timeout: {url}")
            return None
        
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error for {url}: {e}")
            return None
        
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed for {url}: {e}")
            return None
    
    def get_json(self, url: str, **kwargs) -> Optional[Dict[str, Any]]:
        """
        Perform GET request and parse JSON response.
        
        Args:
            url: URL to request
            **kwargs: Additional arguments for requests.get
            
        Returns:
            Parsed JSON dict or None on error
        """
        response = self.get(url, **kwargs)
        if not response:
            return None
        
        try:
            return response.json()
        except ValueError as e:
            logger.error(f"Failed to parse JSON from {url}: {e}")
            return None
    
    def close(self):
        """Close the session."""
        self.session.close()


# Global HTTP client instance
_http_client: Optional[HTTPClient] = None


def get_http_client() -> HTTPClient:
    """Get or create global HTTP client instance."""
    global _http_client
    if _http_client is None:
        from .constants import HTTPConfig
        _http_client = HTTPClient(
            timeout=HTTPConfig.TIMEOUT,
            max_retries=HTTPConfig.MAX_RETRIES
        )
    return _http_client
