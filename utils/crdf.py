import requests
import logging
from . import config
from .utils import enforce_rate_limit

logger = logging.getLogger(__name__)


def report_to_crdf(url: str) -> bool:
    """Report URL to CRDF Labs."""
    if not hasattr(config, 'CRDF_API_KEY') or not config.CRDF_API_KEY:
        return False

    # Rate limiting
    limit = getattr(config, 'RATE_LIMIT_CRDF', 31.0)
    enforce_rate_limit("CRDF Labs", limit)

    api_url = "https://threatcenter.crdf.fr/api/v1/submit_url.json"
    
    headers = {
        "Authorization": f"Bearer {config.CRDF_API_KEY}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "method": "submit_url",
        "urls": [url]
    }

    try:
        response = requests.post(api_url, headers=headers, json=payload, timeout=15)
        if response.status_code in [200, 201]:
            logger.info("Reported %s to CRDF Labs.", url)
            return True
        elif response.status_code == 429:
            logger.warning("CRDF Labs rate limit reached.")
        else:
            logger.debug("CRDF report failed: %s - %s", response.status_code, response.text)
    except Exception as e:
        logger.error("Error reporting to CRDF: %s", e)

    return False
