import requests
import logging
from . import config
from .utils import enforce_rate_limit

logger = logging.getLogger(__name__)


def report_to_urlscan(url: str) -> bool:
    """Submit URL to urlscan.io."""
    if not hasattr(config, 'URLSCAN_API_KEY') or not config.URLSCAN_API_KEY:
        return False

    # Rate limiting
    limit = getattr(config, 'RATE_LIMIT_URLSCAN', 2.0)
    enforce_rate_limit("urlscan.io", limit)

    api_url = "https://urlscan.io/api/v1/scan/"
    headers = {
        'API-Key': config.URLSCAN_API_KEY,
        'Content-Type': 'application/json'
    }
    data = {
        "url": url,
        "visibility": "public",
        "tags": ["malicious", "phishing", "scam"],
        "customagent": "UCE Spam reported by SpamJam.  Spammers violating 15 U.S.C. Chapter 101 — §§ 7701-7713-(CAN-SPAM Act), 18 U.S.C. § 1030-(COMPUTER FRAUD & ABUSE ACT), 18 U.S.C. § 1343-(WIRE FRAUD)"
    }

    try:
        response = requests.post(api_url, headers=headers, json=data, timeout=15)
        if response.status_code == 200:
            resp_json = response.json()
            result_url = resp_json.get("result", "N/A")
            logger.info("Submitted %s to urlscan.io with tags %s. Result: %s", url, data["tags"], result_url)
            return True
        elif response.status_code == 429:
            logger.warning("urlscan.io rate limit reached.")
        else:
            logger.debug("urlscan.io submission failed: %s", response.status_code)
    except Exception as e:
        logger.error("Error submitting to urlscan.io: %s", e)

    return False
