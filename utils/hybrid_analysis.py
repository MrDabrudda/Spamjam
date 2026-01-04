import requests
import logging
import time
from collections import deque
from . import config

logger = logging.getLogger(__name__)

_request_timestamps = deque()


def report_to_hybrid_analysis(url: str) -> bool:
    """
    Submit a URL to Hybrid Analysis for scanning.
    Requires HYBRID_ANALYSIS_API_KEY in config.py.
    """
    try:
        if not hasattr(config, 'HYBRID_ANALYSIS_API_KEY') or not config.HYBRID_ANALYSIS_API_KEY:
            logger.debug("Hybrid Analysis API key not configured.")
            return False

        # Get rate limits from config, default to 30 req / 60 sec
        limit = getattr(config, 'HYBRID_ANALYSIS_RATE_LIMIT', 30)
        window = getattr(config, 'HYBRID_ANALYSIS_RATE_WINDOW', 60)

        # Enforce rate limit
        current_time = time.time()
        while _request_timestamps and _request_timestamps[0] < current_time - window:
            _request_timestamps.popleft()

        if len(_request_timestamps) >= limit:
            logger.warning("Hybrid Analysis rate limit reached (%s/min). Skipping %s", limit, url)
            return False

        _request_timestamps.append(current_time)

        # Endpoint for URL submission (v2)
        api_url = "https://hybrid-analysis.com/api/v2/submit/url"
        
        headers = {
            "api-key": config.HYBRID_ANALYSIS_API_KEY,
            # "User-Agent": "Falcon",
            "accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        data = {
            "url": url,
            "environment_id": 160,  # Windows 10 64 bit
            "comment": "UCE Spam reported by SpamJam.  Spammers violating 15 U.S.C. Chapter 101 — §§ 7701-7713-(CAN-SPAM Act), 18 U.S.C. § 1030-(COMPUTER FRAUD & ABUSE ACT), 18 U.S.C. § 1343-(WIRE FRAUD)"
        }

        response = requests.post(api_url, headers=headers, data=data, timeout=30)
        
        try:
            resp_json = response.json()
        except ValueError:
            resp_json = {}

        if response.status_code in [200, 201]:
            job_id = resp_json.get('job_id', 'N/A')
            sha256 = resp_json.get('sha256', 'N/A')
            logger.info("Successfully submitted %s to Hybrid Analysis (Job ID: %s, SHA256: %s)", url, job_id, sha256)
            return True
        elif response.status_code == 429:
            logger.warning("Hybrid Analysis rate limit reached.")
            return False
        else:
            error_msg = resp_json.get('message', response.text)
            logger.error("Failed to submit %s to Hybrid Analysis: %s - %s", url, response.status_code, error_msg)
            return False

    except Exception as e:
        logger.error("Error submitting %s to Hybrid Analysis: %s", url, e)
        return False
