# utils/virustotal.py

import requests
import base64
import time
import logging
from typing import Optional
from .config import VIRUSTOTAL_API_KEY, RATE_LIMIT_VIRUSTOTAL
from .utils import enforce_rate_limit

logger = logging.getLogger(__name__)

VIRUSTOTAL_API_BASE = "https://www.virustotal.com/api/v3"
HTTP_TIMEOUT = 30

def _get_url_id(url: str) -> str:
    """
    Generate VirusTotal URL identifier.
    Base64 representation of the URL, stripped of '=' padding.
    """
    try:
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    except Exception:
        return ""

def report_to_virustotal(url: str, comment: Optional[str] = None) -> bool:
    """
    Submit a URL to VirusTotal for scanning and add a comment.
    """
    if not VIRUSTOTAL_API_KEY:
        logger.warning("VirusTotal API key not configured.")
        return False

    url = url.strip()

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    # 1. Submit URL for scanning
    enforce_rate_limit("VirusTotal", RATE_LIMIT_VIRUSTOTAL)
    scan_endpoint = f"{VIRUSTOTAL_API_BASE}/urls"
    
    # Form data for URL submission
    data = {"url": url}
    
    success = False
    try:
        response = requests.post(scan_endpoint, headers=headers, data=data, timeout=HTTP_TIMEOUT)
        if response.status_code in [200, 201]:
            logger.info("Successfully submitted URL to VirusTotal: %s", url)
            success = True
        else:
            logger.error("Failed to submit URL to VirusTotal: %s %s", response.status_code, response.text)
            # If scan fails, we probably shouldn't try to comment
            return False
    except Exception as e:
        logger.error("Error submitting to VirusTotal: %s", e)
        return False

    # 2. Add comment and vote if scan was successful
    if success:
        # Allow a brief pause for VirusTotal to propagate the new scan entry
        time.sleep(5)

        url_id = _get_url_id(url)
        if not url_id:
            logger.error("Could not generate URL ID for VirusTotal operations.")
            return success # Return True because scan worked

        # Add Comment
        if comment:
            enforce_rate_limit("VirusTotal", RATE_LIMIT_VIRUSTOTAL)
            comment_endpoint = f"{VIRUSTOTAL_API_BASE}/urls/{url_id}/comments"
            
            # Truncate comment to 500 characters to ensure API acceptance
            if len(comment) > 500:
                logger.warning("VirusTotal comment length %d exceeds 500 limit. Truncating cleanly.", len(comment))
                limit = 500 - 20
                truncated = comment[:limit]
                last_newline = truncated.rfind('\n')
                if last_newline > 0:
                    comment = truncated[:last_newline] + "\n[...truncated...]"
                else:
                    comment = truncated + "\n[...]"

            payload = {
                "data": {
                    "type": "comment",
                    "attributes": {
                        "text": comment
                    }
                }
            }

            for attempt in range(3):
                try:
                    response = requests.post(comment_endpoint, headers=headers, json=payload, timeout=HTTP_TIMEOUT)
                    if response.status_code == 200:
                        logger.info("Successfully added comment to VirusTotal.")
                        break
                    elif response.status_code >= 500:
                        logger.warning("VirusTotal server error %s (attempt %d/3). Retrying...", response.status_code, attempt + 1)
                        time.sleep(5)
                    else:
                        logger.warning("Failed to add comment to VirusTotal: %s %s", response.status_code, response.text)
                        break
                except Exception as e:
                    logger.error("Error adding comment to VirusTotal: %s", e)
                    break

        # Add Vote (Malicious)
        enforce_rate_limit("VirusTotal", RATE_LIMIT_VIRUSTOTAL)
        vote_endpoint = f"{VIRUSTOTAL_API_BASE}/urls/{url_id}/votes"
        
        vote_payload = {
            "data": {
                "type": "vote",
                "attributes": {
                    "verdict": "malicious"
                }
            }
        }

        try:
            response = requests.post(vote_endpoint, headers=headers, json=vote_payload, timeout=HTTP_TIMEOUT)
            if response.status_code == 200:
                logger.info("Successfully voted 'malicious' on VirusTotal.")
            else:
                logger.warning("Failed to vote on VirusTotal: %s %s", response.status_code, response.text)
        except Exception as e:
            logger.error("Error voting on VirusTotal: %s", e)

    return success
