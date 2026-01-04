import requests
import logging
import base64
from . import config
from .utils import redact_email_content, enforce_rate_limit

logger = logging.getLogger(__name__)

def report_to_spam_org(raw_email: str):
    """
    Report raw email headers and body to Spam.org.
    """
    
    if not hasattr(config, 'SPAM_ORG_API_KEY') or not config.SPAM_ORG_API_KEY:
        return
    api_key = str(config.SPAM_ORG_API_KEY).strip()

    # Rate limiting: Default to 5 seconds between requests if not specified
    limit = getattr(config, 'RATE_LIMIT_SPAM_ORG', 5.0)
    enforce_rate_limit("Spam.org", limit)

    api_url = "https://api.spam.org/api"
    
    # Redact emails defined in config
    redact_list = getattr(config, 'REDACT_EMAILS', [])
    clean_email = redact_email_content(raw_email, redact_list)
    
    # Base64 encode the raw email
    email_b64 = base64.b64encode(clean_email.encode('utf-8', errors='replace')).decode('utf-8')

    # Construct payload with all parameters in the body
    data = {
        "a": "report_spam",
        "k": api_key,
        "type": "spam",
        "spam_reason": "Phishing Email",
        "data": email_b64
    }

    try:
        # Using POST to handle large Base64 payloads
        response = requests.post(api_url, data=data, timeout=30)
        
        if response.status_code in [200, 201]:
            try:
                resp_json = response.json()
                if resp_json.get("success"):
                    logger.info("Successfully reported email to Spam.org.")
                else:
                    logger.warning("Spam.org reported failure: %s", resp_json.get("message", "Unknown error"))
            except ValueError:
                logger.info("Successfully reported email to Spam.org (Non-JSON response).")
            return
        elif response.status_code == 429:
            logger.warning("Spam.org rate limit reached.")
        else:
            logger.debug("Spam.org report failed: %s - %s", response.status_code, response.text)
    except Exception as e:
        logger.error("Error reporting to Spam.org: %s", e)

    return
