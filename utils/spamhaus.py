import logging
import requests
from . import config

logger = logging.getLogger(__name__)

def report_to_spamhaus(url: str) -> bool:
    """
    Submit a URL to Spamhaus for analysis.
    API Docs: https://submit.spamhaus.org/portal/api/v1/submissions/add/url
    """
    if not hasattr(config, 'SPAMHAUS_API_KEY') or not config.SPAMHAUS_API_KEY:
        return False

    # Endpoint for URL submission
    api_url = "https://submit.spamhaus.org/portal/api/v1/submissions/add/url"
    
    headers = {
        "Authorization": f"Bearer {config.SPAMHAUS_API_KEY.strip()}",
        "Content-Type": "application/json"
    }
    
    # Payload structure based on Spamhaus API requirements
    payload = {
        "threat_type": "source-of-spam",
        "reason": "Phishing/Spam URL detected in unsolicited email",
        "source": {
            "object": url
        }
    }
    
    try:
        response = requests.post(api_url, json=payload, headers=headers, timeout=15)
        
        if response.status_code in [200, 201, 202]:
            logger.info(f"Submitted {url} to Spamhaus")
            return True
        else:
            logger.error(f"Spamhaus submission failed for {url}: {response.status_code} - {response.text}")
            
    except Exception as e:
        logger.error(f"Error reporting to Spamhaus: {e}")
        
    return False
