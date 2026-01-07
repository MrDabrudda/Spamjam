import logging
import requests
from urllib.parse import quote
from . import config

logger = logging.getLogger(__name__)

def report_to_ipqs(url: str) -> bool:
    """
    Submit a URL to IPQS for scanning.
    """
    if not hasattr(config, 'IPQS_API_KEY') or not config.IPQS_API_KEY:
        return False

    try:
        # IPQS requires the URL to be URL-encoded and appended to the path
        # Format: https://www.ipqualityscore.com/api/json/url/API_KEY/URL_ENCODED
        encoded_url = quote(url, safe='')
        api_key = config.IPQS_API_KEY.strip()
        api_url = f"https://www.ipqualityscore.com/api/json/url/{api_key}/{encoded_url}"
        
        # The API uses a GET request for this endpoint structure
        response = requests.get(api_url, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            if data.get("success"):
                logger.info(f"Submitted {url} to IPQS: {data.get('message', 'Success')}")
                return True
            else:
                logger.error(f"IPQS submission failed for {url}: {data.get('message')}")
        else:
            logger.error(f"IPQS API returned status code {response.status_code}")
            
    except Exception as e:
        logger.error(f"Error reporting to IPQS: {e}")
        
    return False
