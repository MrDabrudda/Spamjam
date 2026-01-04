import requests
import logging
from typing import List, Optional, Dict, Any
from . import config

logger = logging.getLogger(__name__)


def check_abuseipdb(ip: str) -> Optional[Dict[str, Any]]:
    """Check IP reputation against AbuseIPDB."""
    if not hasattr(config, 'ABUSEIPDB_API_KEY') or not config.ABUSEIPDB_API_KEY:
        return None

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        'Key': config.ABUSEIPDB_API_KEY,
        'Accept': 'application/json'
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': 90
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json().get('data', {})
            return {
                'abuse_score': data.get('abuseConfidenceScore', 0),
                'total_reports': data.get('totalReports', 0),
                'usage_type': data.get('usageType', 'Unknown'),
                'isp': data.get('isp', 'Unknown'),
                'domain': data.get('domain', 'Unknown'),
                'country': data.get('countryCode', 'Unknown')
            }
        elif response.status_code == 429:
            logger.warning("AbuseIPDB rate limit reached.")
        else:
            logger.debug("AbuseIPDB check failed: %s", response.status_code)
    except Exception as e:
        logger.debug("AbuseIPDB connection error: %s", e)
    
    return None


def report_to_abuseipdb(ip: str, categories: List[int], comment: str) -> bool:
    """Report an IP to AbuseIPDB."""
    if not hasattr(config, 'ABUSEIPDB_API_KEY') or not config.ABUSEIPDB_API_KEY:
        return False

    url = "https://api.abuseipdb.com/api/v2/report"
    headers = {
        'Key': config.ABUSEIPDB_API_KEY,
        'Accept': 'application/json'
    }
    
    # Categories must be a comma-separated string
    cats = ",".join(str(c) for c in categories)
    
    data = {
        'ip': ip,
        'categories': cats,
        'comment': comment[:1024]
    }

    try:
        response = requests.post(url, headers=headers, data=data, timeout=15)
        if response.status_code == 200:
            logger.info("Reported %s to AbuseIPDB.", ip)
            return True
        else:
            logger.error("Failed to report %s to AbuseIPDB: %s", ip, response.text)
    except Exception as e:
        logger.error("Error reporting to AbuseIPDB: %s", e)
        
    return False
