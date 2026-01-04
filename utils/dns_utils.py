# utils/dns.py

import dns.resolver
import dns.reversename  # Required for reverse DNS lookups
import dns.exception
import logging
from typing import List, Tuple, Optional, Any

try:
    from .config import DNSBL_SERVERS
except (ImportError, AttributeError):
    # Fallback defaults if config is missing or incomplete
    DNSBL_SERVERS = [
        "zen.spamhaus.org",
        "dnsbl.sorbs.net",
        "b.barracudacentral.org"
    ]
from .utils import is_valid_ipv4

logger = logging.getLogger(__name__)


def reverse_dns_lookup(ip: str) -> Optional[str]:
    """Perform reverse DNS lookup for an IP."""
    try:
        rev_name = dns.reversename.from_address(ip)
        return str(dns.resolver.resolve(rev_name, "PTR")[0]).rstrip(".")
    except Exception as e:
        logger.debug("Reverse DNS failed for %s: %s", ip, e)
        return None


def check_dnsbl(ip: str, dnsbl_servers: Optional[List[str]] = None) -> List[str]:
    """Check if IP is listed in DNSBLs."""
    if not dnsbl_servers:
        dnsbl_servers = DNSBL_SERVERS

    listed = []
    reversed_ip = ".".join(reversed(ip.split(".")))
    for bl in dnsbl_servers:
        try:
            query = f"{reversed_ip}.{bl}"
            dns.resolver.resolve(query, "A")
            listed.append(bl)
            logger.info("IP %s listed in %s", ip, bl)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except dns.exception.DNSException as e:
            logger.warning("DNSBL check error for %s on %s: %s", ip, bl, e)
        except Exception as e:
            logger.warning("Unexpected error checking %s on %s: %s", ip, bl, e)
    return listed


def get_mx_records(domain: str) -> List[Tuple[str, int, str]]:
    """
    Get MX records for a domain and resolve hostnames to IP addresses.

    Returns:
        List of tuples: (ip_address, priority, mx_hostname)
        If IP resolution fails, returns (mx_hostname, priority, mx_hostname)
    """
    try:
        answers = dns.resolver.resolve(domain, "MX")
        mx_list = []
        for r in (answers.rrset or []):
            mx_host = str(r.exchange).rstrip(".")
            priority = r.preference

            # Resolve MX hostname to IP address
            try:
                # Get all A records (IPv4 only, per SpamJam spec)
                ip_answers = dns.resolver.resolve(mx_host, "A")
                for ip_answer in (ip_answers.rrset or []):
                    ip = str(ip_answer)
                    mx_list.append((ip, priority, mx_host))
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                # If no A record, fall back to hostname
                logger.debug("Could not resolve MX host %s to IP for domain %s", mx_host, domain)
                mx_list.append((mx_host, priority, mx_host))
            except Exception as e:
                logger.debug("Unexpected error resolving %s: %s", mx_host, e)
                mx_list.append((mx_host, priority, mx_host))

        return mx_list
    except Exception as e:
        logger.debug("MX lookup failed for %s: %s", domain, e)
        return []


def resolve_domain_to_ipv4(domain: str) -> Optional[List[str]]:
    """
    Resolve a domain name to ALL its IPv4 addresses (A records).
    
    Args:
        domain (str): Domain to resolve (e.g., 'example.com')
    
    Returns:
        List[str] or None: List of IPv4 addresses, or None if resolution fails
    """
    try:
        domain = domain.strip().lower()
        if not domain or "." not in domain:
            return None
        
        # Resolve ALL A records (IPv4 only)
        answers = dns.resolver.resolve(domain, "A", lifetime=5)
        ips = []
        for answer in (answers.rrset or []):
            ip = str(answer)
            if is_valid_ipv4(ip):  # Reuse your existing validation
                ips.append(ip)
        
        return ips if ips else None
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        logger.debug("Could not resolve domain to IPv4: %s", domain)
    except Exception as e:
        logger.debug("DNS resolution error for %s: %s", domain, e)
    return None