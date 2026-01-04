# utils/whois.py

import re
import socket
import logging
import time
import ipaddress
from typing import Optional, Dict, Any, List
from . import config

logger = logging.getLogger(__name__)


def get_whois_info(target: str) -> Optional[Dict[str, Any]]:
    """
    Perform a WHOIS lookup for an IP or Domain.
    Handles referrals (e.g. .com -> Verisign -> Registrar) and basic IP parsing.
    For domains, attempts to strip subdomains if the initial lookup yields no results.
    """
    target = target.strip()
    try:
        ipaddress.ip_address(target)
        is_ip = True
    except ValueError:
        is_ip = False

    current_target = target
    while True:
        result = _perform_lookup(current_target, is_ip)
        
        # If we found a registrar or emails, or if it's an IP, we consider it a success
        if result and (is_ip or result["registrar"] or result["emails"]):
            return result
        
        # If it's a domain and we didn't find good info, try stripping a subdomain
        if not is_ip:
            parts = current_target.split('.')
            if len(parts) > 2:
                current_target = ".".join(parts[1:])
                time.sleep(1.0) # Rate limit protection
                continue
        
        # If we're here, we either failed on IP or ran out of domain parts
        return result


def _perform_lookup(target: str, is_ip: bool) -> Optional[Dict[str, Any]]:
    # 1. Identify the Root WHOIS Server (IANA)
    server = _get_root_server(target, is_ip)
    if not server:
        return None

    raw_response = ""
    seen_servers = set()
    
    # 2. Query Loop (Follow Referrals)
    # We limit to 3 hops to prevent loops (IANA -> Registry -> Registrar)
    for _ in range(3):
        if not server or server in seen_servers:
            break
        seen_servers.add(server)

        response = _query_server(server, target)
        if not response:
            break
        
        raw_response += f"\n\n--- Response from {server} ---\n{response}"

        # Check for Referrals (common in .com, .net, and some IPs)
        # Pattern matches "Whois Server: ..." or "ReferralServer: ..."
        referral_match = re.search(r"(?:Whois Server|ReferralServer|Registrar Whois):\s*(?:whois://)?([a-zA-Z0-9.-]+)", response, re.IGNORECASE)
        if referral_match:
            next_server = referral_match.group(1).strip()
            # Only follow if it's a new server
            if next_server and next_server.lower() not in seen_servers:
                server = next_server.lower()
                time.sleep(0.5) # Be polite
                continue

        # Handle ARIN Ambiguity (IPs only)
        # ARIN might return a list of networks. We want the most specific one.
        if is_ip and "Query terms are ambiguous" in response:
            # Find all network handles, e.g., (NET-1-2-3-4-1)
            handles = re.findall(r"\((NET-[^)]+)\)", response)
            if handles:
                # The last handle is usually the most specific assignment
                specific_handle = handles[-1]
                # Query the same server (ARIN) for this handle
                time.sleep(0.5)
                sub_response = _query_server(server, specific_handle)
                if sub_response:
                    raw_response += f"\n\n--- Response from {server} (Refined) ---\n{sub_response}"
        
        # If no referral and no ambiguity, we are done.
        break

    if not raw_response:
        return None

    return {
        "registrar": _extract_registrar(raw_response),
        "emails": _extract_abuse_emails(raw_response),
        "raw": raw_response.strip()
    }


def _get_root_server(target: str, is_ip: bool) -> Optional[str]:
    """Query IANA to determine the initial WHOIS server."""
    query = target
    if not is_ip:
        # For domains, query the TLD (e.g., "com")
        parts = target.split('.')
        if len(parts) > 1:
            query = parts[-1]
    
    # Query IANA
    response = _query_server(config.IANA_WHOIS_SERVER, query)
    if not response:
        # Fallback for IPs if IANA fails
        return "whois.arin.net" if is_ip else None

    # Parse IANA response for "refer: ..." or "whois: ..."
    match = re.search(r"^\s*(?:refer|whois):\s*(\S+)", response, re.MULTILINE | re.IGNORECASE)
    if match:
        server = match.group(1).strip()
        # Fix known IANA quirks
        if server == "whois.nic.br": return "whois.lacnic.net"
        return server
    
    return "whois.arin.net" if is_ip else None


def _query_server(server: str, query: str) -> Optional[str]:
    """Perform a raw socket WHOIS query."""
    try:
        with socket.create_connection((server, 43), timeout=config.WHOIS_TIMEOUT) as s:
            s.send(f"{query}\r\n".encode())
            response = b""
            while True:
                data = s.recv(4096)
                if not data: break
                response += data
            return response.decode('utf-8', errors='replace')
    except Exception as e:
        logger.debug(f"WHOIS query to {server} failed: {e}")
        return None


def _extract_abuse_emails(raw: str) -> List[str]:
    """Extract abuse emails using strict headers first, then context-aware fallback."""
    emails = set()
    
    # 1. Strict Headers (High Confidence)
    # Matches: "OrgAbuseEmail: ...", "Registrar Abuse Contact Email: ...", "abuse-mailbox: ..."
    header_patterns = [
        r"(?:OrgAbuseEmail|Registrar Abuse Contact Email|Abuse Contact Email|abuse-mailbox)\s*:\s*(\S+)",
        r"OrgNOCEmail\s*:\s*(\S+)"
    ]
    
    for pattern in header_patterns:
        for match in re.finditer(pattern, raw, re.IGNORECASE):
            email = match.group(1).strip().rstrip(".,;)")
            if _is_valid_email(email):
                emails.add(email.lower())

    # 2. Context-Aware Fallback
    # Only look for emails in lines that contain "abuse" or "noc"
    if not emails:
        for line in raw.splitlines():
            if "abuse" in line.lower() or "noc" in line.lower():
                found = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", line)
                for email in found:
                    if _is_valid_email(email):
                        emails.add(email.lower())

    return sorted(list(emails))


def _extract_registrar(raw: str) -> Optional[str]:
    """Extract Registrar name."""
    match = re.search(r"^\s*(?:Registrar|Sponsoring Registrar|Registrar Name):\s*(.+)", raw, re.MULTILINE | re.IGNORECASE)
    return match.group(1).strip() if match else None


def _is_valid_email(email: str) -> bool:
    """Basic validation and filtering of infrastructure emails."""
    if "@" not in email or "." not in email.split("@")[-1]:
        return False
    
    # Filter out common false positives / infrastructure emails that aren't actionable
    ignored = {"noc@arin.net", "hostmaster@arin.net", "whois@arin.net", "abuse@iana.org"}
    return email.lower() not in ignored


def is_brazilian_ip(ip: str) -> bool:
    """Check if IP is likely Brazilian to fallback to CERT.br."""
    return ip.startswith(("177.", "179.", "186.", "187.", "189.", "191.", "200.", "201."))