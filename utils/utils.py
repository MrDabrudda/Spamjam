# utils/utils.py

import sys
import time
import subprocess
import re
import fnmatch
import logging
from typing import List
from urllib.parse import urlparse
import ipaddress
from .config import EXCLUDED_DOMAINS

logger = logging.getLogger(__name__)

_last_api_call = {}

def enforce_rate_limit(service_name: str, interval: float = 30.0) -> None:
    """
    Enforce a rate limit (default 2 per minute / 30s interval) with a countdown.
    """
    global _last_api_call
    last_time = _last_api_call.get(service_name, 0)
    now = time.time()
    elapsed = now - last_time

    if elapsed < interval:
        wait_time = interval - elapsed
        if wait_time > 0:
            rate = int(60 / interval) if interval > 0 else 0
            sys.stdout.write(f"\n[Rate Limit] {service_name}: Enforcing {rate} requests/min limit.\n")
            try:
                while wait_time > 0:
                    sys.stdout.write(f"\r⏳ Cooldown: {int(wait_time)+1}s remaining... ")
                    sys.stdout.flush()
                    sleep_time = min(1.0, wait_time)
                    time.sleep(sleep_time)
                    wait_time -= sleep_time
                sys.stdout.write("\r✅ Resuming...                  \n")
            except KeyboardInterrupt:
                sys.stdout.write("\n")
                raise

    _last_api_call[service_name] = time.time()


def is_valid_ipv4(ip: str) -> bool:
    try:
        return type(ipaddress.ip_address(ip)) is ipaddress.IPv4Address
    except ValueError:
        return False


def redact_email_content(content: str, emails_to_redact: List[str]) -> str:
    if not content or not emails_to_redact:
        return content
    escaped_emails = [re.escape(email.strip()) for email in emails_to_redact if email.strip()]
    if not escaped_emails:
        return content
    pattern = r"\b(" + "|".join(escaped_emails) + r")\b"
    try:
        return re.sub(pattern, "[REDACTED]", content, flags=re.IGNORECASE)
    except re.error as e:
        logger.warning("Regex error during redaction: %s", e)
        return content


def extract_ips_from_headers(headers: str) -> List[str]:
    if not headers:
        return []
    ip_patterns = [
        r"X-Originating-IP:\s*\[?(\d+\.\d+\.\d+\.\d+)\]?",
        r"X-Sender-IP:\s*(\d+\.\d+\.\d+\.\d+)",
        r"Received:\s*from\s+\S+\s+\[(\d+\.\d+\.\d+\.\d+)\]",
    ]
    ips = []
    for pattern in ip_patterns:
        matches = re.findall(pattern, headers, re.IGNORECASE)
        for ip in matches:
            if is_valid_ipv4(ip):
                ips.append(ip)
    seen = set()
    return [ip for ip in ips if not (ip in seen or seen.add(ip))]


def is_url_excluded(url: str) -> bool:
    if not url:
        return False
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower().strip()
        if not hostname:
            return False

        def _matches_any(hostname: str, patterns: List[str]) -> bool:
            for pattern in patterns or []:
                pattern = pattern.strip().lower()
                if fnmatch.fnmatch(hostname, pattern):
                    return True
                # Allow *.domain.com to match domain.com
                if pattern.startswith("*.") and hostname == pattern[2:]:
                    return True
            return False

        return _matches_any(hostname, EXCLUDED_DOMAINS)
    except Exception as e:
        logger.debug("Error checking URL exclusion: %s", e)
        return False


def perform_traceroute(target_ip: str, max_hops: int = 15) -> List[str]:
    """
    Perform a traceroute to the target IP and return a list of hop IPs.
    Uses system 'traceroute' (Linux/Mac) or 'tracert' (Windows).
    """
    hops = []
    cmd = []

    # Construct command based on OS
    if sys.platform.lower().startswith("win"):
        cmd = ["tracert", "-h", str(max_hops), "-d", target_ip]
    else:
        # Linux/Unix: -n (no DNS), -m (max hops), -q 1 (1 query/hop), -w 1 (1s wait)
        cmd = ["traceroute", "-n", "-m", str(max_hops), "-q", "1", "-w", "1", target_ip]

    try:
        # Run with timeout to prevent hanging
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=20
        )

        for line in result.stdout.splitlines():
            # Extract IPs from output line
            ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
            if ips:
                # On Linux 'traceroute -n', the first IP is usually the hop.
                # On Windows 'tracert -d', the IP is at the end.
                ip = ips[0] if not sys.platform.lower().startswith("win") else ips[-1]
                
                if is_valid_ipv4(ip) and ip != target_ip:
                    hops.append(ip)

    except Exception as e:
        logger.debug("Traceroute failed or not installed: %s", e)

    return hops


def open_thunderbird(to_emails: List[str], subject: str, body: str) -> None:
    """
    Open Thunderbird compose window with provided details.
    """
    if not to_emails:
        return

    # Join emails with commas
    to_addr = ",".join(to_emails)
    
    # Escape single quotes and commas for the command line argument parser of Thunderbird
    # The syntax is -compose "key='value',key='value'"
    def clean_arg(s):
        if not s: return ""
        return s.replace("\\", "\\\\").replace("'", "\\'").replace(",", "\\,")

    # Construct the command argument string
    # Note: We pass the body directly.
    compose_args = f"to='{to_addr}',subject='{clean_arg(subject)}',body='{clean_arg(body)}'"
    
    try:
        subprocess.Popen(["thunderbird", "-compose", compose_args])
        logger.info("Opened Thunderbird compose window for %s recipients.", len(to_emails))
    except FileNotFoundError:
        logger.warning("Thunderbird executable not found in PATH.")
    except Exception as e:
        logger.error("Error opening Thunderbird: %s", e)