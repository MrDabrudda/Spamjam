# utils/email_processor.py

import email
import logging
from email.header import decode_header, make_header
from typing import Tuple, Optional, List
from .utils import extract_ips_from_headers

logger = logging.getLogger(__name__)

def parse_email_file(filepath: str) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read()
        msg = email.message_from_string(raw)
        headers = str(msg).split("\n\n", 1)[0]

        subject = None
        if msg["Subject"]:
            try:
                subject = str(make_header(decode_header(msg["Subject"])))
            except Exception:
                subject = msg["Subject"]

        html_body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/html":
                    payload = part.get_payload(decode=True)
                    if isinstance(payload, bytes):
                        html_body = payload.decode("utf-8", errors="replace")
                    elif isinstance(payload, str):
                        html_body = payload
                    else:
                        html_body = ""
                    break
        else:
            if msg.get_content_type() == "text/html":
                payload = msg.get_payload(decode=True)
                if isinstance(payload, bytes):
                    html_body = payload.decode("utf-8", errors="replace")
                elif isinstance(payload, str):
                    html_body = payload
                else:
                    html_body = ""

        return raw, headers, html_body, subject
    except Exception as e:
        logger.error("Failed to parse email file: %s", e)
        return None, None, None, None

def get_sender_ip_from_email(headers: str) -> Optional[str]:
    """Extract the most likely sender IP from headers."""
    ips = extract_ips_from_headers(headers)
    if ips:
        logger.info("Found sender IPs: %s", ips)
        return ips[0]  # Use first as primary
    logger.warning("No sender IP found in headers")
    return None