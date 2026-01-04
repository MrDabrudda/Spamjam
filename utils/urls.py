# utils/urls.py

import re
from urllib.parse import urlparse
from typing import List

def normalize_url(url: str) -> str:
    """
    Normalize a URL for deduplication by:
    - Removing scheme (http/https)
    - Converting domain to lowercase
    - Stripping 'www.' prefix from domain
    - Removing trailing slash from path (except root path '/')
    - Ignoring query parameters and fragments (optional: can be enabled)

    Examples:
        'https://www.example.com/page/'   → 'example.com/page'
        'http://example.com/page?utm=1'   → 'example.com/page'
        'https://example.com/'            → 'example.com/'
        'http://sub.example.com'          → 'sub.example.com'

    Args:
        url (str): Raw URL string.

    Returns:
        str: Normalized key for deduplication.
    """
    try:
        # Parse URL
        parsed = urlparse(url)
        netloc = parsed.netloc.lower().strip()

        # Remove 'www.' prefix only if it's at the start and followed by a dot or end
        if netloc.startswith("www.") and len(netloc) > 4:
            netloc = netloc[4:]

        # Handle path
        path = parsed.path or "/"
        # Remove trailing slashes only if path is not root
        if path != "/" and path.endswith("/"):
            path = path.rstrip("/")

        # Construct normalized key: netloc + path
        # (Query and fragment are intentionally ignored for deduplication)
        normalized = netloc + path
        return normalized
    except Exception:
        # Fallback: return lowercase stripped string if parsing fails
        return url.lower().strip()


def extract_urls_from_html(html: str) -> List[str]:
    """
    Extract and deduplicate URLs from HTML content.

    Deduplication is based on normalized URLs (ignoring http/https, www, trailing slashes).
    The first occurrence of each unique URL (in original form) is preserved.

    Args:
        html (str): HTML content of the email.

    Returns:
        List[str]: List of unique URLs in original format.
    """
    if not html:
        return []

    # Regex to find http/https URLs (stops at common delimiters)
    url_pattern = re.compile(
        r"https?://[^\s<>'\"{}|\\^`]+",
        re.IGNORECASE
    )
    urls = url_pattern.findall(html)

    # Clean common trailing punctuation
    cleaned_urls = []
    for url in urls:
        # Remove trailing punctuation that might be part of surrounding text
        cleaned = url.rstrip(".,;?!)]}'\"")
        if cleaned.startswith(("http://", "https://")):
            cleaned_urls.append(cleaned)

    # Deduplicate using normalized keys, preserve original order and format
    seen_normalized = set()
    unique_original_urls = []

    for url in cleaned_urls:
        norm_key = normalize_url(url)
        if norm_key not in seen_normalized:
            seen_normalized.add(norm_key)
            unique_original_urls.append(url)

    return unique_original_urls