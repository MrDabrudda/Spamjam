# utils/config.py
import os

# =============================================================================
# SpamJam Configuration
# =============================================================================

# -----------------------------------------------------------------------------
# API Keys (required for reputation checks)
# -----------------------------------------------------------------------------

# API Keys
ABUSEIPDB_API_KEY = ""
CRDF_API_KEY = "" #<---2 submission per minute, limit of 200 per day
URLSCAN_API_KEY = ""
HYBRID_ANALYSIS_API_KEY = ""
SPAM_ORG_API_KEY = ""
VIRUSTOTAL_API_KEY = ""

# -----------------------------------------------------------------------------
# System Settings (Cache, Files, Network)
# -----------------------------------------------------------------------------

# Directory to scan for .eml files
EMAILS_DIR = "emails"

# Cache settings
CACHE_DIR = ".spamjam_cache"
CACHE_FILE = os.path.join(CACHE_DIR, "cache")
CACHE_TTL_SECONDS = 1800  # 30 minutes

# WHOIS settings
IANA_WHOIS_SERVER = "whois.iana.org"
WHOIS_TIMEOUT = 10

# Rate Limits (seconds per request)
RATE_LIMIT_ABUSEIPDB = 4.0     # 150 submissions/min
RATE_LIMIT_CRDF = 32.0         # 2 submissions/min <--Very flaky even at 30sec
RATE_LIMIT_URLSCAN = 2.0       # 30 submissions/min
HYBRID_ANALYSIS_RATE_LIMIT = 10 # 6 submissions/min
HYBRID_ANALYSIS_RATE_WINDOW = 20
RATE_LIMIT_SPAM_ORG = 2.0      # 30 submissions/min
RATE_LIMIT_VIRUSTOTAL = 15.0   # 4 submissions/min (Public API)

# -----------------------------------------------------------------------------
# Privacy & Redaction
# -----------------------------------------------------------------------------

# Email addresses to redact in output reports (case-insensitive)
# These will be replaced with "[REDACTED]" in the raw email section
REDACT_EMAILS = [
    # "youremail@email.com",
    # "admin@company.com",
    # "username",
    # "anything you want redacted from the email which gets submitted"
]

# -----------------------------------------------------------------------------
# DNS Blackhole Lists (DNSBL)
# -----------------------------------------------------------------------------

# List of DNSBL servers to check sender IPs against
# Common choices: Spamhaus, SORBS, Barracuda
DNSBL_SERVERS = [
    "zen.spamhaus.org",      # Spamhaus (includes XBL for hijacked IPs)
    "dnsbl.sorbs.net",       # SORBS
    "b.barracudacentral.org", # Barracudas
]

# -----------------------------------------------------------------------------
# Global Abuse Reporting Addresses
# -----------------------------------------------------------------------------

# Well-known abuse reporting addresses for phishing, spam, and scams
# These appear in the final report for easy forwarding
GLOBAL_ABUSE_EMAILS = [
    "reportphishing@apwg.org",          # Anti-Phishing Working Group (phishing URLs)
    #"phishing-report@us-cert.gov",     # U.S. CISA (phishing & cyber incidents) <---No longer active
    "scam@netcraft.com",                # Netcraft (scams & phishing sites)
    "spam@donotpay.com",                # DoNotPay Spam Reporting
    "spamreport@spamrl.com",            # Spam Reporting Service
    "abuse@phishtank.com",              # PhishTank (phishing URLs)
    #"support@urlhaus.abuse.ch",        # Abuse contact for URLhaus (malware URLs) <---Only accepts malware...not phishing urls
]
# -----------------------------------------------------------------------------
# Domain Exclusions
# -----------------------------------------------------------------------------

# Combined list of domains to exclude from reporting and analysis
# Includes infrastructure, CDNs, and other non-malicious hosts.
EXCLUDED_DOMAINS = [
    # CDN and image hosting
    "*.imgur.com",
    "*.freepnglogos.com",
    "*.flaticon.com",
    "*.hotmail.com",
    "*.@hotmail.com",
    "*.gov",
    
    # Infrastructure, etc
    "*.onmicrosoft.com",
    "*.prod.outlook.com",
    "*.outlook.com",
    "*.mail.protection.outlook.com",
    "*.protection.outlook.com",
    "*.messaging.microsoft.com",
    "*.googleapis.com",
    "cdnjs.cloudflare.com",
    "www.w3.org",
    "*.schemas.microsoft.com",
    "*.avast.com",
    "*.avcdn.net",
    "*.wikimedia.com",
    "www.google.com",
    
    # AWS
    "*.amazonses.com",
]
