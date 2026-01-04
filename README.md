# 🕵️‍♂️ SpamJam — Email Threat Intelligence Analyzer

SpamJam is a powerful **open-source Python tool** that extracts and analyzes email headers, URLs, and infrastructure to identify malicious senders, botnets, phishing campaigns, and spam sources. It provides **actionable abuse contacts**, **reputation scores**, and **reporting guidance** — all in one report.

---
<a href="https://www.abuseipdb.com/user/92481" title="AbuseIPDB is an IP address blacklist for webmasters and sysadmins to report IP addresses engaging in abusive behavior on their networks">
  <img src="https://www.abuseipdb.com/contributor/92481.svg" alt="AbuseIPDB Contributor Badge" style="width: 361px;">
</a>

<br>
<br>
## 🌟 Features

### 🔍 **Email Analysis**
- **Header Extraction**: Automatically identifies and extracts the true sender IP from complex headers like `X-Originating-IP` and `Received` chains.
- **EML Parsing**: Full support for RFC 2822 `.eml` files, handling attachments and multipart messages.
- **Privacy Redaction**: Automatically detects and redacts private email addresses in the output to protect victim identity.
- **URL Extraction**: Scrapes and deduplicates URLs from the email body, normalizing them (ignoring `http`/`https`, `www`) for analysis.

### 🌐 **Infrastructure Intelligence**
- **Domain Resolution**: Resolves domains to their hosting IPs (A records) to identify physical infrastructure.
- **Mail Server Analysis**: Performs deep MX record lookups to uncover the mail servers handling the domain's traffic.
- **WHOIS Lookup**: Retrieves registration data for IPs and domains to identify owners and registrars.
- **Reverse DNS (PTR)**: Checks PTR records to verify if IP addresses map back to the claimed domain.
- **Traceroute Analysis**: Traces the network path to the suspect IP to identify intermediate hops and network location (requires `traceroute`).

### 🛡️ **Reputation & Threat Checks**
- **AbuseIPDB Integration**: Fetches abuse confidence scores, report counts, and ISP/Country data.
- **VirusTotal Scanning**: Checks IPs and URLs against VirusTotal's database for malicious or suspicious flags.
- **DNSBL Lookups**: Queries major DNS Blacklists (Spamhaus, SORBS, etc.) to check if the sender is a known spammer.
- **Botnet Detection**: Heuristically flags IPs that exhibit characteristics of zombie networks or compromised hosts.

### 📧 **Abuse Contact Intelligence**
- **Comprehensive Contact Discovery**: Extracts abuse contacts from Hosting IPs, Mail Server IPs, and Domain Registrars via WHOIS.
- **Smart Fallback**: Intelligently identifies alternative contact emails if a specific `abuse@` address is missing.
- **Deduplication**: Aggregates and removes duplicate contact emails to provide a clean list for reporting.

### 🌍 **Global Reporting**
- **Pre-configured Reporting List**: Includes a curated list of global abuse reporting addresses such as:
  - `reportphishing@apwg.org` (Anti-Phishing Working Group)
  - `phishing-report@us-cert.gov` (CISA)
  - `scam@netcraft.com` (Netcraft)
  - `spam@donotpay.com`, `spamreport@spamrl.com`, and others.

### ⚡ **Performance & Efficiency**
- **Smart Caching**: Implements disk-based caching with a 1-hour TTL for DNS, WHOIS, and API lookups (AbuseIPDB, VirusTotal) to minimize API quota usage and speed up re-runs.
- **Batch Processing**: Capable of processing multiple `.eml` files in the `emails/` directory simultaneously.

### 📁 **Output**
- **Detailed Reports**: Generates timestamped text reports (`results_YYYY-MM-DD_HH-MM-SS.txt`) containing all analysis data.
- **Human-Readable**: Organized with logical sections for easy reading and actionability.
- **Safe Evidence**: Includes the raw email content with sensitive addresses redacted, ready for submission as evidence.

---

## 📦 Requirements

- Python 3.6+
- Dependencies: `dnspython`, `requests`
- Software: `traceroute`,` web browser`, `Thunderbird Email Client`
- Optional: `A life long hatred of spammers and scammers`

## ⚙️ Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/SpamJam.git
   cd SpamJam

   sudo apt install traceroute
   pip install -r requirements.txt
   ```

2. **Configure API Keys**
   Open `utils/config.py` and enter your API keys in the configuration section.

   ***Configure Email Redaction***
   Add your email addresses, names, usernames, etc to the redacted section so your email, name, username does not get included in the submitted abuse reports.

   ***Configure Thunderbird Email Client***
   Setup Thunderbird to send and receive emails.  You can use Hotmail, Gmail, etc as long as the email provider supports IMAP and SMTP
