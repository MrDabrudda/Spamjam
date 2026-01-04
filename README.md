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
- Extracts sender IP from headers (`X-Originating-IP`, `Received`, etc.)
- Parses `.eml` files (RFC 2822 format)
- Redacts specified email addresses for privacy
- Extracts and **deduplicates URLs** (ignores `http`/`https`, `www` differences)

### 🌐 **Infrastructure Intelligence**
- Resolves domains to **hosting IPs** (A records)
- Performs **MX record analysis** with mail server IPs
- Retrieves **WHOIS data** for IPs and domains
- Displays **reverse DNS (PTR)** for IPs

### 🛡️ **Reputation & Threat Checks**
- **AbuseIPDB**: Abuse confidence score, report count, country
- **VirusTotal**: Malicious/suspicious detections for IPs and URLs
- **DNSBL**: Checks against Spamhaus, SORBS, and more
- **Botnet detection**: Flags IPs likely part of zombie networks

### 📧 **Abuse Contact Intelligence**
- **Hosting Abuse Contact**: From IP WHOIS
- **MX Abuse Contact**: From mail server IP WHOIS
- **Registrar Abuse Contact**: From domain WHOIS
- **Smart fallback**: Uses any valid email if no `abuse@` found
- **Deduplicated list**: All unique abuse contacts in one place

### 🌍 **Global Reporting**
- Built-in list of **global abuse reporting addresses**:
  - `reportphishing@apwg.org` (Anti-Phishing Working Group)
  - `phishing-report@us-cert.gov` (CISA)
  - `scam@netcraft.com` (Netcraft)
  - `spam@donotpay.com`, `spamreport@spamrl.com`, and more

### ⚡ **Performance & Efficiency**
- **Disk-based caching**: Persists results across runs (1-hour TTL)
  - Caches DNS, WHOIS, AbuseIPDB, VirusTotal, DNSBL lookups
  - Reduces API usage and speeds up repeated analysis
- **Batch processing**: Analyze all `.eml` files in `emails/` folder

### 📁 **Output**
- Timestamped report files (`results_YYYY-MM-DD_HH-MM-SS.txt`)
- Clean, human-readable format with logical sections
- Raw email content (with redacted private addresses)

---

## 📦 Requirements

- Python 3.6+
- Dependencies: `dnspython`, `requests`

---

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
