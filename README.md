# 🕵️‍♂️ SpamJam — Email Analyzer

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
- **EML Parsing**: Full support for `.eml` files, handling attachments and multipart messages.
- **Privacy Redaction**: Automatically detects and redacts private email addresses in the output to protect victim identity.
- **URL Extraction**: Scrapes and deduplicates URLs from the email body, normalizing them (ignoring `http`/`https`, `www`) for analysis.

### 🌐 **Infrastructure Intelligence**
- **Domain Resolution**: Resolves domains to their hosting IPs (A records) to identify physical infrastructure.
- **WHOIS Lookup**: Retrieves registration data for IPs and domains to identify owners and registrars.
- **Traceroute Analysis**: Traces the network path to the suspect IP to identify intermediate hops and network location (requires `traceroute`).

### 🛡️ **Reputation & Threat Checks**
- **AbuseIPDB**: Submits spam URLs for blacklisting and blocklists
- **VirusTotal**: Submits spam URLs, leaves a comment and down votes the spam URLs
- **URLSCAN.io**: Submits spam URLs for analysis.
- **Hybrid Analysis**: Submits spam URLs for analysis.
- **Spam.org**: Submits spam emails which then get submitted to authorites.
- **CRDF**: Submits spam URLs for analysis.

### 🌍 **Global Reporting**
- **Pre-configured Reporting List**: Includes a curated list of global abuse reporting addresses such as:
  - `reportphishing@apwg.org` (Anti-Phishing Working Group)
  - `scam@netcraft.com` (Netcraft)
  - `spam@donotpay.com` (DoNotPay)
  - `spamreport@spamrl.com` (SpamURL)
  - `abuse@phishtank.com` (Phish Tank)
  - Submits the email headers and body to the Global Reporting List minus your redacted email addresses, usenames, etc.

### ⚡ **Performance & Efficiency**
- **Smart Caching**: Implements disk-based caching with a 30-minutes TTL for DNS, WHOIS, and API lookups (AbuseIPDB, VirusTotal) to minimize API quota usage and speed up re-runs.

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
   git clone https://github.com/MrDabrudda/SpamJam.git
   cd SpamJam
  
  Install the dependancies:
   sudo apt install traceroute
   sudo apt install python3-dnspython
   sudo apt install python3-requests
   ```

2. **Configure API Keys**
   Open `utils/config.py` and enter your API keys in the API Keys section.  You will need to sign up with each service for the API keys.

   ***Configure Email Redaction***
   Add your email addresses, names, usernames, etc to the Redacted Emails section of the config.py so your email, name, username does not get included in the submitted abuse reports.  Many reports will be public.

   ***Configure Thunderbird Email Client***
   Setup Thunderbird to send and receive emails.  You can use Hotmail/Outlook, Gmail, etc as long as the email provider supports IMAP and SMTP.
   Hotmail/Outlook.com will bitch and complain sometimes and prevent you from sending emails...lock your account, etc...especially when there is an abuse@microsoft.com email address in your abuse report.
   I guess Micro$oft doesn't like it when you report one of their IP addresses which is repeatedly being abused by spammers.

   **Save your Spam emails**
   Right click the spam email and select Save As/Download/Export and save the spam email as a .eml file.
   Copy/paste the .eml files into the /Spamjam/emails folder
   Open a terminal.  CD to the /Spamjam folder
   Run `python spamjam.py`
   Thunderbird will open up with two emails.  One email goes to the host of the spammers.  The second email will go to the Global Abuse emails.  Review the emails before hitting `Send`.
   The web browser will open with the Google Safe Browsing link and the spam URL filled in.  You can add `Additional details` such as `Phishing scam URL from UCE spam email` and click submit.  Rinse and report for the other Google Safe Browsing tabs in the web browser to report the spam URLs to Google
   Wait until the script finishes
   You can check the /Spamjam/output folder for the final report which has already been reported via email
