# utils/main.py

import os
import re
import time
import logging
import webbrowser
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple
from urllib.parse import quote, urlparse

from .config import REDACT_EMAILS, GLOBAL_ABUSE_EMAILS, ABUSEIPDB_API_KEY
from .utils import redact_email_content, is_valid_ipv4, is_url_excluded, perform_traceroute, open_thunderbird
from .email_processor import parse_email_file, get_sender_ip_from_email
from .dns_utils import reverse_dns_lookup, check_dnsbl, get_mx_records, resolve_domain_to_ipv4
from .whois import get_whois_info, is_brazilian_ip
from .abuseipdb import check_abuseipdb, report_to_abuseipdb
from .crdf import report_to_crdf
from .urlscanio import report_to_urlscan
from .hybrid_analysis import report_to_hybrid_analysis
from .spam_org import report_to_spam_org
from .virustotal import report_to_virustotal
from .urls import extract_urls_from_html
from .cache import get as cache_get, set as cache_set

logger = logging.getLogger(__name__)


def _extract_valid_emails(emails_input):
    if not emails_input:
        return []
    if isinstance(emails_input, str):
        emails = re.split(r'[,\s;]+', emails_input)
    else:
        emails = list(emails_input)
    valid = []
    for e in emails:
        if e and "@" in e:
            e_clean = e.strip().strip("'\"")
            if e_clean and "@" in e_clean and "." in e_clean.split("@")[-1]:
                valid.append(e_clean.lower())
    return list(set(valid))


def get_report_targets(email_path: str) -> Dict[str, Any]:
    raw, headers, html_body, _ = parse_email_file(email_path)
    if raw is None:
        return {"sender_ip": None, "url_ips": set()}

    targets = {"sender_ip": None, "url_ips": set()}
    sender_ip = get_sender_ip_from_email(headers) if headers else None
    if sender_ip and is_valid_ipv4(sender_ip):
        targets["sender_ip"] = sender_ip

    if html_body:
        urls = extract_urls_from_html(html_body)
        for url in urls:
            if is_url_excluded(url):
                continue  # ← Skip entirely — no output
            try:
                domain_match = re.match(r"https?://([^/]+)", url, re.IGNORECASE)
                if domain_match:
                    domain = domain_match.group(1).lower().split(":")[0]
                    ips = resolve_domain_to_ipv4(domain)
                    if ips:
                        for ip in ips:
                            targets["url_ips"].add(ip)
            except Exception:
                continue
    return targets


def _get_abuse_emails_from_whois(ip_whois: Optional[Dict], is_brazilian: bool = False) -> List[str]:
    if not ip_whois:
        return []
    emails = ip_whois.get("emails")
    if not emails:
        return []
    valid_emails = _extract_valid_emails(emails)
    if not valid_emails:
        return []
    keywords = ["abuse", "noc"]
    if is_brazilian:
        keywords.append("tech")
    abuse_emails = [e for e in valid_emails if any(k in e.lower() for k in keywords)]
    return abuse_emails if abuse_emails else valid_emails


def _get_ip_reputation(ip: str) -> Tuple[Optional[List[str]], Optional[Dict[str, Any]]]:
    """Helper to check DNSBL and AbuseIPDB with caching."""
    dnsbl_key = f"dnsbl:{ip}"
    dnsbl_hits = cache_get(dnsbl_key)
    if dnsbl_hits is None:
        dnsbl_hits = check_dnsbl(ip)
        cache_set(dnsbl_key, dnsbl_hits)

    abuse_key = f"abuseipdb:{ip}"
    abuseData = cache_get(abuse_key)
    if abuseData is None:
        abuseData = check_abuseipdb(ip)
        cache_set(abuse_key, abuseData)
    return dnsbl_hits, abuseData


def _get_abuse_contact_info(ip: str) -> Tuple[List[str], str, Optional[Dict[str, Any]]]:
    """Helper to get Whois info and extract abuse contacts with caching and fallbacks."""
    whois_key = f"whois:{ip}"
    ip_whois = cache_get(whois_key)
    if ip_whois is None:
        ip_whois = get_whois_info(ip)
        cache_set(whois_key, ip_whois)

    is_br = is_brazilian_ip(ip)
    found_emails = _get_abuse_emails_from_whois(ip_whois, is_brazilian=is_br)

    if not found_emails and is_br:
        found_emails = ["cert@cert.br", "mail-abuse@cert.br", "soc@cert.br"]

    abuse_contact = ", ".join(found_emails) if found_emails else "Not found"
    return found_emails, abuse_contact, ip_whois


def run_analysis(email_path: str, enable_reporting: bool = False) -> Optional[str]:
    start_time = time.time()
    raw, headers, html_body, original_subject = parse_email_file(email_path)
    if raw is None:
        return None

    redacted_raw = redact_email_content(raw, REDACT_EMAILS)
    all_abuse_emails = set()
    reported_ips = set()

    sender_ip = get_sender_ip_from_email(headers) if headers else None
    if sender_ip and not is_valid_ipv4(sender_ip):
        sender_ip = None

    report_lines = []
    report_header = "Spammers utilizing your services to violate 15 U.S.C. Chapter 101 — §§ 7701-7713-(CAN-SPAM Act), 18 U.S.C. § 1030-(COMPUTER FRAUD & ABUSE ACT), 18 U.S.C. § 1343-(WIRE FRAUD)"
    report_lines.append(f"{report_header}")

    email_date = "Unknown"
    if headers:
        date_match = re.search(r"^Date:\s*(.+)$", headers, re.MULTILINE | re.IGNORECASE)
        if date_match:
            email_date = date_match.group(1).strip()
    report_lines.append(f"\nEmail Date: {email_date}")
    report_lines.append(f"Email file: {email_path}")
    report_lines.append(f"Processing time: {time.time() - start_time:.2f}s")
    report_lines.append("-" * 60)

    if sender_ip:
        report_lines.append(f"\n[+] Sender IP: {sender_ip}")

        dnsbl_hits, abuseData = _get_ip_reputation(sender_ip)

        is_suspicious = False
        if dnsbl_hits:
            is_suspicious = True
        elif abuseData and abuseData.get('abuse_score', 0) >= 25:
            is_suspicious = True

        if is_suspicious:
            report_lines.append("(Compromised/BOTNET/Email server used to send Unsolicited Email)")
            report_lines.append("Violation of:")
            report_lines.append("15 U.S.C. Chapter 101 — §§ 7701-7713 (CAN-SPAM Act)")
            report_lines.append("18 U.S.C. § 1030 (Computer Fraud and Abuse Act)")
            report_lines.append("18 U.S.C. § 1343 (Wire Fraud)")
            report_lines.append("")

        rdns_key = f"rdns:{sender_ip}"
        rdns = cache_get(rdns_key)
        if rdns is None:
            rdns = reverse_dns_lookup(sender_ip)
            cache_set(rdns_key, rdns)
        if rdns:
            report_lines.append(f"    Reverse DNS: {rdns}")

        if dnsbl_hits:
            report_lines.append(f"    DNSBL Listed: {', '.join(dnsbl_hits)}")
        else:
            report_lines.append("    DNSBL: Not listed")

        if abuseData:
            report_lines.append(f"    AbuseIPDB Score: {abuseData['abuse_score']}%")
            report_lines.append(f"    Total Reports: {abuseData['total_reports']}")
        else:
            report_lines.append("    AbuseIPDB: Skipped")

        found_emails, abuse_contact, ip_whois = _get_abuse_contact_info(sender_ip)
        original_ip_has_contact = bool(found_emails)

        # If no contact found, try to find upstream provider via traceroute
        if not found_emails:
            hops = perform_traceroute(sender_ip)
            # Check hops in reverse (closest to target first) to find immediate upstream
            for hop_ip in reversed(hops):
                hop_emails, _, hop_whois = _get_abuse_contact_info(hop_ip)
                if hop_emails:
                    found_emails = hop_emails
                    abuse_contact = f"{', '.join(found_emails)} (via upstream {hop_ip})"
                    break

        if found_emails:
            if abuse_contact == "Not found":
                abuse_contact = ", ".join(found_emails)
            all_abuse_emails.update(found_emails)

        report_lines.append(f"    Abuse Contact: {abuse_contact}")
        if not found_emails:
            report_lines.append("    [!] WARNING: Not having an abuse contact email listed violates the ICANN agreement your company agreed to.")
        elif not original_ip_has_contact:
            report_lines.append("    [!] Note: Direct abuse contact not found. Using upstream provider contact.")

    else:
        report_lines.append("\n[!] No sender IP found.")

    domains = set()
    if html_body:
        domains.update(re.findall(r"https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", html_body))
    
    valid_domains = set()
    for d in domains:
        d = d.strip().lower()
        if d and "." in d and not d.startswith(".") and not d.endswith("."):
            if not is_url_excluded(f"http://{d}"):
                valid_domains.add(d)

    if valid_domains:
        report_lines.append(f"\n[+] Analyzed domains ({len(valid_domains)}):")

        for domain in sorted(valid_domains):
            dns_key = f"dns_a:{domain}"
            ips = cache_get(dns_key)
            if ips is None:
                ips = resolve_domain_to_ipv4(domain)
                cache_set(dns_key, ips)

            if ips:
                if len(ips) == 1:
                    report_lines.append(f"  Domain: {domain} → {ips[0]}")
                else:
                    report_lines.append(f"  Domain: {domain} → {', '.join(ips)}")
                
                first_ip = ips[0]
                found_emails, hosting_abuse, ip_whois = _get_abuse_contact_info(first_ip)

                if found_emails:
                    all_abuse_emails.update(found_emails)
                report_lines.append(f"    Hosting Abuse Contact: {hosting_abuse}")
                if not found_emails:
                    report_lines.append("    [!] WARNING: Not having an abuse contact email listed violates the ICANN agreement your company agreed to.")
            else:
                report_lines.append(f"  Domain: {domain} → [IP resolution failed]")
                report_lines.append("    Hosting Abuse Contact: Not found")
            
            report_lines.append("")

            mx_key = f"mx:{domain}"
            mx_records = cache_get(mx_key)
            if mx_records is None:
                mx_records = get_mx_records(domain)
                cache_set(mx_key, mx_records)
            if mx_records:
                for ip_or_host, priority, mx_host in mx_records:
                    if is_url_excluded(f"http://{mx_host}"):
                        continue

                    if ip_or_host == mx_host:
                        report_lines.append(f"    MX: {mx_host} (prio {priority})")
                    else:
                        report_lines.append(f"    MX: {ip_or_host} (prio {priority}, from {mx_host})")

                        whois_key = f"whois:{ip_or_host}"
                        mx_ip_whois = cache_get(whois_key)
                        if mx_ip_whois is None:
                            mx_ip_whois = get_whois_info(ip_or_host)
                            cache_set(whois_key, mx_ip_whois)

                        mx_abuse = "Not found"
                        found_emails = []

                        if mx_ip_whois and mx_ip_whois.get("emails"):
                            emails = mx_ip_whois.get("emails", [])
                            if isinstance(emails, str):
                                emails = [emails]
                            found_emails = _extract_valid_emails(emails)

                        if not found_emails and mx_ip_whois:
                            raw = mx_ip_whois.get('raw', '')
                            if raw:
                                abuse_matches = re.findall(r'\b((?:abuse|noc)@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b', raw, re.IGNORECASE)
                                if abuse_matches:
                                    found_emails = list(set(abuse_matches))

                        is_br_mx = is_brazilian_ip(ip_or_host)
                        if not found_emails and is_br_mx:
                            found_emails = ["cert@cert.br", "mail-abuse@cert.br", "soc@cert.br"]

                        if found_emails:
                            keywords = ["abuse", "noc"]
                            if is_br_mx:
                                keywords.append("tech")
                            abuse_emails = [e for e in found_emails if any(k in e.lower() for k in keywords)]
                            selected = abuse_emails if abuse_emails else found_emails
                            mx_abuse = ", ".join(selected)
                            all_abuse_emails.update(selected)

                        report_lines.append(f"    MX Abuse Contact: {mx_abuse}")
                        if not found_emails:
                            report_lines.append("    [!] WARNING: Not having an abuse contact email listed violates the ICANN agreement your company agreed to.")
            else:
                report_lines.append("    MX: None found")
            
            report_lines.append("")

            whois_dom_key = f"whois_domain:{domain}"
            d_whois = cache_get(whois_dom_key)
            if d_whois is None:
                d_whois = get_whois_info(domain)
                cache_set(whois_dom_key, d_whois)
            if d_whois:
                registrar = d_whois.get("registrar")
                if registrar:
                    report_lines.append(f"    Registrar: {registrar}")
                else:
                    report_lines.append("    Registrar: Not found")
                
                registrar_abuse = "Not found"
                if d_whois.get("emails"):
                    emails = d_whois["emails"]
                    valid_emails = _extract_valid_emails(emails)
                    if valid_emails:
                        abuse_emails = [e for e in valid_emails if "abuse" in e.lower() or "noc" in e.lower()]
                        selected = abuse_emails if abuse_emails else valid_emails
                        registrar_abuse = ", ".join(selected)
                        all_abuse_emails.update(selected)
                report_lines.append(f"    Registrar Abuse Contact: {registrar_abuse}")
            else:
                report_lines.append("    Registrar: Not found")
                report_lines.append("    Registrar Abuse Contact: Not found")
            
            report_lines.append("")

    url_hosting_ips = set()
    valid_urls_found = []
    if html_body:
        urls = extract_urls_from_html(html_body)
        if urls:
            report_lines.append(f"\n[+] URLs found ({len(urls)}):")

            for url in urls:
                if is_url_excluded(url):
                    continue

                valid_urls_found.append(url)
                report_lines.append(f"    {url}")
                try:
                    domain_match = re.match(r"https?://([^/]+)", url, re.IGNORECASE)
                    if domain_match:
                        domain = domain_match.group(1).lower().split(":")[0]
                        dns_key = f"dns_a:{domain}"
                        ips = cache_get(dns_key)
                        if ips is None:
                            ips = resolve_domain_to_ipv4(domain)
                            cache_set(dns_key, ips)
                        if ips:
                            if len(ips) == 1:
                                report_lines.append(f"    → IP: {ips[0]}")
                            else:
                                report_lines.append(f"    → IPs: {', '.join(ips)}")
                            
                            for ip in ips:
                                url_hosting_ips.add(ip)
                            
                            first_ip = ips[0]
                            
                            dnsbl_hits, abuseData_url = _get_ip_reputation(first_ip)
                            if dnsbl_hits:
                                report_lines.append(f"    → DNSBL Listed: {', '.join(dnsbl_hits)}")
                            else:
                                report_lines.append("    → DNSBL: Not listed")

                            if abuseData_url:
                                report_lines.append(f"    → AbuseIPDB Total Reports: {abuseData_url['total_reports']}")
                            else:
                                report_lines.append("    → AbuseIPDB: Skipped")

                            found_emails, abuse_contact_url, ip_whois = _get_abuse_contact_info(first_ip)
                            if found_emails:
                                all_abuse_emails.update(found_emails)
                            report_lines.append(f"    → Abuse Contact: {abuse_contact_url}")
                            if not found_emails:
                                report_lines.append("    → [!] WARNING: Not having abuse contact listed violates the ICANN agreement your company agreed to.")
                        else:
                            report_lines.append("    → IP resolution failed")
                    else:
                        report_lines.append("    → Invalid URL format")
                except Exception as e:
                    logger.debug("Error analyzing URL %s: %s", url, e)
                    report_lines.append("    → Analysis failed")

    if enable_reporting and ABUSEIPDB_API_KEY:
        report_lines.append("\n[+] AbuseIPDB Reporting:")

        if sender_ip and sender_ip not in reported_ips:
            success = report_to_abuseipdb(
                ip=sender_ip,
                categories=[3, 7, 11, 15, 17, 19, 20],
                comment=f"Report generated by Spamjam Email Analyzer:\nPhishing SCAM URL(s) found in UCE spam email: {os.path.basename(email_path)}"
            )
            status = "✅ Success" if success else "❌ Failed"
            report_lines.append(f"    Sender IP {sender_ip}: {status}")
            reported_ips.add(sender_ip)

        urls_to_report = []
        if html_body:
            all_urls = extract_urls_from_html(html_body)
            for url in all_urls:
                if not is_url_excluded(url):
                    urls_to_report.append(url)

        report_ips = set()
        for url in urls_to_report:
            try:
                domain_match = re.match(r"https?://([^/]+)", url, re.IGNORECASE)
                if domain_match:
                    domain = domain_match.group(1).lower().split(":")[0]
                    ips = resolve_domain_to_ipv4(domain)
                    if ips:
                        report_ips.update(ips)
            except Exception:
                continue

        formatted_urls = "\n".join(urls_to_report)
        for ip in report_ips:
            if ip not in reported_ips:
                success = report_to_abuseipdb(
                    ip=ip,
                    categories=[3, 7, 11, 15, 17, 19, 20],
                    comment=f"Report generated by Spamjam Email Analyzer:\nPhishing SCAM URL(s) found in UCE spam email: {formatted_urls}"
                )
                status = "✅ Success" if success else "❌ Failed"
                report_lines.append(f"    URL Hosting IP {ip}: {status}")
                reported_ips.add(ip)

    elif enable_reporting and not ABUSEIPDB_API_KEY:
        report_lines.append("\n[!] AbuseIPDB reporting enabled but no API key configured.")

    if enable_reporting:
        # Spam.org Reporting
        spam_org_configured = False
        try:
            from .config import SPAM_ORG_API_KEY
            if SPAM_ORG_API_KEY and SPAM_ORG_API_KEY.strip():
                spam_org_configured = True
        except (ImportError, AttributeError):
            pass

        if spam_org_configured:
            report_lines.append("\n[+] Spam.org Reporting:")
            report_to_spam_org(raw)

        # CRDF Labs URL Reporting
        crdf_configured = False
        try:
            from .config import CRDF_API_KEY
            if CRDF_API_KEY and CRDF_API_KEY.strip():
                crdf_configured = True
        except (ImportError, AttributeError):
            pass

        if crdf_configured:
            report_lines.append("\n[+] CRDF Labs URL Reporting:")
            urls_to_report = []
            if html_body:
                all_urls = extract_urls_from_html(html_body)
                for url in all_urls:
                    if not is_url_excluded(url):
                        urls_to_report.append(url)
            
            if urls_to_report:
                reported_urls = set()
                for url in urls_to_report:
                    if url in reported_urls:
                        continue
                    success = report_to_crdf(url)
                    status = "✅ Success" if success else "❌ Failed"
                    report_lines.append(f"    URL {url}: {status}")
                    reported_urls.add(url)
            else:
                report_lines.append("    No URLs found to report.")

        # urlscan.io URL Reporting
        urlscan_configured = False
        try:
            from .config import URLSCAN_API_KEY
            if URLSCAN_API_KEY and URLSCAN_API_KEY.strip():
                urlscan_configured = True
        except (ImportError, AttributeError):
            pass

        if urlscan_configured:
            report_lines.append("\n[+] urlscan.io URL Reporting:")
            urls_to_report = []
            if html_body:
                all_urls = extract_urls_from_html(html_body)
                for url in all_urls:
                    if not is_url_excluded(url):
                        urls_to_report.append(url)

            if urls_to_report:
                reported_urls = set()
                for url in urls_to_report:
                    if url in reported_urls:
                        continue
                    success = report_to_urlscan(url)
                    status = "✅ Success" if success else "❌ Failed"
                    report_lines.append(f"    URL {url}: {status}")
                    reported_urls.add(url)
            else:
                report_lines.append("    No URLs found to report.")

        # VirusTotal URL Reporting
        vt_configured = False
        try:
            from .config import VIRUSTOTAL_API_KEY
            if VIRUSTOTAL_API_KEY and VIRUSTOTAL_API_KEY.strip():
                vt_configured = True
        except (ImportError, AttributeError):
            pass

        if vt_configured:
            report_lines.append("\n[+] VirusTotal URL Reporting:")
            urls_to_report = []
            if html_body:
                all_urls = extract_urls_from_html(html_body)
                for url in all_urls:
                    if not is_url_excluded(url):
                        urls_to_report.append(url)

            if urls_to_report:
                reported_items = set()
                domain_map = {}
                individual_comment = "Report generated by Spamjam Email Analyzer:\nPhishing SCAM URL(s) found in UCE spam email."

                for url in urls_to_report:
                    # Report Full URL
                    if url not in reported_items:
                        success = report_to_virustotal(url, comment=individual_comment)
                        status = "✅ Success" if success else "❌ Failed"
                        report_lines.append(f"    URL {url}: {status}")
                        reported_items.add(url)

                    # Collect for Base URL Report
                    try:
                        parsed = urlparse(url)
                        base_url = parsed.netloc
                        if base_url:
                            if base_url not in domain_map:
                                domain_map[base_url] = []
                            if url not in domain_map[base_url]:
                                domain_map[base_url].append(url)
                    except Exception:
                        pass

                # Report Base URLs with aggregated list
                for base_url, children in domain_map.items():
                    msg = "Phishing SCAM URL(s) found in UCE spam email\n\n"
                    msg += f"{base_url}\n"
                    for child in children:
                        msg += f"{child}\n"
                    
                    success = report_to_virustotal(base_url, comment=msg)
                    status = "✅ Success" if success else "❌ Failed"
                    report_lines.append(f"    Base URL {base_url}: {status}")
                    reported_items.add(base_url)
            else:
                report_lines.append("    No URLs found to report.")

        # Hybrid Analysis URL Reporting
        hybrid_configured = False
        try:
            from .config import HYBRID_ANALYSIS_API_KEY
            if HYBRID_ANALYSIS_API_KEY and HYBRID_ANALYSIS_API_KEY.strip():
                hybrid_configured = True
        except (ImportError, AttributeError):
            pass

        if hybrid_configured:
            report_lines.append("\n[+] Hybrid Analysis URL Reporting:")
            urls_to_report = []
            if html_body:
                all_urls = extract_urls_from_html(html_body)
                for url in all_urls:
                    if not is_url_excluded(url):
                        urls_to_report.append(url)

            if urls_to_report:
                reported_urls = set()
                for url in urls_to_report:
                    if url in reported_urls:
                        continue
                    success = report_to_hybrid_analysis(url)
                    status = "✅ Success" if success else "❌ Failed"
                    report_lines.append(f"    URL {url}: {status}")
                    reported_urls.add(url)
            else:
                report_lines.append("    No URLs found to report.")

        # IPQS URL Reporting
        ipqs_configured = False
        try:
            from .config import IPQS_API_KEY
            if IPQS_API_KEY and IPQS_API_KEY.strip():
                ipqs_configured = True
        except (ImportError, AttributeError):
            pass

        if ipqs_configured:
            from .ipqs import report_to_ipqs
            report_lines.append("\n[+] IPQS URL Reporting:")
            urls_to_report = []
            if html_body:
                all_urls = extract_urls_from_html(html_body)
                for url in all_urls:
                    if not is_url_excluded(url):
                        urls_to_report.append(url)

            if urls_to_report:
                reported_urls = set()
                for url in urls_to_report:
                    if url in reported_urls:
                        continue
                    success = report_to_ipqs(url)
                    status = "✅ Success" if success else "❌ Failed"
                    report_lines.append(f"    URL {url}: {status}")
                    reported_urls.add(url)
            else:
                report_lines.append("    No URLs found to report.")

    if all_abuse_emails:
        sorted_emails = sorted(all_abuse_emails)
        report_lines.append(f"\n[+] Deduplicated Abuse & Registrar Contacts ({len(sorted_emails)}):")
        for email in sorted_emails:
            report_lines.append(f"    {email}")
    else:
        report_lines.append("\n[+] Deduplicated Abuse & Registrar Contacts: None found")

    if GLOBAL_ABUSE_EMAILS:
        for email in GLOBAL_ABUSE_EMAILS:
            report_lines.append(f"    {email}")

    report_lines.append("\nICANN Agreement-Section 3.18 Registrar's Abuse Contact and Duty to Investigate Reports of Abuse.")
    report_lines.append("https://itp.cdn.icann.org/en/files/accredited-registrars/registrar-accreditation-agreement-21jan24-en.htm")
    report_lines.append("\nList of Accredited Registrars")
    report_lines.append("https://www.icann.org/en/contracted-parties/accredited-registrars/list-of-accredited-registrars")

    report_lines.append("\n" + "=" * 60)
    report_lines.append("\n[Raw Email Content]")
    report_lines.append(redacted_raw)

    final_report = "\n".join(report_lines)
    redacted_report = redact_email_content(final_report, REDACT_EMAILS)

    # Open Thunderbird with the report
    if enable_reporting:
        if all_abuse_emails:
            open_thunderbird(list(all_abuse_emails), f"{report_header}", redacted_report)
        if GLOBAL_ABUSE_EMAILS:
            email_subject = original_subject if original_subject else "Spam Report"
            email_subject = f"FW: {email_subject}".replace('\n', ' ').replace('\r', '').strip()
            open_thunderbird(GLOBAL_ABUSE_EMAILS, email_subject, redacted_raw)

    if valid_urls_found:
        save_google_safebrowsing_links(valid_urls_found)

    return redacted_report


def save_report(report: str) -> str:
    os.makedirs("output", exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"output/results_{timestamp}.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(report)
    logger.info("Report saved to %s", filename)
    return filename


def save_google_safebrowsing_links(urls: List[str]) -> None:
    """
    Append found URLs to a text file with Google Safe Browsing submission links.
    """
    if not urls:
        return

    os.makedirs("output", exist_ok=True)
    filename = os.path.join("output", "google_safebrowsing_links.txt")
    
    with open(filename, "a", encoding="utf-8") as f:
        for url in urls:
            safe_url = quote(url, safe='')
            submit_link = f"https://safebrowsing.google.com/safebrowsing/report_phish/?url={safe_url}"
            f.write(f"{submit_link}\n")
            webbrowser.open_new_tab(submit_link)