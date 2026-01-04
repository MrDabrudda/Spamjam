# spamjam.py

import sys
import os
import time
import shutil
import glob
import logging
import argparse
from utils.main import run_analysis, save_report, get_report_targets  # ← NEW IMPORT
from utils import config

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)

def main():
    parser = argparse.ArgumentParser(description="SpamJam: Email Threat Intelligence Analyzer")
    parser.add_argument(
        "email_file",
        nargs="?",
        help="Path to a single email file (.eml). If omitted, processes all .eml files in 'emails/' folder."
    )
    parser.add_argument(
        "--clear-cache",
        action="store_true",
        help="Clear the disk cache before running analysis."
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Enable AbuseIPDB reporting (requires confirmation)."
    )
    args = parser.parse_args()

    # Handle cache clearing
    if args.clear_cache:
        cache_dir = config.CACHE_DIR
        if os.path.exists(cache_dir):
            shutil.rmtree(cache_dir)
            print("✅ Cache cleared.")
        else:
            print("ℹ️  No cache found.")
        return

    # Default email directory
    email_dir = config.EMAILS_DIR

    # Determine list of files to process
    if args.email_file:
        if not os.path.isfile(args.email_file):
            print(f"❌ Error: File not found: {args.email_file}")
            sys.exit(1)
        email_files = [args.email_file]
    else:
        if not os.path.exists(email_dir):
            print(f"📁 Creating '{email_dir}' directory for .eml files.")
            os.makedirs(email_dir, exist_ok=True)
        email_files = sorted(glob.glob(os.path.join(email_dir, "*.eml")))
        if not email_files:
            print(f"⚠️  No .eml files found in '{email_dir}/'. Place email files there and try again.")
            sys.exit(1)

    # If --report is used, get report targets for confirmation
    report_targets = {}
    if args.report:
        print("\n🔍 Analyzing for reporting targets...")
        for eml_file in email_files:
            targets = get_report_targets(eml_file)
            if targets:
                report_targets[eml_file] = targets
        
        if not report_targets:
            print("ℹ️  No reporting targets found.")
            return

        # Show summary
        print("\n[+] AbuseIPDB Reporting Summary:")
        total_ips = 0
        for eml_file, targets in report_targets.items():
            print(f"\n  File: {os.path.basename(eml_file)}")
            if targets["sender_ip"]:
                print(f"    Sender IP: {targets['sender_ip']} (Spam)")
                total_ips += 1
            if targets["url_ips"]:
                for ip in sorted(targets["url_ips"]):
                    print(f"    URL IP: {ip} (Phishing)")
                    total_ips += 1
        
        print(f"\nℹ️  Total IPs to report: {total_ips}")
        confirm = input("\n⚠️  Confirm reporting to AbuseIPDB? (y/N): ").strip().lower()
        if confirm not in ("y", "yes"):
            print("❌ Reporting cancelled.")
            return
        print("✅ Proceeding with reports...\n")

    # Process each file
    for eml_file in email_files:
        print(f"\n🔍 Analyzing: {eml_file}")
        report = run_analysis(eml_file, enable_reporting=args.report)
        if report is None:
            print(f"❌ Failed to analyze: {eml_file}")
            continue
        output_file = save_report(report)
        print(f"✅ Report saved: {output_file}")
        time.sleep(1)

if __name__ == "__main__":
    main()