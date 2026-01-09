#!/usr/bin/env python3
import requests
import argparse
import json
import os
import sys
import subprocess
from datetime import datetime

# ==========================================
# CONFIGURATION & BANNER
# ==========================================
AUTHOR = "Javo Bernardo"
VERSION = "3.0"
CONTACT = "@javobernardo"
HISTORY_FILE = "subdomains_history.json"

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_banner():
    # Usamos r""" (raw string) para evitar el error de escape sequence (\)
    ascii_art = r"""
  _______        _ _  __          __   _       _               
 |__   __|      (_) | \ \        / /  | |     | |              
    | |_ __ __ _ _| |  \ \  /\  / /_ _| |_ ___| |__   ___ _ __ 
    | | '__/ _` | | |   \ \/  \/ / _` | __/ __| '_ \ / _ \ '__|
    | | | | (_| | | |    \  /\  / (_| | || (__| | | |  __/ |   
    |_|_|  \__,_|_|_|     \/  \/ \__,_|\__\___|_| |_|\___|_|   
    """
    print(f"{Colors.BLUE}{ascii_art}{Colors.ENDC}")
    print(f"   {Colors.BOLD}:: Domain Intelligence & Monitoring Tool ::{Colors.ENDC}")
    print(f"   {Colors.HEADER}Author:{Colors.ENDC} {AUTHOR} | {Colors.HEADER}Version:{Colors.ENDC} {VERSION}")
    print(f"   {Colors.HEADER}Contact:{Colors.ENDC} {CONTACT}")
    print("")

# ==========================================
# HELPER FUNCTIONS
# ==========================================

def send_telegram_alert(token, chat_id, message):
    """Sends a message via Telegram API."""
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": message, "parse_mode": "Markdown"}
    try:
        requests.post(url, json=payload, timeout=10)
    except Exception as e:
        print(f"{Colors.FAIL}[!] Telegram Error: {e}{Colors.ENDC}")

def send_notify_alert(message):
    """Pipes message to ProjectDiscovery's notify tool."""
    try:
        process = subprocess.Popen(['notify', '-silent'], stdin=subprocess.PIPE, text=True)
        process.communicate(input=message)
    except FileNotFoundError:
        print(f"{Colors.FAIL}[!] 'notify' tool not found in PATH.{Colors.ENDC}")

def check_api_quota(api_key):
    """Checks remaining SecurityTrails API credits."""
    url = "https://api.securitytrails.com/v1/account/usage"
    headers = {"APIKEY": api_key, "Accept": "application/json"}
    try:
        resp = requests.get(url, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            current = data.get('current_monthly_usage', 0)
            limit = data.get('allowed_monthly_usage', 0)
            print(f"{Colors.WARNING}[i] API Usage: {current}/{limit} requests used.{Colors.ENDC}")
        else:
            pass
    except Exception:
        pass 

def save_to_file(filename, data_list):
    """Exports data to a file."""
    try:
        with open(filename, 'w') as f:
            if filename.endswith('.json'):
                json.dump(data_list, f, indent=4)
            else:
                for line in data_list:
                    f.write(f"{line}\n")
        print(f"{Colors.GREEN}[OK] Data exported to: {filename}{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}[!] Export failed: {e}{Colors.ENDC}")

# ==========================================
# CORE LOGIC
# ==========================================

def get_data(endpoint, api_key):
    base_url = "https://api.securitytrails.com/v1"
    url = f"{base_url}{endpoint}"
    headers = {"APIKEY": api_key, "Accept": "application/json"}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"{Colors.FAIL}[!] API Error ({endpoint}): {e}{Colors.ENDC}")
        return None

def analyze_domain(domain, api_key):
    print(f"{Colors.HEADER}=== 1. CURRENT DOMAIN DETAILS ==={Colors.ENDC}")
    data = get_data(f"/domain/{domain}", api_key)
    
    if data:
        current_dns = data.get('current_dns', {})
        # A Records
        a_records = current_dns.get('a', {}).get('values', [])
        print(f"{Colors.BLUE}[+] A Records (IPs):{Colors.ENDC}")
        for ip in a_records:
            print(f"    - {ip.get('ip')} ({ip.get('ip_organization', 'Unknown Org')})")

        # MX Records
        mx_records = current_dns.get('mx', {}).get('values', [])
        print(f"{Colors.BLUE}[+] MX Records (Mail):{Colors.ENDC}")
        for mx in mx_records:
            host = mx.get('exchange') or mx.get('host') or 'Unknown'
            print(f"    - {host} (Priority: {mx.get('priority')})")
    else:
        print("    No current details found.")

def analyze_history(domain, api_key):
    print(f"\n{Colors.HEADER}=== 2. HISTORICAL DATA ==={Colors.ENDC}")
    
    # DNS History
    print(f"{Colors.BLUE}[+] A Record History:{Colors.ENDC}")
    hist_a = get_data(f"/history/{domain}/dns/a", api_key)
    if hist_a and 'records' in hist_a:
        for rec in hist_a['records']:
            ips = [v.get('ip') for v in rec.get('values', [])]
            first_seen = rec.get('first_seen', '')[:10]
            print(f"    [{first_seen}] -> {', '.join(ips)}")
    
    # WHOIS History
    print(f"{Colors.BLUE}[+] WHOIS History (Ownership):{Colors.ENDC}")
    hist_w = get_data(f"/history/{domain}/whois", api_key)
    if hist_w and 'result' in hist_w and 'items' in hist_w['result']:
        for item in hist_w['result']['items']:
            date = item.get('updatedDate', 'N/A')[:10]
            email = item.get('contactEmail', 'Hidden')
            print(f"    [{date}] Email: {email}")

def process_subdomains(domain, api_key, export_file, run_httpx, telegram_cfg, use_notify):
    print(f"\n{Colors.HEADER}=== 3. SUBDOMAIN MONITORING ==={Colors.ENDC}")
    
    # Load History
    history = {}
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, 'r') as f:
                history = json.load(f)
        except: pass
    
    old_subs = set(history.get(domain, []))
    
    # Fetch New
    print(f"{Colors.BLUE}[i] Fetching subdomains...{Colors.ENDC}")
    data = get_data(f"/domain/{domain}/subdomains", api_key)
    
    current_subs = set()
    if data and 'subdomains' in data:
        current_subs = {f"{s}.{domain}" for s in data['subdomains']}
    
    # Alphabetical Sort
    sorted_subs = sorted(list(current_subs))
    
    print(f"    Total Subdomains Found: {Colors.BOLD}{len(sorted_subs)}{Colors.ENDC}")
    
    # --- HERE IS THE CHANGE: PRINT ALL SUBDOMAINS ---
    print(f"\n{Colors.BLUE}[+] Full Subdomain List (Alphabetical):{Colors.ENDC}")
    for s in sorted_subs:
        print(f"    {s}")
    # ------------------------------------------------

    # Compare for Alerts
    new_subs = current_subs - old_subs
    if new_subs:
        msg = f"Alert: {len(new_subs)} NEW subdomains found for {domain}!"
        print(f"\n{Colors.FAIL}[!] {msg}{Colors.ENDC}")
        
        alert_body = f"target: {domain}\n"
        for s in sorted(new_subs):
            print(f"    + {s}")
            alert_body += f"{s}\n"

        # Notifications
        if telegram_cfg:
            send_telegram_alert(telegram_cfg['token'], telegram_cfg['chat_id'], f"🚨 *TrailWatcher*\n{msg}\n\n`{alert_body}`")
        if use_notify:
            send_notify_alert(alert_body)
    else:
        print(f"\n{Colors.GREEN}[OK] No new subdomains detected since last scan.{Colors.ENDC}")

    # Export
    if export_file:
        save_to_file(export_file, sorted_subs)

    # HTTPX
    if run_httpx and current_subs:
        print(f"\n{Colors.HEADER}=== 4. HTTPX LIVE CHECK ==={Colors.ENDC}")
        print(f"{Colors.BLUE}[i] Running: httpx -sc -fr -cl -silent{Colors.ENDC}")
        
        subs_str = "\n".join(sorted_subs)
        try:
            cmd = ['httpx', '-sc', '-fr', '-cl', '-silent']
            process = subprocess.Popen(cmd, stdin=subprocess.PIPE, text=True)
            process.communicate(input=subs_str)
        except FileNotFoundError:
            print(f"{Colors.FAIL}[!] Error: 'httpx' is not installed or not in PATH.{Colors.ENDC}")

    # Update History
    history[domain] = list(current_subs)
    with open(HISTORY_FILE, 'w') as f:
        json.dump(history, f, indent=4)

def print_cron_help(script_path):
    print(f"\n{Colors.HEADER}=== CRON SETUP HELPER ==={Colors.ENDC}")
    print("To run this script daily, add the following line to your crontab.")
    print("1. Open crontab:  crontab -e")
    print("2. Add this line (runs every day at 08:00 AM):")
    print(f"\n{Colors.GREEN}0 8 * * * /usr/bin/python3 {script_path} -k YOUR_API_KEY -d YOUR_DOMAIN --notify{Colors.ENDC}\n")
    sys.exit(0)

# ==========================================
# MAIN EXECUTION
# ==========================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='SecurityTrails Unified Tool')
    parser.add_argument('-k', '--key', required=True, help='SecurityTrails API Key')
    parser.add_argument('-d', '--domain', required=True, help='Target Domain (e.g. strike.sh)')
    parser.add_argument('-o', '--output', help='File to export subdomains (e.g. subs.txt or subs.json)')
    parser.add_argument('--httpx', action='store_true', help='Run httpx on found subdomains')
    parser.add_argument('--notify', action='store_true', help='Send alerts via ProjectDiscovery notify tool')
    parser.add_argument('--tg-token', help='Telegram Bot Token')
    parser.add_argument('--tg-chat', help='Telegram Chat ID')
    parser.add_argument('--cron-help', action='store_true', help='Show how to setup a cron job')

    args = parser.parse_args()
    
    print_banner()

    if args.cron_help:
        print_cron_help(os.path.abspath(__file__))

    check_api_quota(args.key)

    tg_config = None
    if args.tg_token and args.tg_chat:
        tg_config = {'token': args.tg_token, 'chat_id': args.tg_chat}

    try:
        analyze_domain(args.domain, args.key)
        analyze_history(args.domain, args.key)
        process_subdomains(
            domain=args.domain, 
            api_key=args.key, 
            export_file=args.output, 
            run_httpx=args.httpx,
            telegram_cfg=tg_config,
            use_notify=args.notify
        )
        print(f"\n{Colors.BOLD}[*] Scan completed successfully.{Colors.ENDC}")
    except KeyboardInterrupt:
        print("\n[!] Aborted by user.")
