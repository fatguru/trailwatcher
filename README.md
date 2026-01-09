# TrailWatcher 👁️

**TrailWatcher** is a unified domain monitoring tool powered by the SecurityTrails API. It allows you to audit current domain states, travel through DNS/IP history, and monitor new subdomain discoveries with real-time alerting.

![](./trail.png)

> **Author:** [@javobernardo](https://twitter.com/javobernardo)  
> **Version:** 3.0

## 🚀 Features

* **Comprehensive Audit:** Fetches current A, MX, Subdomains, etc.
* **Time Travel:** View historical IP changes (DNS History) and ownership changes.
* **Subdomain Monitoring:** Detects **new** subdomains by comparing current scans against a local history file.
* **Live Validation:** Optional integration with `httpx` to check which domains are alive.
* **Alerting:** Native support for **Telegram** and **ProjectDiscovery Notify** alerts.
* **Quota Management:** Checks your API usage limits before running.
* **Smart Persistence:** Maintains a local `subdomains_history.json` database for multi-domain tracking.

## 📋 Requirements

* Python 3.x
* A [SecurityTrails](https://securitytrails.com/) API Key [Free up to 50 API requests per Month]
* (Optional) [httpx](https://github.com/projectdiscovery/httpx) installed in your PATH.
* (Optional) [notify](https://github.com/projectdiscovery/notify) installed in your PATH.

## 📦 Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/javobernardo/trailwatcher.git
    ```

2.  Install dependencies:
    ```bash
    cd TrailWatcher
    pip install -r requirements.txt
    ```

3.  Make the script executable:
    ```bash
    chmod +x trail_watcher.py
    ```

## 🛠️ Usage

### 1. Basic Audit
Shows current details, history, and lists all subdomains.
```bash
python3 trail_watcher.py -k YOUR_API_KEY -d strike.sh
```
### 2. Advanced Scan with Export + HTTPX
Saves subdomains to a file and checks for live hosts.

```bash
python3 trail_watcher.py -k YOUR_API_KEY -d strike.sh --httpx -o results.txt
```

### 3. Continuous Monitoring (Alerts)
Ideal for CRON jobs. If new subdomains are found, an alert is sent.

Via Telegram:

```Bash
python3 trail_watcher.py -k YOUR_KEY -d strike.sh --tg-token "1234:ABC..." --tg-chat "999888"
```

Via Notify (ProjectDiscovery):

```Bash
python3 trail_watcher.py -k YOUR_KEY -d strike.sh --notify
```

### 🤖 Automation (Cron)
The tool includes a helper to generate your CRON line:

```Bash
python3 trail_watcher.py --cron-help
```

Output example:

0 8 * * * /usr/bin/python3 /path/to/trail_watcher.py -k KEY -d DOMAIN --notify

### ⚠️ Disclaimer

This tool was created for educational purposes and security research. The author is not responsible for any misuse. Ensure you have authorization to audit the target domains.

Made with ❤️ by Jav0.
