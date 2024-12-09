# AutoAR - Automated Attack & Reconnaissance Tool

```
 ▗▄▖ ▗▖ ▗▖▗▄▄▄▖▗▄▖  ▗▄▖ ▗▄▄▖ 
▐▌ ▐▌▐▌ ▐▌  █ ▐▌ ▐▌▐▌ ▐▌▐▌ ▐▌
▐▛▀▜▌▐▌ ▐▌  █ ▐▌ ▐▌▐▛▀▜▌▐▛▀▚▖
▐▌ ▐▌▝▚▄▞▘  █ ▝▚▄▞▘▐▌ ▐▌▐▌ ▐▌
```

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#tools">Tools</a> •
  <a href="#contributing">Contributing</a>
</p>

AutoAR is an advanced automation framework for bug bounty hunting and penetration testing. It combines powerful reconnaissance and vulnerability scanning tools into a streamlined workflow, making security testing more efficient and thorough.

## ✨ Features

- 🔍 **Comprehensive Subdomain Enumeration**
  - Multiple sources and techniques
  - Subdomain takeover checks
  - Live subdomain filtering

- 🌐 **URL Discovery & Analysis**
  - Endpoint crawling
  - Parameter discovery
  - JavaScript file analysis

- 🛡️ **Vulnerability Scanning**
  - XSS Detection
  - SQL Injection
  - Nuclei Template Scanning

- 🔔 **Real-time Notifications**
  - Discord integration
  - Detailed scan progress
  - Results reporting

## 🚀 Installation

1. Clone the repository:
```bash
git clone https://github.com/h0tak88r/AutoAR.git
cd AutoAR
```

2. Run the setup script:
```bash
chmod +x setup.sh
./setup.sh
```

3. Make the main script executable:
```bash
chmod +x autoAr.sh
```

## 🛠️ Required Tools

AutoAR depends on the following tools:

| Tool | Purpose |
|------|---------|
| subfinder | Subdomain discovery |
| httpx | HTTP toolkit |
| naabu | Port scanning |
| nuclei | Vulnerability scanner |
| [ffuf](https://github.com/cyinnove/ffuf) | Web fuzzer |
| kxss | XSS detection |
| qsreplace | Query replacement |
| paramx | Parameter discovery |
| dalfox | XSS scanner |
| urlfinder | URL discovery |
| interlace | Process management |

## 📖 Usage

### Basic Usage:
```bash
./autoAr.sh -d example.com
```

### Scan Specific Subdomain:
```bash
./autoAr.sh -s subdomain.example.com
```

### Advanced Options:
```bash
./autoAr.sh -d example.com \
  --discord-webhook "YOUR_WEBHOOK_URL" \
  --skip-port \
  --skip-fuzzing \
  -v
```

### Available Options:

| Option | Description |
|--------|-------------|
| `-d, --domain` | Target domain |
| `-s, --subdomain` | Single subdomain to scan |
| `-v, --verbose` | Enable verbose output |
| `--skip-port` | Skip port scanning |
| `--skip-fuzzing` | Skip fuzzing scans |
| `--skip-sqli` | Skip SQL injection scanning |
| `--skip-paramx` | Skip ParamX scanning |
| `--skip-dalfox` | Skip Dalfox XSS scanning |
| `--discord-webhook` | Discord webhook URL for notifications |

## 📁 Output Structure

```
results/
└── domain.com/
    ├── subs/
    │   ├── all-subs.txt
    │   ├── apis-subs.txt
    │   └── subfinder-subs.txt
    ├── urls/
    │   ├── live.txt
    │   └── all-urls.txt
    ├── vulnerabilities/
    │   ├── xss/
    │   ├── sqli/
    │   ├── ssrf/
    │   ├── ssti/
    │   ├── lfi/
    │   ├── rce/
    │   └── idor/
    ├── fuzzing/
    │   ├── ffufGet.txt
    │   └── ffufPost.txt
    └── ports/
        └── ports.txt
```

## 🔄 Workflow

1. **Initial Reconnaissance**
   - Subdomain enumeration
   - Live host detection
   - Port scanning

2. **Content Discovery**
   - URL crawling
   - Directory fuzzing
   - Parameter discovery

3. **Vulnerability Assessment**
   - Active scanning
   - Passive analysis
   - Custom vulnerability checks

4. **Reporting**
   - Organized results
   - Discord notifications
   - Detailed logs

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. Fork the repository
2. Create a new branch (`git checkout -b feature/improvement`)
3. Make your changes
4. Commit your changes (`git commit -am 'Add new feature'`)
5. Push to the branch (`git push origin feature/improvement`)
6. Create a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

Created by [h0tak88r](https://github.com/h0tak88r)

## ⚠️ Disclaimer

This tool is for educational purposes and authorized testing only. Users are responsible for obtaining proper authorization before scanning any systems.

## 🌟 Support
Buy-me-coffee: https://Ko-fi.com/h0tak88r
If you find AutoAR useful, please consider giving it a star ⭐ on GitHub!
