# VulnHawk 🛡️  
**Python-Based Modular Vulnerability Scanner (Purple Team Oriented)**

VulnHawk is a modular vulnerability scanning tool built with a **Purple Team mindset**, focusing on **safe detection, clean architecture, and professional reporting** rather than exploitation.

The project is designed to resemble how **internal security tools** are built and used in real organizations.

---

## 🚀 Features

- 🔍 **Multithreaded TCP Port Scanning**
- 🧠 **Service & Banner Detection**
- 🌐 **HTTP Security Header Misconfiguration Detection**
- 📂 **Sensitive File & Directory Discovery**
- 💉 **Safe SQL Injection & Reflected XSS Detection**
- 🔐 **Authenticated Scanning Support (via environment variables)**
- 🔌 **Plugin-Based Architecture**
- 📊 **JSON & Professional HTML Reports**
- 🟣 **Severity Scoring (CVSS-style inspired)**

---

## 🧱 Project Structure

```text
vuln_scanner/
│
├── core/           # Core scanning logic
├── web/            # Web vulnerability checks
├── plugins/        # Plugin system
├── reports/        # JSON & HTML report generation
├── utils/          # Helper utilities
├── main.py         # CLI entry point
└── requirements.txt
