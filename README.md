# 🔵 Blue Guard – SIEM Toolkit for Apache/Nginx Logs (Zero Day Mitigation)

**Status:** 🚧 In Development  
**Tech Stack:** Python, Flask, SQLite, Scikit-learn, Streamlit, Slack API, LLaMA (GenAI via Together.ai)

## 💡 Overview

**Blue Guard** is a real-time Security Information and Event Management (SIEM) toolkit designed to analyze Apache/Nginx access logs and mitigate suspicious or malicious IP behavior — including zero-day anomalies.

This lightweight, modular solution uses both **rule-based detection** and **ML-based anomaly detection**, with support for **GenAI-based explanations**, **live Slack/email alerts**, and **IP blocking at firewall and application layers**.

---

## 🚀 Features

- ✅ Real-time ingestion of Apache/Nginx access logs
- ⚙️ Rule-based + ML-based IP detection
- 🧠 GenAI-powered behavioral explanations (LLaMA via Together.ai)
- 📩 Slack & email alerts for critical events
- 🔒 Simulated or real IP blocking using application-layer controls
- 🧱 SQLite for persistent log and IP behavior tracking
- 🌐 Flask REST API for modular integration

---

## 📁 Modules (Coming Soon)

- `log_ingestion/` – Real-time log parser and preprocessor  
- `detection/` – Rule-based engine and ML anomaly detector  
- `alerts/` – Slack + Email notifier logic  
- `explain/` – GenAI integration for IP context explanation  
- `firewall/` – IP blocking logic (simulated + extendable to live WAF)  
- `storage/` – SQLite DB for logs, IPs, detection history  

---

## 🔐 Use Case

- Protect servers from DDoS, brute-force, scraping, scanning attacks
- Help admins understand anomalies with GenAI insights
- Provide a lightweight SIEM for teams without expensive commercial tools

---

## 📌 Roadmap

- [x] Basic rule-based detection  
- [x] SQLite log storage  
- [x] Slack & email alert integration  
- [ ] GenAI context explanation (LLaMA)  
- [ ] ML model integration  
- [ ] REST API endpoints  
- [ ] Streamlit dashboard (optional UI layer)  
- [ ] Deployment-ready version

---

## 🧪 Demo

> Coming soon: Streamlit-powered visualization and testing UI

---

## 👩‍💻 Author

**Aashi Jain**  
📍 [LinkedIn](https://www.linkedin.com/in/aashi-jain-671a3b321) | 🌐 [GitHub](https://github.com/AashiJain971)

---

## ⚠️ Disclaimer

This project is under active development.
---

