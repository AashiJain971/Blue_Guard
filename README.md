
# 🔵 Blue Guard – Lightweight SIEM for Apache/Nginx Logs

*Real-time Threat Detection with Hybrid Rule-Based + ML Engine*

**Tech Stack:**
Python, Flask, SQLite, Streamlit, Scikit-learn (Isolation Forest), Slack API, Email (SMTP), REST APIs
*(GenAI via LLaMA / Together.ai – tested, currently optional to reduce token usage)*

---

## 💡 Overview

**Blue Guard** is a lightweight, real-time **Security Information and Event Management (SIEM)** toolkit designed specifically for **Apache and Nginx web servers**. It monitors access logs in near real time and detects suspicious or malicious IP behavior with an average detection latency of **~180–200 ms**.

The system is built to bridge the gap between basic log analysis tools and heavyweight commercial SIEMs by offering a solution that is **fast, interpretable, easy to deploy, and cost-effective** for small teams and organizations.

---

## ⚙️ Core Capabilities

Blue Guard uses a **hybrid detection pipeline** that combines adaptive rule-based analysis with machine-learning-based anomaly detection.

### 🔍 Rule-Based Detection

* Uses a **21-day rolling historical baseline**, segmented by local hour
* Dynamically computes thresholds for:

  * Requests per minute
  * Error rate
  * Average request size
* Tiered severity scoring with contextual boosts
* Designed to reduce false positives while remaining sensitive to attacks

### 🤖 Machine Learning Detection

* Integrates **Isolation Forest** for anomaly detection
* Profiles normal IP behavior across multiple traffic features
* Detects stealthy and previously unseen attack patterns
* Lightweight and fast, suitable for real-time use

---

## 🚀 Features

* Real-time ingestion of Apache/Nginx access logs
* Hybrid detection engine (rule-based + ML)
* Detection latency of approximately **180–200 ms**
* Persistent storage using **SQLite** for logs and behavioral metadata
* **Instant Slack and email alerts** for suspicious activity
* Interactive **Streamlit dashboard** with:

  * Live detections
  * Traffic trends
  * Geo-based insights
  * Downloadable HTML/CSV reports
* Modular **Flask REST APIs** for integration with external systems

---

## 🧠 GenAI-Assisted Analysis (Optional to reduce token usage )

Blue Guard includes an experimental **GenAI-based explanation module** using **LLaMA via Together.ai**, which generates human-readable explanations for flagged IP behavior.
This feature has been **tested and validated**, but is currently **disabled by default** in the codebase to conserve API tokens.

---

## 🔐 Use Cases

* Detect and respond to:

  * DDoS bursts
  * Brute-force login attempts
  * Scanning and scraping activity
  * Abnormal traffic spikes
* Help administrators understand *why* an IP was flagged
* Provide a practical SIEM solution for teams without access to expensive commercial platforms

---

## 📊 Performance Highlights

* **Detection latency:** ~180–200 ms
* **Dashboard refresh rate:** ~1 second
* **High recall and strong F1 score** observed during testing on simulated attack traffic
* Designed for continuous operation with minimal overhead

---

## 🛣️ Roadmap (Future Work)

The following features are **planned but not yet fully implemented**:

* SaaS-style multi-tenant deployment
* Zero-time mitigation (first-packet blocking using NFQUEUE / eBPF / XDP)
* Self-tuning detection thresholds
* Privacy-preserving analytics
* Full GenAI integration for automated incident summaries

---

👩‍💻 Author

Aashi Jain  
Connect with me on **[LinkedIn](https://www.linkedin.com/in/aashi-jain-671a3b321)**


---

> **Note:** Blue Guard is under continuous development, with a focus on performance, interpretability, and real-world usability.

