# 🛡️ SOC Sentinel

*A Mini Security Information and Event Management (SIEM) Platform*

A lightweight **Security Information and Event Management (SIEM)** application built using **Python** and **Flask** to analyse security log files, detect suspicious activities, extract Indicators of Compromise (IOCs), map attacks to the **MITRE ATT&CK** framework, perform IP geolocation, and generate professional PDF & CSV security reports through an interactive dashboard.

---

## ✨ Features

- 📂 Upload and analyse security log files
- 🚨 Detect suspicious activities and security alerts
- 🎯 MITRE ATT&CK technique mapping
- 🔍 IOC extraction (IP addresses & usernames)
- 🌍 IP geolocation lookup
- 📊 Interactive security dashboard with charts and metrics
- 📑 Generate PDF & CSV security reports
- 💾 Store analysed data using SQLite

---

## 🛠️ Tech Stack

| Category | Technology |
|-----------|------------|
| Backend | Python, Flask |
| Frontend | HTML, CSS, JavaScript |
| Database | SQLite |
| Charts | Chart.js |
| Reporting | ReportLab, CSV |
| Security | MITRE ATT&CK |

---

## 📸 Screenshots

### 🏠 Home

![Home](screenshots/home.png)

### 📊 Dashboard Overview

![Dashboard Overview](screenshots/dashboard-overview.png)

### 📈 Dashboard Analysis

![Dashboard Analysis](screenshots/dashboard-analysis.png)

### 📂 Upload Logs

![Upload Logs](screenshots/upload-logs.png)

### 🌍 IP Geolocation

![IP Geolocation](screenshots/ip-geolocation.png)

### 📑 Reports

![Reports](screenshots/reports.png)

### 📄 Generated Security Report

![Report Preview](screenshots/report-preview.png)

---

## 📁 Project Structure

```text
mini-siem/
│
├── detection/
├── geo/
├── ioc/
├── parser/
├── reports/
├── sample_logs/
├── screenshots/
├── search/
├── static/
├── templates/
├── uploads/
├── app.py
├── requirements.txt
├── README.md
└── .gitignore
```

---

## 🚀 Installation

```bash
git clone https://github.com/tanviagrawalnew-bot/mini-siem.git

cd mini-siem

python -m venv venv

# Windows
venv\Scripts\activate

pip install -r requirements.txt

python app.py
```

Open your browser:

```text
http://127.0.0.1:5000
```

---

## 📖 Workflow

```text
Upload Log
     │
     ▼
Log Parsing
     │
     ▼
Threat Detection
     │
     ├── IOC Extraction
     ├── MITRE ATT&CK Mapping
     ├── IP Geolocation
     ▼
Dashboard
     │
     ▼
PDF & CSV Reports
```

---

## 🚀 Future Improvements

- Real-time log monitoring
- Threat Intelligence API integration
- Email alerts
- Docker support

---

## 👩‍💻 Authors

**Tanvi Agrawal**  
B.Tech CSE Student

**Kajal Singh**  
B.Tech CSE Student

---

## 📄 License

This project is developed for educational and learning purposes.