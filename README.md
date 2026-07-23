Mini SIEM (Security Information and Event Management)

A lightweight Security Information and Event Management (SIEM) system built using PYTHON and FLASK for analyzing security log files.

The application collects and processes log data, detects suspicious activities, identifies Indicators of Compromise (IOCs), performs IP geolocation, assigns severity levels and threat scores, maps events to the MITRE ATT&CK framework, and generates detailed security reports through an interactive web dashboard.

This project was developed to demonstrate the core concepts of Security Operations Center (SOC) monitoring and log analysis in a simplified and beginner-friendly environment.

#Key Features

📂 Log Analysis
- Upload log files for analysis
- Parse structured log data
- Support for sample log datasets

🚨 Threat Detection
- Detect suspicious security events
- Identify Indicators of Compromise (IOCs)
- Assign event severity
- Calculate threat scores

🌍 IP Intelligence
- IP Geolocation lookup
- Display location information for suspicious IP addresses

🎯 MITRE ATT&CK Mapping
- Map detected activities to relevant MITRE ATT&CK techniques
- Improve understanding of attacker behavior

📊 Dashboard
- Interactive security dashboard
- View detected events
- Search analyzed logs
- Review threat information

📑 Reporting
- Generate professional PDF reports
- Export analysis as CSV
- Store reports for future reference

💾 Data Management
- SQLite database integration
- Store analyzed security events
- Maintain uploaded log records

🛠️ Technology Stack

| Category | Technologies |
|----------|--------------|
| Backend | Python, Flask |
| Frontend | HTML, CSS, JavaScript |
| Database | SQLite |
| Reporting | PDF, CSV |
| Security Framework | MITRE ATT&CK |


# 📂 Project Structure
mini-siem/
├── app.py                 # Main Flask application
├── database/              # Database and storage
├── detection/             # Threat detection engine
├── geo/                   # IP geolocation
├── ioc/                   # IOC detection
├── parser/                # Log parsing modules
├── reports/               # PDF & CSV report generation
├── sample_logs/           # Sample log files
├── search/                # Search functionality
├── static/                # CSS, JavaScript and assets
├── templates/             # HTML templates
├── uploads/               # Uploaded log files
├── requirements.txt
└── README.md


# 🔄 Project Workflow

                Log File Upload
                       │
                       ▼
                Log Parsing Engine
                       │
                       ▼
              Threat Detection Engine
                       │
       ┌───────────────┴───────────────┐
       ▼                               ▼
 IOC Detection                  IP Geolocation
       │                               │
       └───────────────┬───────────────┘
                       ▼
         Severity & Threat Score
                       │
                       ▼
          MITRE ATT&CK Mapping
                       │
                       ▼
          Dashboard Visualization
                       │
                       ▼
        PDF & CSV Security Reports

Installation-
Clone the repository
git clone https://github.com/tanviagrawalnew-bot/mini-siem.git

Move into the project directory
cd mini-siem

Install dependencies
pip install -r requirements.txt

Run the application
Python app.py

Open your browser
http://127.0.0.1:5000

How to Use
1. Launch the Flask application.
2. Upload a supported log file.
3. The parser processes the logs.
4. Suspicious activities are detected.
5. IOC analysis and IP geolocation are performed.
6. Severity levels and threat scores are calculated.
7. Events are mapped to MITRE ATT&CK techniques.
8. Results are displayed on the dashboard.
9. Export the security report as PDF or CSV.

 Future Improvements
- Real-time log monitoring
- AI-based anomaly detection
- Live charts and analytics
- Email alert notifications
- User authentication
- Multi-user support
- Dark mode dashboard
- Threat intelligence API integration

# 👩‍💻 Author
Tanvi Agrawal
Kajal Singh
B.Tech CSE Student
Cybersecurity Enthusiast