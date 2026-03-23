# Real Time Log Analyzer (cybersecurity project)

## Overview

This project was written in Python and is a real time log monitoring tool that detects common recon activity, and web based attacks from log files. It simulates a lightweight intrusion detection system (IDS) for Apache/Nginx style web server logs.


# Detection capabilities

- Cross-Site Scripting (XSS)
- Directory Traversal
- SQL injection
- Web Shell Activity
- Command Injection


# Features

- Real time log monitoring
- Timestamped alerts
- Apache/Nginx style log support
- Writes alerts to alerts.log
- Alert counter + summary
- Lightweight and easy to run
- Color Terminal output
- Regex based detection
- Severity Classification (HIGH / MEDIUM / LOW)


# Technologies Used
- Python
- String based threat detection
- Datetime module
- File streaming (real time monitoring)
- Regular Expressions ('re')


# How to Run

## Clone the repository
git clone https://github.com/D34ds3a/log-analyzer-reailtime.git cd log-analyzer-realtime

## Run the Analyzer

'''bash
py realtime_log_analyzer.py


## Simulate Log Activity

While the program is running

1. Open sample_logs.txt

2. Add a new line at the bottom, for example in descending severity order LOW, MEDIUM, HIGH :

   '''text
   192.168.1.30 - - [22/Mar/2026:07:00:45 +0000] "GET /robots.txt HTTP/1.1" 200 120
   
   192.168.1.30 - - [22/Mar/2026:06:10:00 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 512
   
   10.0.0.5 - - [22/Mar/2026:06:10:05 +0000] "GET /login?user=admin' OR '1'='1 HTTP/1.1" 401 210
   
4. save file


# Observe Alerts

The program will instantly detect malicious patterns and display alerts like:
[2026-03-22 )7:00:00] [HIGH] [ALERT] SQL Injection detected from 10.0.0.5 | Log: 10.0.0.5 - - [22/Mar/2026:06:10:05 +0000] "GET /login?user=admin' OR '1'='1 HTTP/1.1" 401 210

alerts are also saved to:
alerts.log


# Stop the Program

Press:

Ctrl + C

To safely stop monitoring


# Demo

Screenshots saved as alerts.png, Realtime_log_analyzer_input_demo.png, Realtime_log_analyzer_output_demo.png, Realtime_log_analyzer_run_demo.png



# Future Improvements

- Regex based detection engine
- Detection thresholds (repeat offender alerts)
- JSON/CSV export for SIEM integration
- Integration with real server logs
- Modular detection engine
- Dashboard/UI visualization
- Custom themes an banners


# Why This Project Matters

This project demonstrates real time log analysis, cybersecurity threat detection, and Python scripting for security tool development. It leverages Regex based pattern matching to identify an classify recon activity, common web attacks such as XSS and SQL injection.


# Author

Cole Hart


&#x20;









&#x20;

