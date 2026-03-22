\# Real Time Log Analyzer (cybersecurity project)



\## Overview



This project was written in Python and is a real time log monitoring tool that detects common web based attacks from log files. It simulates a lightweight intrusion detection system (IDS) for web server logs.





\# Detection capabilities



* Cross-Site Scripting (XSS)
* Directory Traversal
* SQL injection
* Web Shell Activity
* Command Injection





\# Features



* Real time log monitoring
* Timestamped alerts
* Apache/Nginx style log support
* Writes alerts to alerts.log
* Alert counter + summary
* Lightweight and easy to run





\# Technologies Used

* Python
* String based threat detection
* Datetime module
* File streaming (real time monitoring)





\# How to Run



\## Clone the repository

git clone https://github.com/D34ds3a/log-analyzer-reailtime.git cd log-analyzer-realtime



\## Run the Analyzer



'''bash

py realtime\_log\_analyzer.py





\## Simulate Log Activity



While the program is running



1. Open sample\_logs.txt
2. Add a new line at the bottom, for example:

192.168.1.50 - - \[22/Mar/2026:07:00:00 +0000] "GET / login?user=admin' OR '1'='1 HTTP/1.1" 401 210

3\. save file





\# Observe Alerts



The program will instantly detect malicious patterns and display alerts like:

\[2026-03-22 )7:00:00] \[ALERT] SQL Injection detected!



alerts are also saved to:

alerts.log





\# Stop the Program



Press:



Ctrl + C



To safely stop monitoring





\# Demo



Screenshots saved as Realtime\_log\_analysis\_run\_demo.png, Realtime\_log\_analyzer\_input\_demo.png, Realtime\_log\_analyzer\_output\_demo.png





\# Future Improvements



* Regex based detection engine
* IP tracking \& rate limiting
* JSON/CSV export
* Integration with real server logs
* Color text





\# Why This Project Matters



This project demonstrates real time log analysis, cybersecurity threat detection, and Python scripting for security tools.



\# Author



Cole Hart

&#x20;









&#x20;

