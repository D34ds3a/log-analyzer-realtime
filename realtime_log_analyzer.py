import time 
from datetime import datetime
import re

RED = "\033[38;5;196m"
YELLOW = "\033[38;5;226m"
GREEN = "\033[38;5;46m"
GREY = "\033[38;5;146m"
RESET = "\033[0m"
BOLD = "\033[1m"


def extract_request(line):
   if '"' in line:
       parts = line.split('"')
       if len(parts) >=2:
           return parts[1]
   return line 
 
def analyze_log(line):
   request = extract_request(line)
   line_lower = request.lower()
   if re.search(r"<\s*script.*?>", line_lower) or re.search(r"%3c\s*script%3e", line_lower):
        return "XSS"
   elif re.search(r"onerror\s*=", line_lower) or re.search(r"onload\s*=", line_lower):
        return "XSS"
   elif re.search(r"javascript\s*:", line_lower):
        return "XSS"
   elif re.search(r"\bor\b\s+['\"]?1['\"]?\s*=\s*['\"]?1", line_lower) or re.search(r"\bor\b\s+1\s*=\s*1", line_lower):
        return "SQL Injection"
   elif re.search(r"union\s+select", line_lower):
        return "SQL Injection"
   elif re.search(r"drop\s+table", line_lower):
        return "SQL Injection"
   elif re.search(r"\.\./", line_lower) or re.search(r"\.\.\\", line_lower):
        return "Directory Traversal"
   elif re.search(r"etc/passwd", line_lower) or re.search("boot\.ini", line_lower):
       return "Directory Traversal"
   elif re.search(r";\s*whoami", line_lower) or re.search(r";\s*ls", line_lower) or re.search(r"&&\s*whoami", line_lower):
       return "Command Injection"
   elif re.search(r"\|\s*whoami", line_lower) or re.search(r"\|\s*ls", line_lower):
       return "Command Injection"
   elif re.search(r"\.php", line_lower) and re.search(r"cmd\s*=", line_lower):
       return "Web Shell Activity"
   elif re.search(r"powershell", line_lower) or re.search(r"cmd\.exe", line_lower):
       return "Suspicious Command Execution"
   elif re.search(r"/admin\b",line_lower) or re.search(r"phpmyadmin", line_lower) or re.search(r"\.env", line_lower) or re.search(r"robots\.txt", line_lower):
       return "Recon Activity"  
   return None

def get_severity(result):
   if result == "SQL Injection":
       return "HIGH"
   elif result == "Directory Traversal":
       return "HIGH"
   elif result == "Command Injection":
       return "HIGH"
   elif result == "Web Shell Activity":
       return "HIGH"
   elif result == "XSS":
       return "MEDIUM"
   elif result == "Suspicious Command Execution":
       return "MEDIUM"
   elif result == "Recon Activity":
       return "LOW"
   else:
       return "LOW"

def color_for_severity(severity):
   if severity == "HIGH":
       return RED
   elif severity == "MEDIUM":
       return YELLOW
   else:
       return GREEN


def main():
   total_alerts = 0
   alert_counts = {}
   ip_counts = {}
   
   print("Monitoring sample_logs.txt for new log enteries...")
   print("Press Ctrl + C to stop. \n")

   with open("sample_logs.txt", "r") as log_file, open("alerts.log", "a") as alert_file:
       log_file.seek(0,2)
    
       try:
           while True:
               line = log_file.readline()
               if not line:
                   time.sleep(1)
                   continue

               line = line.strip()
               if not line:
                   continue

               result = analyze_log(line)
               ip = line.split()[0]
               if result:
                   severity = get_severity(result)
                   color = color_for_severity(severity)
                   total_alerts += 1

                   alert_counts[result] = alert_counts.get(result, 0) + 1
                   ip_counts[ip] = ip_counts.get(ip, 0) + 1
                   timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                   alert_message = f"[{timestamp}] [{severity}] [ALERT] {result} detected from {ip} | Log: {line}"
                   print(f"{color}{BOLD}{alert_message}{RESET}")

                   alert_file.write(alert_message + "\n")
                   alert_file.flush()
                   print(f"\n{GREY}{BOLD}--- Summary ---{RESET}")
                   print(f"{BOLD}Total alerts detected:{RESET} {total_alerts}")
                   
                   for alert_type, count in alert_counts.items():
                       alert_severity = get_severity(alert_type)
                       alert_color = color_for_severity(alert_severity)
                       print(f"{alert_color}{alert_type}:{RESET} {count}")
                   print(f"\n{GREY}{BOLD}Suspicious IPs:{RESET}")
                   for ip_addr, count in ip_counts.items():
                       print(f"{ip_addr}: {count}")
                   print()
       except KeyboardInterrupt:
           print("\nMonitoring stopped.")

if __name__ == "__main__":
   main() 
