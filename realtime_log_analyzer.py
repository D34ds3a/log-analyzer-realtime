import time 
from datetime import datetime


def analyze_log(line):
   line_lower = line.lower()
   if "<script>" in line_lower or "%3cscript%3e" in line_lower:
        return "XSS"
   elif "onerror=" in line_lower or "onload=" in line_lower:
        return "XSS"
   elif "javascript:" in  line_lower:
        return "XSS"
   elif "or '1'='1" in line_lower or 'or "1"="1' in line_lower:
        return "SQL Injection"
   elif "union select" in line_lower:
        return "SQL Injection"
   elif "drop table" in line_lower:
        return "SQL Injection"
   elif "../" in line or "..\\" in line:
        return "Directory Traversal"
   elif "etc/passwd" in line_lower or "boot.ini" in line_lower:
       return "Directory Traversal"
   elif "; whoami" in line_lower or "; ls" in line_lower or "&& whoami" in line_lower:
       return "Command Injection"
   elif "| whoami" in line_lower or "| ls" in line_lower:
       return "Command Injection"
   elif ".php" in line_lower and "cmd=" in line_lower:
       return "Web Shell Activity"
   elif "powershell" in line_lower or "cmd.exe" in line_lower:
       return "Suspicious Command Exicution"
   return None


def main():
   total_alerts = 0
   alert_counts = {}
   
   print("Monitoring sample_logs.txt for new log enteries...")
   print("Press Ctrl + C to stop. \n")

   with open("sample_logs.txt", "r") as log_file, open("alerts.log", "a") as alert_file:
       log_file.seek(0,2)
    
       try:
           while True:
               line = log_file.readline()
               if not line:
                   time.sleep(1)
               line = line.strip()
               result = analyze_log(line)
               if result:
                   total_alerts += 1

                   alert_counts[result] = alert_counts.get(result, 0) + 1

                   timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                   alert_message = f"[{timestamp}] [ALERT] {result} detected! | Log: {line}"
                   print(alert_message)

                   alert_file.write(alert_message + "\n")
                   alert_file.flush()
                   print("n\--- Summary ---")
                   print(f"Total alerts detected:{total_alerts}")
                   
                   for alert_type, count in alert_counts.items():
                       print(f"{alert_type}: {count}")
                   print()
       except KeyboardInterrupt:
           print("\nMonitoring stopped.")

if __name__ == "__main__":
   main() 





 
