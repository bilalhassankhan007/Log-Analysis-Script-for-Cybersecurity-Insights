# Log Analysis Script for Cybersecurity Insights
# Problem Statement
Modern IT infrastructure generates extensive log files that capture critical information about system events, user interactions, and potential security breaches. Analyzing these log files manually is tedious, time-consuming, and prone to human error.

To address this challenge, organizations need automated solutions that can efficiently extract, analyze, and present actionable insights from log files. This is especially critical in cybersecurity, where identifying malicious activities like brute-force attacks, unauthorized access attempts, or suspicious patterns is essential for system security.

# Objective
The goal of this project is to build a Python-based Log Analysis Script that processes server log files to:

# 1) Count and display the number of requests made by each IP address.
# 2) Identify the most frequently accessed endpoints.
# 3) Detect and flag suspicious activities such as brute-force login attempts.
# 4) Save the analysis results to a CSV file for easy reporting and auditing.


# Features & Functionality
# 1) Count Requests Per IP Address
The script parses the log file to extract all IP addresses, counts how many requests each IP address made, and sorts them in descending order by request count.

# Code Logic:

Use a regular expression to extract IP addresses from each log entry.
Use a dictionary to count requests per IP.
Sort and display the results

# Sample Output: 
Requests per IP Address:
192.168.1.1          7
203.0.113.5          6
10.0.0.2             5
198.51.100.23        5
192.168.1.100        5


# 2) Identify the Most Frequently Accessed Endpoint
The script identifies which endpoint (e.g., /home, /login, /dashboard) was accessed most frequently.

# Code Logic:

# Use a regular expression to extract endpoints from log entries.
# Use a dictionary to count the frequency of each endpoint.
# Identify the endpoint with the highest access count.

# Sample Output:
Most Frequently Accessed Endpoint:
/home (Accessed 4 times)

# 3) Detect Suspicious Activity
The script detects potential brute-force login attempts by identifying IP addresses that have failed login attempts (HTTP 401 status or "Invalid credentials") exceeding a configurable threshold (default: 10).

# Code logic 
# Use a regular expression to identify failed login attempts.
# Count the number of failed attempts per IP address.
# Filter IPs exceeding the threshold and flag them as suspicious

# Sample Output :
Suspicious Activity Detected:
IP Address           Failed Login Attempts
192.168.1.100        12
203.0.113.5          11

# 4) Output Results to a CSV File
The script saves the analysis results in a well-organized CSV file (log_analysis_results.csv) with three sections:

# Requests per IP
# Most Frequently Accessed Endpoint
# Suspicious Activity Detected
# CSV Strcurure
"Requests per IP"
"IP Address", "Request Count"
"192.168.1.1", 7
"203.0.113.5", 6
...

"Most Frequently Accessed Endpoint"
"Endpoint", "Access Count"
"/home", 4

"Suspicious Activity Detected"
"IP Address", "Failed Login Attempts"
"192.168.1.100", 12



# Conclusion
This Log Analysis Script provides a foundational solution for parsing and analyzing server logs. It automates the tedious process of extracting key insights from log files, enhancing security monitoring, and system performance optimization.

# This project demonstrates:
# 1) Proficiency in Python programming for file handling and data analysis.
# 2) Practical application of regular expressions for string manipulation.
# 3) Experience in detecting security threats based on log data patterns.
# 4) Ability to generate reports in CSV format for further review and compliance.
