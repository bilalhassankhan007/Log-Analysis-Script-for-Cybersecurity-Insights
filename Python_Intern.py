import re
from collections import defaultdict
import csv

# Constants
LOG_FILE = 'sample.log'
OUTPUT_CSV = 'log_analysis_results.csv'
FAILED_LOGIN_THRESHOLD = 10

# Regular expressions to extract relevant information from the log file
IP_REGEX = r'^(\d+\.\d+\.\d+\.\d+)'
ENDPOINT_REGEX = r'"(?:GET|POST|PUT|DELETE|PATCH) (/\S*)'
FAILED_LOGIN_REGEX = r'401|Invalid credentials'


def count_requests_per_ip(log_lines):
    """Count requests per IP address."""
    ip_requests = defaultdict(int)
    for line in log_lines:
        match = re.search(IP_REGEX, line)
        if match:
            ip_requests[match.group(1)] += 1
    return sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)


def identify_most_accessed_endpoint(log_lines):
    """Identify the most frequently accessed endpoint."""
    endpoint_requests = defaultdict(int)
    for line in log_lines:
        match = re.search(ENDPOINT_REGEX, line)
        if match:
            endpoint_requests[match.group(1)] += 1
    return max(endpoint_requests.items(), key=lambda x: x[1])


def detect_suspicious_activity(log_lines):
    """Detect suspicious activity based on failed login attempts."""
    failed_logins = defaultdict(int)
    for line in log_lines:
        if re.search(FAILED_LOGIN_REGEX, line):
            match = re.search(IP_REGEX, line)
            if match:
                failed_logins[match.group(1)] += 1
    # Filter out IPs that exceed the threshold
    return {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}


def save_to_csv(requests_per_ip, most_accessed_endpoint, suspicious_activity):
    """Save results to a CSV file."""
    with open(OUTPUT_CSV, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(requests_per_ip)
        writer.writerow([])

        # Most accessed endpoint
        writer.writerow(["Most Frequently Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow(most_accessed_endpoint)
        writer.writerow([])

        # Suspicious activity
        writer.writerow(["Suspicious Activity Detected"])
        writer.writerow(["IP Address", "Failed Login Attempts"])
        writer.writerows(suspicious_activity.items())


def main():
    # Read the log file
    with open(LOG_FILE, 'r') as file:
        log_lines = file.readlines()

    # 1. Count requests per IP
    requests_per_ip = count_requests_per_ip(log_lines)
    print("Requests per IP Address:")
    for ip, count in requests_per_ip:
        print(f"{ip:20} {count}")
    print()

    # 2. Identify the most accessed endpoint
    most_accessed_endpoint = identify_most_accessed_endpoint(log_lines)
    print("Most Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    print()

    # 3. Detect suspicious activity
    suspicious_activity = detect_suspicious_activity(log_lines)
    print("Suspicious Activity Detected:")
    for ip, count in suspicious_activity.items():
        print(f"{ip:20} {count}")
    print()

    # 4. Save the results to a CSV file
    save_to_csv(requests_per_ip, most_accessed_endpoint, suspicious_activity)
    print(f"Results saved to {OUTPUT_CSV}")


if __name__ == '__main__':
    main()
