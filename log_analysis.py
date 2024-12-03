import re
from collections import defaultdict, Counter
import csv


def parse_log_file(file_path):
    with open(file_path, 'r') as file:
        return file.readlines()


def count_requests_per_ip(log_lines):
    ip_counts = Counter()
    for line in log_lines:
        ip_match = re.match(r'(\d+\.\d+\.\d+\.\d+)', line)
        if ip_match:
            ip_counts[ip_match.group(1)] += 1
    return ip_counts


def most_frequent_endpoint(log_lines):
    endpoint_counts = Counter()
    for line in log_lines:
        endpoint_match = re.search(r'\"(?:GET|POST|PUT|DELETE)\s+([^\s]+)', line)
        if endpoint_match:
            endpoint_counts[endpoint_match.group(1)] += 1
    if endpoint_counts:
        most_common_endpoint, count = endpoint_counts.most_common(1)[0]
        return most_common_endpoint, count
    return None, 0


def detect_suspicious_activity(log_lines, threshold=10):
    failed_login_counts = defaultdict(int)
    for line in log_lines:
        if '401' in line or 'Invalid credentials' in line:
            ip_match = re.match(r'(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                failed_login_counts[ip_match.group(1)] += 1
    return {ip: count for ip, count in failed_login_counts.items() if count > threshold}


def save_results_to_csv(ip_requests, most_accessed_endpoint, suspicious_activity):
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # Write Requests per IP
        writer.writerow(['Requests per IP'])
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])
        writer.writerow([])  # Blank row for separation
        
        # Write Most Accessed Endpoint
        writer.writerow(['Most Accessed Endpoint'])
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])
        writer.writerow([])  # Blank row for separation
        
        # Write Suspicious Activity
        writer.writerow(['Suspicious Activity'])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])


def main():
    log_file = input("Enter the path to the log file: ").strip()
    log_lines = parse_log_file(log_file)

    # Count requests per IP
    ip_requests = count_requests_per_ip(log_lines)
    print("IP Address           Request Count")
    for ip, count in ip_requests.most_common():
        print(f"{ip:<20}{count}")

    # Most frequently accessed endpoint
    endpoint, access_count = most_frequent_endpoint(log_lines)
    print(f"\nMost Frequently Accessed Endpoint:\n{endpoint} (Accessed {access_count} times)")

    # Detect suspicious activity
    suspicious_activity = detect_suspicious_activity(log_lines)
    if suspicious_activity:
        print("\nSuspicious Activity Detected:")
        print("IP Address           Failed Login Attempts")
        for ip, count in suspicious_activity.items():
            print(f"{ip:<20}{count}")
    else:
        print("\nNo suspicious activity detected.")

    # Save results to CSV
    save_results_to_csv(ip_requests, (endpoint, access_count), suspicious_activity)
    print("\nResults saved to 'log_analysis_results.csv'")


if __name__ == "__main__":
    main()
