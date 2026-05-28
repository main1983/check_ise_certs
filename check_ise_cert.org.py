#!/usr/bin/env python3
import sys
import requests
import argparse
from datetime import datetime

# Disable SSL warnings for self-signed ISE certs
requests.packages.urllib3.disable_warnings()

def get_ise_data(url, user, password):
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    try:
        response = requests.get(url, auth=(user, password), headers=headers, verify=False, timeout=8)
        response.raise_for_status()
        return response.json()
    except Exception:
        return None

def check_certs(host, user, password, usage_input, warn, crit):
    # Step 1: Discover all nodes
    nodes_url = f"https://{host}/api/v1/deployment/node"
    nodes_data = get_ise_data(nodes_url, user, password)

    if nodes_data is None:
        print(f"CRITICAL: Primary PAN {host} is unreachable.")
        sys.exit(2)

    # Convert comma-separated input into a clean list of lowercase strings
    target_usages = [u.strip().lower() for u in usage_input.split(',')]
    node_list = [node['hostname'] for node in nodes_data.get('response', [])]

    issues = []
    unreachable_nodes = []
    checked_certs = set() # Prevent duplicate alerts if a cert has multiple roles
    max_severity = 0

    for node_name in node_list:
        cert_url = f"https://{host}/api/v1/certs/system-certificate/{node_name}"
        cert_data = get_ise_data(cert_url, user, password)

        if cert_data is None:
            unreachable_nodes.append(node_name)
            continue

        for cert in cert_data.get('response', []):
            # API returns usage as a string like "Admin, RADIUS DTLS"
            cert_usages = cert.get('usedBy', '').lower()

            # Check if ANY of our target usages appear in this certificate's roles
            match = any(usage in cert_usages for usage in target_usages)
            if usage_input.lower() != "all" and not match:
                continue

            cert_id = f"{node_name}_{cert.get('id')}"
            if cert_id in checked_certs: continue
            checked_certs.add(cert_id)

            friendly_name = cert.get('friendlyName', 'Unknown')
            expiry_str = cert.get('expirationDate')

            try:
                expiry_date = datetime.strptime(expiry_str, "%Y-%m-%d %H:%M:%S")
                days_left = (expiry_date - datetime.now()).days

                status_text = f"[{node_name}] {friendly_name} ({days_left}d)"

                if days_left <= crit:
                    max_severity = 2
                    issues.append(f"CRIT: {status_text}")
                elif days_left <= warn:
                    max_severity = max(max_severity, 1)
                    issues.append(f"WARN: {status_text}")
            except: continue

    # Build the final output string for OP5
    output = []
    if issues:
        output.append(" | ".join(issues))
    else:
        output.append(f"OK: Checked {len(checked_certs)} certs for '{usage_input}' across {len(node_list)} nodes.")

    if unreachable_nodes:
        output.append(f"Unreachable: {', '.join(unreachable_nodes)}")
        max_severity = max(max_severity, 1)

    print(" - ".join(output))
    sys.exit(max_severity)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-H', '--host', required=True)
    parser.add_argument('-u', '--user', required=True)
    parser.add_argument('-p', '--password', required=True)
    parser.add_argument('-m', '--usage', required=True, help='e.g. "Admin, RADIUS DTLS" or "EAP Authentication"')
    parser.add_argument('-w', '--warning', type=int, default=30)
    parser.add_argument('-c', '--critical', type=int, default=15)
    args = parser.parse_args()
    check_certs(args.host, args.user, args.password, args.usage, args.warning, args.critical)
