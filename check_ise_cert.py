#!/usr/bin/env python3
"""
Cisco ISE Certificate Expiration Checker (Nagios/OP5 Compliant Plugin)

This monitoring plugin connects to a Cisco ISE Primary Policy Administration Node (PAN)
using its External RESTful Services (ERS) or OpenAPI REST API, discovers all nodes in 
the deployment, and checks the expiration dates of system certificates mapped to specific usages.

Prerequisites:
  1. Cisco ISE ERS (External RESTful Services) or OpenAPI must be enabled:
     Administration > System > Settings > ERS Settings (or OpenAPI Settings)
  2. The API user must have appropriate read permissions (e.g., ERS Admin or Read-Only).
  3. The 'requests' library must be installed.

Exit Codes (Nagios Standard):
  0 - OK       All matching certificates are valid and above the warning threshold.
  1 - WARNING  At least one matching certificate is within the warning threshold (<= warning days),
               or one or more secondary nodes are unreachable.
  2 - CRITICAL At least one matching certificate is within the critical threshold (<= critical days),
               or the primary PAN is unreachable.
  3 - UNKNOWN  Invalid command-line arguments, missing parameters, or parsing errors.
"""

import sys
import os
import argparse
from datetime import datetime
import requests
import warnings
import traceback

# Disable SSL warnings for self-signed certificates by default.
# Users can verify certificates using the --ssl-verify option.
requests.packages.urllib3.disable_warnings()

def print_usage_guide():
    """
    Prints a detailed user guide to stderr, providing usage examples,
    parameter explanations, exit codes, and output formatting.
    """
    guide = """
Cisco ISE Certificate Expiration Checker (Nagios/OP5 Compliant Plugin)

This script connects to a Cisco ISE Primary Policy Administration Node (PAN) via its REST API,
discovers all nodes in the deployment, and checks the expiration dates of certificates matching 
the specified usage(s).

Usage:
  python3 check_ise_cert.py -H <host> -u <user> -p <password> -m <usage> [options]

Arguments:
  -H, --host        Cisco ISE Primary PAN hostname or IP address (Required)
  -u, --user        ISE ERS or OpenAPI Admin username (Required)
  -p, --password    ISE ERS or OpenAPI Admin password (Required)
  -m, --usage       Comma-separated list of certificate usages to check (Required)
                    Examples: "Admin", "EAP Authentication", "RADIUS DTLS", "Portal", or "all"
  -w, --warning     Number of days remaining before warning status (Default: 30)
  -c, --critical    Number of days remaining before critical status (Default: 15)
  --ssl-verify      Enable SSL certificate verification (Disabled by default)
  -v, --verbose     Print detailed diagnostic output to stdout (Disabled by default)

Monitoring Output:
  Outputs a single line compliant with Nagios/OP5 plugin guidelines, including performance data:
  OK: Checked X certs for 'Admin' across Y nodes | min_days_left=45;30;15;0;
  WARN: [node1] Admin (28d), Unreachable: node2 (HTTP 404) | min_days_left=28;30;15;0;
  CRIT: [node1] Admin (10d) | min_days_left=10;30;15;0;

Exit Codes:
  0 - OK       All certificates are valid and above the warning threshold.
  1 - WARNING  At least one certificate is within the warning threshold, or a secondary node is unreachable.
  2 - CRITICAL At least one certificate is within the critical threshold, or the primary PAN is unreachable.
  3 - UNKNOWN  Invalid command-line arguments or unexpected API error.

Examples:
  1. Check Admin certificate usage with default thresholds (30d warning, 15d critical):
     python3 check_ise_cert.py -H ise.local -u api_user -p api_pass -m Admin

  2. Check EAP and Portal certificates with custom thresholds (60d warning, 30d critical):
     python3 check_ise_cert.py -H ise.local -u api_user -p api_pass -m "EAP Authentication, Portal" -w 60 -c 30

  3. Check all certificates regardless of their usage:
     python3 check_ise_cert.py -H ise.local -u api_user -p api_pass -m all
"""
    print(guide, file=sys.stderr)


def get_ise_data(url, user, password, ssl_verify=False):
    """
    Performs an authenticated GET request to the Cisco ISE API.

    Args:
        url (str): The endpoint URL.
        user (str): Username for Basic Authentication.
        password (str): Password for Basic Authentication.
        ssl_verify (bool): Whether to verify the SSL certificate.

    Returns:
        dict: The parsed JSON response if successful.

    Raises:
        requests.exceptions.RequestException: If the HTTP request fails.
    """
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    response = requests.get(url, auth=(user, password), headers=headers, verify=ssl_verify, timeout=8)
    response.raise_for_status()
    return response.json()


def check_certs(host, user, password, usage_input, warn, crit, ssl_verify=False, verbose=False):
    """
    Discovers ISE nodes and validates expiration dates for matching system certificates.

    Args:
        host (str): Primary PAN hostname or IP.
        user (str): API admin username.
        password (str): API admin password.
        usage_input (str): Target certificate usage(s) (comma-separated or "all").
        warn (int): Number of days before warning status.
        crit (int): Number of days before critical status.
        ssl_verify (bool): True to verify SSL, False to skip verification.
        verbose (bool): True to print detailed certificate logs, False otherwise.
    """
    verbose_log = []

    def log_verbose(msg):
        if verbose:
            verbose_log.append(msg)

    # Step 1: Discover all deployment nodes from the Primary PAN
    nodes_url = f"https://{host}/api/v1/deployment/node"
    log_verbose(f"[*] Discovering deployment nodes via Primary PAN: https://{host}/api/v1/deployment/node")
    
    try:
        nodes_data = get_ise_data(nodes_url, user, password, ssl_verify)
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code
        if status == 401:
            print(f"CRITICAL: Primary PAN {host} returned 401 Unauthorized. Verify credentials and ERS Settings.")
        elif status == 403:
            print(f"CRITICAL: Primary PAN {host} returned 403 Forbidden. Ensure ERS API is enabled and user has access.")
        else:
            if verbose:
                print(f"CRITICAL: Primary PAN {host} returned HTTP {status}: {e}")
            else:
                print(f"CRITICAL: Primary PAN {host} returned HTTP {status}.")
        if verbose and verbose_log:
            print("\n--- Detailed Certificate Diagnostics ---")
            print("\n".join(verbose_log))
        sys.exit(2)
    except requests.exceptions.ConnectionError:
        print(f"CRITICAL: Primary PAN {host} is unreachable. Check network path or DNS resolution.")
        if verbose and verbose_log:
            print("\n--- Detailed Certificate Diagnostics ---")
            print("\n".join(verbose_log))
        sys.exit(2)
    except requests.exceptions.Timeout:
        print(f"CRITICAL: Primary PAN {host} request timed out (8s limit).")
        if verbose and verbose_log:
            print("\n--- Detailed Certificate Diagnostics ---")
            print("\n".join(verbose_log))
        sys.exit(2)
    except Exception as e:
        if verbose:
            print(f"CRITICAL: Primary PAN {host} connection failed: {e}")
        else:
            print(f"CRITICAL: Primary PAN {host} connection failed.")
        if verbose and verbose_log:
            print("\n--- Detailed Certificate Diagnostics ---")
            print("\n".join(verbose_log))
        sys.exit(2)

    # Parse nodes list
    node_list = [node['hostname'] for node in nodes_data.get('response', [])]
    if not node_list:
        print(f"CRITICAL: No deployment nodes returned by Primary PAN {host}.")
        if verbose and verbose_log:
            print("\n--- Detailed Certificate Diagnostics ---")
            print("\n".join(verbose_log))
        sys.exit(2)

    log_verbose(f"[+] Discovered {len(node_list)} node(s): {', '.join(node_list)}")
    log_verbose(f"[*] Usage filter: '{usage_input}'")

    # Clean the requested certificate usage input
    target_usages = [u.strip().lower() for u in usage_input.split(',')]
    
    issues = []
    unreachable_nodes = []
    checked_certs = set()  # Set of (node_name, cert_id) to avoid duplicate evaluation
    max_severity = 0
    min_days_left = None

    # Step 2: Query each discovered node for its system certificates
    for node_name in node_list:
        cert_url = f"https://{host}/api/v1/certs/system-certificate/{node_name}"
        log_verbose(f"\n[*] Querying system certificates for node: {node_name}")
        try:
            cert_data = get_ise_data(cert_url, user, password, ssl_verify)
        except Exception as e:
            # Map exception type to a brief string for standard output
            err_msg = type(e).__name__
            if isinstance(e, requests.exceptions.HTTPError):
                err_msg = f"HTTP {e.response.status_code}"
            unreachable_nodes.append(f"{node_name} ({err_msg})")
            log_verbose(f"  [-] Failed to reach node {node_name}: {e}")
            continue

        certs = cert_data.get('response', [])
        log_verbose(f"  [+] Found {len(certs)} total certificates on {node_name}")

        # Step 3: Evaluate each certificate on the node
        for cert in cert_data.get('response', []):
            # Safe parsing of 'usedBy' field which can be a list or comma-separated string
            used_by = cert.get('usedBy', '')
            if isinstance(used_by, list):
                cert_usages = ", ".join(used_by).lower()
            else:
                cert_usages = str(used_by).lower()

            friendly_name = cert.get('friendlyName', 'Unknown')
            cert_id_raw = cert.get('id')

            # Check if this certificate is mapped to any requested usages
            match = any(usage in cert_usages for usage in target_usages)
            if usage_input.lower() != "all" and not match:
                log_verbose(f"  - [{friendly_name}] (ID: {cert_id_raw}) | Usages: '{used_by}' -> IGNORED (no match)")
                continue

            # Prevent duplicate checks if a cert has multiple matching roles
            cert_id = f"{node_name}_{cert_id_raw}"
            if cert_id in checked_certs:
                log_verbose(f"  - [{friendly_name}] (ID: {cert_id_raw}) | Usages: '{used_by}' -> SKIP (already evaluated)")
                continue
            checked_certs.add(cert_id)

            expiry_str = cert.get('expirationDate')

            # Parse the expiration datetime using multiple fallback formats
            expiry_date = None
            date_formats = ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"]
            for fmt in date_formats:
                try:
                    expiry_date = datetime.strptime(expiry_str, fmt)
                    break
                except (ValueError, TypeError):
                    continue

            # Fallback for formats containing timezones (e.g. "Thu Sep 03 10:11:48 CEST 2026")
            if expiry_date is None and isinstance(expiry_str, str):
                parts = expiry_str.split()
                if len(parts) == 6:
                    # Strip out the timezone abbreviation (5th element) so standard strptime parses it
                    clean_str = " ".join(parts[:4] + parts[5:])
                    try:
                        expiry_date = datetime.strptime(clean_str, "%a %b %d %H:%M:%S %Y")
                    except ValueError:
                        pass

            if expiry_date is None:
                issues.append(f"UNKNOWN: [{node_name}] {friendly_name} expiration date '{expiry_str}' format not recognized")
                max_severity = max(max_severity, 3)
                continue

            # Calculate remaining days
            days_left = (expiry_date - datetime.now()).days

            # Update the global minimum days left for performance telemetry
            if min_days_left is None or days_left < min_days_left:
                min_days_left = days_left

            status_text = f"[{node_name}] {friendly_name} ({days_left}d)"

            # Check thresholds
            status_label = "OK"
            if days_left <= crit:
                max_severity = max(max_severity, 2)
                issues.append(f"CRIT: {status_text}")
                status_label = "CRITICAL"
            elif days_left <= warn:
                max_severity = max(max_severity, 1)
                issues.append(f"WARN: {status_text}")
                status_label = "WARNING"

            log_verbose(f"  - [{friendly_name}] (ID: {cert_id_raw}) | Usages: '{used_by}' | Expires: {expiry_str} ({days_left}d left) -> {status_label}")

    # Step 4: Build the final output string
    output_parts = []
    
    if issues:
        # Separate issues with commas rather than pipe characters to avoid Nagios metrics conflict
        output_parts.append(", ".join(issues))
    else:
        # Success output
        output_parts.append(f"OK: Checked {len(checked_certs)} certs for '{usage_input}' across {len(node_list)} nodes.")

    if unreachable_nodes:
        output_parts.append(f"Unreachable: {', '.join(unreachable_nodes)}")
        max_severity = max(max_severity, 1) # Unreachable nodes trigger WARNING status at least

    # Compile the performance data in Nagios-standard format: 'label'=value[UOM];[warn];[crit];[min];[max]
    perf_data = ""
    if min_days_left is not None:
        perf_data = f" | min_days_left={min_days_left};{warn};{crit};0;"

    print(" - ".join(output_parts) + perf_data)

    if verbose and verbose_log:
        print("\n--- Detailed Certificate Diagnostics ---")
        print("\n".join(verbose_log))

    sys.exit(max_severity)


def load_env_file(env_path=".env"):
    """
    Manually parses a .env file and sets values in os.environ.
    This avoids adding external dependencies like python-dotenv.
    """
    if not os.path.exists(env_path):
        return
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue
            # Split key and value on the first "="
            if "=" in line:
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip()
                # Strip wrapping single/double quotes if present
                if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                    val = val[1:-1]
                # Populate os.environ
                os.environ[key] = val


def main():
    # Load env variables from .env file if it exists
    load_env_file()

    # Read environment variables (either set natively or loaded from .env)
    host_default = os.environ.get('ISE_HOST')
    user_default = os.environ.get('ISE_USER')
    password_default = os.environ.get('ISE_PASSWORD')
    usage_default = os.environ.get('ISE_USAGE')
    
    # Optional arguments defaults from env
    warning_default = 30
    val_warn = os.environ.get('ISE_WARNING')
    if val_warn:
        try:
            warning_default = int(val_warn)
        except ValueError:
            pass
            
    critical_default = 15
    val_crit = os.environ.get('ISE_CRITICAL')
    if val_crit:
        try:
            critical_default = int(val_crit)
        except ValueError:
            pass

    ssl_verify_default = os.environ.get('ISE_SSL_VERIFY', '').lower() in ('true', '1', 'yes')
    verbose_default = os.environ.get('ISE_VERBOSE', '').lower() in ('true', '1', 'yes')

    # If no arguments are provided AND environment configuration is incomplete,
    # display the user guide and exit with UNKNOWN (3)
    if len(sys.argv) == 1 and not (host_default and user_default and password_default and usage_default):
        print_usage_guide()
        sys.exit(3)

    parser = argparse.ArgumentParser(add_help=True)
    
    # Configure required state dynamically: if the variable is in the environment,
    # it is not required on the command line.
    parser.add_argument('-H', '--host', required=host_default is None, default=host_default, help='Cisco ISE Primary PAN hostname/IP')
    parser.add_argument('-u', '--user', required=user_default is None, default=user_default, help='API Admin username')
    parser.add_argument('-p', '--password', required=password_default is None, default=password_default, help='API Admin password')
    parser.add_argument('-m', '--usage', required=usage_default is None, default=usage_default, help='Comma-separated cert usages (e.g. "Admin, RADIUS DTLS") or "all"')
    parser.add_argument('-w', '--warning', type=int, default=warning_default, help='Days before warning threshold (default: 30)')
    parser.add_argument('-c', '--critical', type=int, default=critical_default, help='Days before critical threshold (default: 15)')
    parser.add_argument('--ssl-verify', action='store_true', default=ssl_verify_default, help='Enable SSL certificate verification')
    parser.add_argument('-v', '--verbose', action='store_true', default=verbose_default, help='Print detailed diagnostic output to stdout')
    
    try:
        args = parser.parse_args()
    except SystemExit:
        # Standard argparse exit code on help (-h) is 0, but on syntax errors it is 2.
        # Let's preserve standard argparse exit, but intercept usages if needed.
        raise

    if not args.verbose:
        warnings.filterwarnings("ignore")

    try:
        check_certs(
            host=args.host,
            user=args.user,
            password=args.password,
            usage_input=args.usage,
            warn=args.warning,
            crit=args.critical,
            ssl_verify=args.ssl_verify,
            verbose=args.verbose
        )
    except Exception as e:
        if args.verbose:
            print("CRITICAL: An unexpected internal error occurred:", file=sys.stderr)
            traceback.print_exc()
        else:
            print("UNKNOWN: An unexpected error occurred. Use -v/--verbose for diagnostics.")
        sys.exit(3)


if __name__ == "__main__":
    main()
