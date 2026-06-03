# Cisco ISE Certificate Expiration Checker

[![Language](https://img.shields.io/badge/Language-Python%203-blue.svg)](https://www.python.org/)
[![Monitoring Compliant](https://img.shields.io/badge/Plugin%20Standard-Nagios%20%2F%20OP5-orange.svg)](https://nagios-plugins.org/doc/guidelines.html)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

A robust, enterprise-ready Python monitoring plugin designed to inspect the expiration dates of certificates on **Cisco Identity Services Engine (ISE)** nodes. Compliant with standard monitoring engines (Nagios, OP5, Icinga), this script automatically discovers all nodes in the ISE deployment and outputs status results alongside performance telemetry metrics.

---

## Features

- **Deployment Auto-Discovery**: Queries the Primary PAN once to discover all ISE nodes in the deployment, automatically verifying certificates across all active members.
- **Nagios/OP5 Compliant Exit Codes**: Translates certificate lifetimes directly into standard monitoring status codes (`0` OK, `1` WARNING, `2` CRITICAL, `3` UNKNOWN).
- **Performance Telemetry**: Appends performance metrics (`min_days_left`) after the pipe character (`|`), allowing graphing software (such as PNP4Nagios, Grafana, or InfluxDB) to track certificate lifetimes.
- **Robust Exception Handling**: Diagnoses connection errors, timeouts, and auth failures (reporting `401 Unauthorized` or `403 Forbidden` with helpful configuration tips) rather than failing silently.
- **Defensive API Parsing**: Safely handles cases where Cisco ISE returns certificate roles (`usedBy`) as either a list or a comma-separated string, and matches date templates dynamically using fallback patterns.
- **Interactive Usage Guide**: Executing the script without arguments displays a custom, informative usage guide.

---

## Cisco ISE Prerequisites

To query the Cisco ISE REST API, External RESTful Services (ERS) or OpenAPI must be enabled on your deployment:

1. Log in to your Cisco ISE Admin Portal.
2. Navigate to **Administration > System > Settings > ERS Settings** (or **OpenAPI Settings**).
3. Select **Enable ERS Read/Write** (or **Enable OpenAPI**).
4. Click **Save**.
5. Ensure the API user account possesses appropriate read roles (e.g., `ERS Admin` or `ERS Operator`).

> [!WARNING]
> By default, Cisco ISE issues self-signed HTTPS certificates for ERS API endpoints. If your environment has not provisioned trusted certificates for ERS, execute the script without the `--ssl-verify` flag (warnings are suppressed automatically).

---

## Installation & Setup

We recommend setting up a virtual environment using `uv` (a fast Python package installer and resolver).

### 1. Initialize Virtual Environment
```bash
# Create the UV virtual environment
uv venv

# Activate the virtual environment
source .venv/bin/activate
```

### 2. Install Dependencies
Install the required `requests` library:
```bash
uv pip install requests
```

---

## Environment File Configuration (.env)

The script can automatically load default values from a `.env` file located in the same working directory. This is useful for automating checks in cron jobs or running checks without displaying passwords in terminal process lists.

Create a file named `.env` in the script directory:
```env
# Cisco ISE Core Configurations
ISE_HOST=ise.local
ISE_USER=api_user
ISE_PASSWORD=api_password
ISE_USAGE=Admin, EAP Authentication

# Optional Threshold Overrides
ISE_WARNING=30
ISE_CRITICAL=15
ISE_SSL_VERIFY=false
```

Once defined in your `.env` file, you can run the check without any command-line parameters:
```bash
python3 check_ise_cert.py
```
> [!NOTE]
> Command-line arguments always take precedence and override values defined in the `.env` file.

---


## Command-Line Usage

Running the script with no arguments prints the interactive help guide:
```bash
python3 check_ise_cert.py
```

### Arguments Table

| Flag | Argument | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `-H` | `--host` | **Yes** (or `ISE_HOST` in `.env`) | *None* | Cisco ISE Primary PAN hostname or IP address. |
| `-u` | `--user` | **Yes** (or `ISE_USER` in `.env`) | *None* | Cisco ISE ERS or OpenAPI admin username. |
| `-p` | `--password` | **Yes** (or `ISE_PASSWORD` in `.env`) | *None* | Cisco ISE ERS or OpenAPI admin password. |
| `-m` | `--usage` | **Yes** (or `ISE_USAGE` in `.env`) | *None* | Comma-separated certificate usages to check (e.g. `Admin, RADIUS DTLS`, `EAP Authentication`, or `all`). |
| `-w` | `--warning` | No | `30` (or `ISE_WARNING` in `.env`) | Number of days left before triggering a `WARNING` state. |
| `-c` | `--critical` | No | `15` (or `ISE_CRITICAL` in `.env`) | Number of days left before triggering a `CRITICAL` state. |
| *None*| `--ssl-verify`| No | `False` (or `ISE_SSL_VERIFY` in `.env`) | Enable SSL verification of the Cisco ISE endpoints. |
| `-v` | `--verbose`   | No | `False` (or `ISE_VERBOSE` in `.env`)    | Print detailed diagnostic output to stdout (debugging mode). |

---

## Practical Examples

### 1. Check EAP and Portal Certificates (Default Thresholds)
Check EAP and Portal certificates across all deployment nodes, alerting if any expire within 30 days (Warning) or 15 days (Critical):
```bash
python3 check_ise_cert.py -H ise.local -u api_user -p api_pass -m "EAP Authentication, Portal"
```

### 2. Custom Expiration Thresholds
Raise warning alerts at 60 days and critical alerts at 30 days:
```bash
python3 check_ise_cert.py -H ise.local -u api_user -p api_pass -m "Admin" -w 60 -c 30
```

### 3. Check All Certificates
Inspect all system certificates regardless of their active roles or usages:
```bash
python3 check_ise_cert.py -H ise.local -u api_user -p api_pass -m all
```

### 4. Enable SSL Certificate Verification
If your Cisco ISE ERS API uses certificates issued by a trusted corporate CA:
```bash
python3 check_ise_cert.py -H ise.local -u api_user -p api_pass -m "Admin" --ssl-verify
```

### 5. Detailed Verbose Diagnostic Output
To print a breakdown of all discovered nodes, evaluated/ignored certificates, and dates, pass the `-v` / `--verbose` flag:
```bash
python3 check_ise_cert.py -H ise.local -u api_user -p api_pass -m Admin -v
```
Example Output:
```text
OK: Checked 7 certs for 'Admin' across 7 nodes. | min_days_left=97;30;15;0;

--- Detailed Certificate Diagnostics ---
[*] Discovering deployment nodes via Primary PAN: https://ise.local/api/v1/deployment/node
[+] Discovered 7 node(s): ise-node1, ise-node2, ise-node3, ise-node4, ise-node5, ise-node6, ise-node7
[*] Usage filter: 'Admin'

[*] Querying system certificates for node: ise-node1
  [+] Found 6 total certificates on ise-node1
  - [SAML Cert] (ID: 81b9c6be...) | Usages: 'SAML' -> IGNORED (no match)
  - [Radius Cert] (ID: 8e69504e...) | Usages: 'EAP Authentication' -> IGNORED (no match)
  - [Admin Cert] (ID: 71641a22...) | Usages: 'Admin, RADIUS DTLS' | Expires: Thu Sep 03 10:11:48 CEST 2026 (97d left) -> OK
```

---

## OP5 & Nagios Integration

### Output Format
The script returns a single line of status text followed by performance metrics:

```text
Status Text | Performance Data Metrics
```

- **OK Status**:
  `OK: Checked 3 certs for 'Admin' across 3 nodes. | min_days_left=120;30;15;0;`
- **Alert Status**:
  `CRIT: [ise-node1] Admin (10d), WARN: [ise-node2] Admin (28d) | min_days_left=10;30;15;0;`
- **Secondary Node Offline Status**:
  `OK: Checked 2 certs for 'Admin' across 3 nodes. - Unreachable: ise-node3 (ConnectionError) | min_days_left=45;30;15;0;`

### Exit Codes

Monitoring systems use exit codes to gauge status severity:

| Exit Code | Severity | Description |
| :---: | :--- | :--- |
| **`0`** | **OK** | All matching certificates are valid and above the warning threshold. |
| **`1`** | **WARNING** | At least one certificate is within the warning threshold (<= warning days), OR one or more secondary deployment nodes could not be contacted. |
| **`2`** | **CRITICAL** | At least one certificate is within the critical threshold (<= critical days), OR the primary PAN is unreachable. |
| **`3`** | **UNKNOWN** | Invalid command usage, unrecognized arguments, or unparseable certificate date formats. |

---

## Development & Verification

A mock unit test suite is provided to verify all script logic without contacting a live Cisco ISE server.

### Run Unit Tests
Ensure you have activated the virtual environment and execute the unit test scripts:
```bash
# Run Expiration Checker tests
python3 -m unittest tests/test_cert_checker.py

# Run Trust Chain & Orphan Analyzer tests
python3 -m unittest tests/test_orphan_analyzer.py
```

### Test Coverage Scenarios
- Custom usage guide triggering on zero-arguments.
- API authentication errors (`401 Unauthorized` diagnostics) and connection failures.
- Normal validation with valid certificates (`min_days_left` metrics check).
- Multiple expirations triggering warning/critical severities.
- Graceful handling of unreachable secondary nodes (triggers `WARNING`).
- Date parser validation and unsupported date format handling (triggers `UNKNOWN`).
- Dependency loop protection, missing parents, and standalone trust flags verification.

---

## Certificate Dependency & Orphan Analyzer

In addition to checking expiration, the repository includes `check_ise_orphans.py` which performs a top-down trust chain dependency audit. Over years of certificate renewals, deployments often accumulate old/redundant root CAs, intermediate CAs, and unused self-signed system certificates. This tool helps identify and clean up that clutter.

### Key Capabilities
- **Top-Down Trust Visualization**: Renders an ASCII hierarchy tree starting from active Root CAs, through intermediate CAs, down to active System Certificates.
- **Node-Targeted Audits**: Focuses the analysis on a single targeted node (using the `-N`/`--node` flag), isolating its specific trust tree branches and auditing only its system certificates.
- **Narrow-Screen Readability**: Intelligently auto-truncates long friendly names (while preserving unique suffix `#ID` hashes) and maps usages/trusts to compact abbreviations, with an optional `-w`/`--wide` mode to disable truncation on wide terminals.
- **Orphan System Certificates**: Detects certificates installed on nodes that are not mapped to any active roles (i.e. `usedBy` is `"Not in use"`).
- **Unused/Orphan Trusted Certificates**: Identifies certificates in the Trust Store that are enabled but are not part of any active system certificate chain, and have no active trust flags.
- **Superceded / Duplicate Trusted Certificates**: Flags old versions of CAs that are expired or unused but share a CN with a newer, active CA.
- **Loop & Recursion Safety**: Employs visited-path checks and leaf boundaries to prevent infinite loops from circular parent-child references.


### Command-Line Usage
```bash
python3 check_ise_orphans.py -H <host> -u <user> -p <password> [options]
```

| Flag | Argument | Required | Description |
| :--- | :--- | :--- | :--- |
| `-H` | `--host` | **Yes** (or `ISE_HOST` in `.env`) | Cisco ISE Primary PAN hostname or IP address. |
| `-u` | `--user` | **Yes** (or `ISE_USER` in `.env`) | Cisco ISE ERS or OpenAPI admin username. |
| `-p` | `--password` | **Yes** (or `ISE_PASSWORD` in `.env`) | Cisco ISE ERS or OpenAPI admin password. |
| *None*| `--ssl-verify`| No | Enable SSL verification of the Cisco ISE endpoints. |
| `-x` | `--exclude-cisco-services`| No | Exclude/hide built-in root CAs only used for Cisco Services trust (reduces noise). |
| `-N` | `--node`     | No | Target a specific node in the deployment for a focused audit and trust chain rendering. |
| `-w` | `--wide`     | No | Display full certificate names and long fields (disables auto-truncation for narrow screens). |
| `-v` | `--verbose`   | No | Print detailed discovery logs to stdout. |


