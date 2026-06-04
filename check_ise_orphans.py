#!/usr/bin/env python3
"""
Cisco ISE Certificate Dependency and Orphan Analyzer

This script performs a top-down dependency analysis of certificates in a Cisco ISE deployment.
It identifies:
1. Active trust chains (which root/intermediate CAs are backing active system services).
2. Orphaned System Certificates (system certificates on nodes not bound to any services).
3. Orphaned Trusted Certificates (certificates in the trust store that are not part of any active chain and have no active trust flags).
4. Expired Trusted Certificates.
5. Superceded/Duplicate Trusted Certificates (old versions of CAs that are expired or unused).
"""

import sys
import os
import argparse
from datetime import datetime
import requests
import warnings

# Disable SSL warnings for self-signed certificates by default.
requests.packages.urllib3.disable_warnings()

def load_env_file(env_path=".env"):
    """
    Parses a .env file and sets values in os.environ.
    This avoids adding external dependencies like python-dotenv.
    """
    if not os.path.exists(env_path):
        return
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip()
                if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                    val = val[1:-1]
                os.environ[key] = val

def get_ise_data(url, user, password, ssl_verify=False):
    """
    Performs an authenticated GET request to the Cisco ISE API.
    """
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    response = requests.get(url, auth=(user, password), headers=headers, verify=ssl_verify, timeout=12)
    response.raise_for_status()
    return response.json()

def parse_expiry_date(expiry_str):
    """
    Parses the certificate expiration/validity datetime string using multiple fallback formats.
    """
    if not expiry_str:
        return None
    
    expiry_date = None
    date_formats = ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"]
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

    return expiry_date
            
def extract_suffix_num(friendly_name):
    """
    Extracts the unique numeric index suffix (e.g. 45 from "Root CA#00045") if present.
    """
    if not friendly_name:
        return None
    parts = friendly_name.split('#')
    if len(parts) > 1:
        s = parts[-1].strip()
        if s.isdigit():
            return int(s)
    return None

def find_best_parent(child_node, candidates):
    """
    Resolves the single best parent among duplicate/renewed CA candidates.
    Uses standard X.509 validity period nesting constraints, preferring the newest parent CA 
    that was active at the time the child certificate was issued, and falling back to friendlyName suffix indexes.
    """
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]

    valid_candidates = []
    child_start_dt = child_node.valid_from
    child_end_dt = child_node.expiration_date

    for p in candidates:
        p_start_dt = p.valid_from
        p_end_dt = p.expiration_date

        start_ok = True
        if child_start_dt and p_start_dt:
            # Nesting constraint: Child must be issued after parent start (allow 5-minute grace for clock drift)
            start_ok = (child_start_dt - p_start_dt).total_seconds() >= -300
            
        end_ok = True
        if child_end_dt and p_end_dt:
            # Nesting constraint: Parent must not expire before child (allow 5-minute grace for clock drift)
            end_ok = (p_end_dt - child_end_dt).total_seconds() >= -300
            
        if start_ok and end_ok:
            valid_candidates.append(p)

    if not valid_candidates:
        valid_candidates = candidates

    if len(valid_candidates) == 1:
        return valid_candidates[0]

    # Sort valid candidates descending (newest / most specific first):
    # 1. By valid_from descending (newest parent CA that was active when child was issued)
    # 2. By friendlyName suffix index descending (if indexes are present)
    def sort_key(p):
        ts = p.valid_from.timestamp() if p.valid_from else 0
        suffix = extract_suffix_num(p.friendly_name) or 0
        return (ts, suffix)

    valid_candidates.sort(key=sort_key, reverse=True)
    return valid_candidates[0]

class CertificateNode:
    def __init__(self, cert_type, id_val, friendly_name, issued_to, issued_by, expiration_date_str, raw_data, node_name=None):
        self.type = cert_type  # 'system' or 'trusted'
        self.id = id_val
        self.friendly_name = friendly_name
        self.issued_to = (issued_to or '').strip()
        self.issued_by = (issued_by or '').strip()
        self.expiration_date_str = expiration_date_str
        self.expiration_date = parse_expiry_date(expiration_date_str)
        self.raw_data = raw_data
        self.valid_from_str = raw_data.get('validFrom') if isinstance(raw_data, dict) else None
        self.valid_from = parse_expiry_date(self.valid_from_str)
        self.node_name = node_name  # Only for system certificates
        self.serial_number = raw_data.get('serialNumberDecimalFormat', '')
        
        # Determine usages and trust flags
        self.usages = []
        if self.type == 'system':
            used_by = raw_data.get('usedBy', '')
            if isinstance(used_by, list):
                self.usages = [u.strip() for u in used_by if u.strip()]
            elif isinstance(used_by, str) and used_by.strip():
                self.usages = [u.strip() for u in used_by.split(',') if u.strip()]
        
        self.trusted_for = []
        if self.type == 'trusted':
            tf = raw_data.get('trustedFor', '')
            if isinstance(tf, list):
                self.trusted_for = [t.strip() for t in tf if t.strip()]
            elif isinstance(tf, str) and tf.strip():
                self.trusted_for = [t.strip() for t in tf.split(',') if t.strip()]
                
        self.status = raw_data.get('status', 'Enabled') # Enabled/Disabled
        self.self_signed = raw_data.get('selfSigned', False)
        
        # If not explicitly marked self-signed, double check if subject DN matches issuer DN, or issued_to matches issued_by
        if not self.self_signed:
            if self.issued_to and self.issued_by and self.issued_to.lower() == self.issued_by.lower():
                self.self_signed = True
            elif self.type == 'trusted':
                subj = raw_data.get('subject', '')
                if subj and subj.lower() == self.issued_by.lower():
                    self.self_signed = True
                    
        # Graph tracing flags
        self.is_directly_active = False
        self.is_indirectly_active = False
        self.is_visited = False

    @property
    def key(self):
        if self.type == 'system':
            return f"system_{self.node_name}_{self.id}"
        return f"trusted_{self.id}"

    @property
    def is_active(self):
        if self.type == 'system':
            return len(self.usages) > 0 and 'not in use' not in [u.lower() for u in self.usages]
        # Trusted certificates are active if they are enabled and have active trust flags or chain to an active system cert
        return self.is_directly_active or self.is_indirectly_active

    @property
    def is_expired(self):
        if self.expiration_date:
            return self.expiration_date < datetime.now()
        return False

    def __repr__(self):
        return f"<{self.type.upper()} {self.friendly_name} (ID: {self.id})>"

def build_trust_graph(host, user, password, ssl_verify=False, verbose=False):
    """
    Queries Cisco ISE API to fetch all system and trusted certificates, and returns lists of nodes.
    """
    def log_verbose(msg):
        if verbose:
            print(msg)

    # 1. Discover Nodes
    nodes_url = f"https://{host}/api/v1/deployment/node"
    log_verbose(f"[*] Discovering nodes from primary PAN: {nodes_url}")
    nodes_data = get_ise_data(nodes_url, user, password, ssl_verify)
    node_list = [node['hostname'] for node in nodes_data.get('response', [])]
    log_verbose(f"[+] Discovered {len(node_list)} node(s): {', '.join(node_list)}")

    all_certs = {}

    # 2. Get System Certificates
    for node_name in node_list:
        sys_url = f"https://{host}/api/v1/certs/system-certificate/{node_name}"
        log_verbose(f"[*] Fetching system certificates for node: {node_name}")
        try:
            sys_data = get_ise_data(sys_url, user, password, ssl_verify)
            certs = sys_data.get('response', [])
            log_verbose(f"  [+] Found {len(certs)} system certificates")
            for cert_raw in certs:
                node_obj = CertificateNode(
                    cert_type='system',
                    id_val=cert_raw.get('id'),
                    friendly_name=cert_raw.get('friendlyName'),
                    issued_to=cert_raw.get('issuedTo'),
                    issued_by=cert_raw.get('issuedBy'),
                    expiration_date_str=cert_raw.get('expirationDate'),
                    raw_data=cert_raw,
                    node_name=node_name
                )
                all_certs[node_obj.key] = node_obj
        except Exception as e:
            print(f"[-] Warning: Failed to fetch system certificates for node {node_name}: {e}", file=sys.stderr)

    # 3. Get Trusted Certificates (with pagination)
    trust_url = f"https://{host}/api/v1/certs/trusted-certificate"
    log_verbose(f"[*] Fetching trusted certificates from: {trust_url}")
    
    page = 1
    size = 100
    while True:
        try:
            paginated_url = f"{trust_url}?page={page}&size={size}"
            log_verbose(f"  [*] Querying trusted certificates page {page}...")
            trust_data = get_ise_data(paginated_url, user, password, ssl_verify)
            certs = trust_data.get('response', [])
            if not certs:
                break
            log_verbose(f"    [+] Page {page} returned {len(certs)} trusted certificates")
            for cert_raw in certs:
                node_obj = CertificateNode(
                    cert_type='trusted',
                    id_val=cert_raw.get('id'),
                    friendly_name=cert_raw.get('friendlyName'),
                    issued_to=cert_raw.get('issuedTo'),
                    issued_by=cert_raw.get('issuedBy'),
                    expiration_date_str=cert_raw.get('expirationDate'),
                    raw_data=cert_raw
                )
                # Keep unique ones
                all_certs[node_obj.key] = node_obj
                
            if len(certs) < size:
                break
            page += 1
        except Exception as e:
            print(f"[-] Warning: Failed to fetch trusted certificates on page {page}: {e}", file=sys.stderr)
            break

    return all_certs

def analyze_dependencies(all_certs):
    """
    Builds the dependency relationships and identifies active chains, orphans, and redundant certificates.
    """
    # Build lookup maps:
    # - issued_to_map: issuedTo (lowercase, stripped) -> list of CertificateNode
    # - issued_by_map: issuedBy (lowercase, stripped) -> list of CertificateNode
    issued_to_map = {}
    issued_by_map = {}
    for cert in all_certs.values():
        name_key_to = cert.issued_to.lower().strip()
        if name_key_to:
            issued_to_map.setdefault(name_key_to, []).append(cert)
            
        name_key_by = cert.issued_by.lower().strip()
        if name_key_by:
            issued_by_map.setdefault(name_key_by, []).append(cert)

    # Step 1: Identify directly active system certificates and standalone active trusted certificates
    for cert in all_certs.values():
        if cert.type == 'system':
            # Active if it has non-ignored usages
            if len(cert.usages) > 0 and not any(u.lower() == 'not in use' for u in cert.usages):
                cert.is_directly_active = True
        elif cert.type == 'trusted':
            # Enabled trusted certificates with active trust flags can be standalone active
            if cert.status.lower() == 'enabled' and cert.trusted_for and not cert.is_expired:
                # E.g., used for Client Auth or Cisco Services or Infrastructure
                cert.is_directly_active = True

    # Step 2: Trace chains upwards from active system certificates to build the active trust graph
    def trace_parents(child_node, visited_keys):
        if child_node.self_signed:
            return
        
        parent_name = child_node.issued_by.lower().strip()
        if not parent_name:
            return
            
        candidates = issued_to_map.get(parent_name, [])
        parent = find_best_parent(child_node, candidates)
        if parent:
            # Avoid cycles
            if parent.key in visited_keys:
                return
            
            # Skip system certificates as parents (system certs don't issue other certs)
            if parent.type == 'system':
                return
                
            # If child is system certificate, parent CA must be in trust store
            # Mark parent as indirectly active because it is part of an active chain
            parent.is_indirectly_active = True
            
            # Recurse
            visited_keys.add(parent.key)
            trace_parents(parent, visited_keys)
            visited_keys.remove(parent.key)

    for cert in list(all_certs.values()):
        if cert.type == 'system' and cert.is_directly_active:
            trace_parents(cert, {cert.key})

    # Step 3: Identify Superceded / Redundant Trusted Certificates
    # These are CAs with the same issuedTo/subject name, but they are expired or unused,
    # while there exists an active/newer unexpired version in the store.
    superceded_certs = []
    
    for name_key, cert_list in issued_to_map.items():
        if len(cert_list) <= 1:
            continue
        
        # Only check trusted certificates
        trusted_candidates = [c for c in cert_list if c.type == 'trusted']
        if len(trusted_candidates) <= 1:
            continue
            
        # Find if there is at least one active, unexpired certificate in this name group
        active_unexpired = [c for c in trusted_candidates if c.is_active and not c.is_expired]
        
        if active_unexpired:
            # Any other certificate in this group that is either expired OR unused (inactive)
            # can be considered superceded/redundant.
            for c in trusted_candidates:
                if c not in active_unexpired:
                    superceded_certs.append(c)

    return all_certs, issued_to_map, issued_by_map, superceded_certs

def shorten_usages(usages):
    mapping = {
        'eap authentication': 'EAP',
        'radius dtls': 'RAD-DTLS',
        'ise messaging service': 'Msg',
        'portal': 'Portal',
        'admin': 'Admin',
        'pxgrid': 'pxGrid',
        'saml': 'SAML'
    }
    shortened = []
    for u in usages:
        u_low = u.lower().strip()
        shortened.append(mapping.get(u_low, u))
    return shortened

def shorten_trusts(trusts):
    mapping = {
        'infrastructure': 'Infra',
        'endpoints': 'Endp',
        'cisco services': 'Cisco',
        'adminauth': 'Admin'
    }
    shortened = []
    for t in trusts:
        t_low = t.lower().strip()
        shortened.append(mapping.get(t_low, t))
    return shortened

def truncate_friendly(friendly_name, max_len=35):
    if not friendly_name:
        return ""
    parts = friendly_name.split('#')
    suffix = ""
    main_name = friendly_name
    if len(parts) > 1:
        if parts[-1].strip().isdigit() or (parts[-1].strip().isalnum() and len(parts[-1].strip()) < 8):
            suffix = "#" + parts[-1].strip()
            main_name = "#".join(parts[:-1]).strip()
            
    if len(main_name) > max_len:
        main_name = main_name[:max_len-3].strip() + "..."
        
    return main_name + (f" {suffix}" if suffix else "")

def print_ascii_tree(all_certs, issued_to_map, issued_by_map, exclude_cisco_services=False, wide=False, node_filter=None):
    """
    Constructs and prints the top-down active trust chains starting from Root CAs down to System Certificates.
    """
    # 1. Find all active root/trust anchors
    active_certs = [c for c in all_certs.values() if c.is_active]
    
    roots = []
    for cert in active_certs:
        if cert.type == 'trusted':
            parent_name = cert.issued_by.lower().strip()
            parents = issued_to_map.get(parent_name, [])
            active_parents = [p for p in parents if p.type == 'trusted' and p.is_active and p.key != cert.key]
            
            if cert.self_signed or not active_parents:
                roots.append(cert)

    # Sort roots by friendly name
    roots.sort(key=lambda x: x.friendly_name)

    print("\n" + "=" * 80)
    if node_filter:
        print(f" ACTIVE CERTIFICATE TRUST CHAINS FOR NODE: {node_filter.upper()} (TOP-DOWN)")
    else:
        print(" ACTIVE CERTIFICATE TRUST CHAINS (TOP-DOWN)")
    print("=" * 80)
    
    if not roots:
        print("No active trust chains found.")
        return

    def get_children(parent_node):
        # System certificates are leaf/endpoint nodes. They never issue other certificates.
        if parent_node.type == 'system':
            return []
            
        # Children are certificates whose issuedBy matches parent_node.issuedTo
        # and are active.
        name_key = parent_node.issued_to.lower().strip()
        candidates = issued_by_map.get(name_key, [])
        children = []
        for c in candidates:
            if c.key == parent_node.key:
                continue
            if c.self_signed:
                # A self-signed certificate is a trust anchor/root, not a child
                continue
            if c.is_active:
                # Only add if parent_node is the selected best parent for c
                parent_name = c.issued_by.lower().strip()
                parent_candidates = issued_to_map.get(parent_name, [])
                best_parent = find_best_parent(c, parent_candidates)
                if best_parent and best_parent.key == parent_node.key:
                    children.append(c)
        # Sort children: trusted first, then system. Within each, sort by name/friendly name.
        children.sort(key=lambda x: (0 if x.type == 'trusted' else 1, x.node_name or '', x.friendly_name))
        return children

    def has_node_leaves(node):
        if node_filter is None:
            return True
        if node.type == 'system':
            return node.node_name.lower().strip() == node_filter.lower().strip()
        
        # It's a trusted CA. Check if any children lead to the target node
        children = get_children(node)
        return any(has_node_leaves(child) for child in children)

    # Filter roots to only those that lead to target node (if filtered)
    if node_filter:
        roots = [r for r in roots if has_node_leaves(r)]

    if not roots:
        print(f"No active trust chains found leading to node: {node_filter}")
        return

    def render_tree(node, prefix="", is_last=True, visited_keys=None):
        if visited_keys is None:
            visited_keys = set()
            
        friendly_name = node.friendly_name
        if not wide:
            friendly_name = truncate_friendly(friendly_name, 35)

        # Format node details
        if node.type == 'system':
            usages = shorten_usages(node.usages) if not wide else node.usages
            usages_str = ", ".join(usages)
            days_left = ""
            if node.expiration_date:
                days = (node.expiration_date - datetime.now()).days
                days_left = f" ({days}d left)"
            node_label = f"\033[92m[Node]\033[0m {node.node_name} | {friendly_name} [{usages_str}]{days_left}"
        else:
            trusts = shorten_trusts(node.trusted_for) if not wide else node.trusted_for
            trust_str = ", ".join(trusts) if trusts else "None"
            status_str = f" [{node.status}]" if node.status != 'Enabled' else ""
            days_left = ""
            if node.expiration_date:
                days = (node.expiration_date - datetime.now()).days
                days_left = f" ({days}d left)"
            node_label = f"\033[96m[CA]\033[0m {friendly_name} [{trust_str}]{status_str}{days_left}"

        # Print current node
        marker = "└── " if is_last else "├── "
        
        # Check if already visited in this path (loop detection)
        if node.key in visited_keys:
            print(f"{prefix}{marker}{node_label} \033[91m[Circular Loop Detected]\033[0m")
            return

        print(f"{prefix}{marker}{node_label}")

        # Recurse children
        visited_keys.add(node.key)
        children = get_children(node)
        if node_filter:
            children = [c for c in children if has_node_leaves(c)]
            
        new_prefix = prefix + ("    " if is_last else "│   ")
        for idx, child in enumerate(children):
            render_tree(child, new_prefix, is_last=(idx == len(children) - 1), visited_keys=visited_keys)
        visited_keys.remove(node.key)

    for idx, r in enumerate(roots):
        # Optionally exclude roots that are ONLY trusted for Cisco Services (built-ins) and have no children
        if exclude_cisco_services and r.trusted_for == ['Cisco Services']:
            children = get_children(r)
            if not children:
                continue
                
        render_tree(r, is_last=(idx == len(roots) - 1))
    print()

def print_audit_report(all_certs, superceded_certs, exclude_cisco_services=False, wide=False, node_filter=None):
    """
    Prints a detailed audit report listing orphans, expired certificates, and superceded CAs.
    """
    sys_certs = [c for c in all_certs.values() if c.type == 'system']
    trusted_certs = [c for c in all_certs.values() if c.type == 'trusted']

    if node_filter:
        sys_certs = [c for c in sys_certs if c.node_name.lower().strip() == node_filter.lower().strip()]

    # 1. Orphan System Certificates (usages == 'Not in use' or empty)
    orphan_sys = [c for c in sys_certs if not c.is_active]
    orphan_sys.sort(key=lambda x: (x.node_name, x.friendly_name))

    # 2. Expired Trusted Certificates
    expired_trusted = [c for c in trusted_certs if c.is_expired]
    expired_trusted.sort(key=lambda x: x.friendly_name)

    # 3. Disabled Trusted Certificates
    disabled_trusted = [c for c in trusted_certs if c.status.lower() == 'disabled' and c not in expired_trusted]
    disabled_trusted.sort(key=lambda x: x.friendly_name)

    # 4. Unused Trusted Certificates (no active chains, no active trust flags, and not expired/disabled)
    unused_trusted = []
    for c in trusted_certs:
        if c.is_active:
            continue
        if c in expired_trusted or c in disabled_trusted:
            continue
        # Optionally exclude Cisco Services built-ins
        if exclude_cisco_services and c.trusted_for == ['Cisco Services']:
            continue
        unused_trusted.append(c)
    unused_trusted.sort(key=lambda x: x.friendly_name)

    # Print Summary Table
    print("=" * 80)
    print(" CERTIFICATE PORTFOLIO SUMMARY")
    print("=" * 80)
    print(f" Total System Certificates:      {len(sys_certs)}")
    print(f"   - Active (In Use):           {len(sys_certs) - len(orphan_sys)}")
    print(f"   - Orphaned (Not in Use):      {len(orphan_sys)}")
    print(f" Total Trusted Certificates:     {len(trusted_certs)}")
    print(f"   - Active/In Chain:           {len([c for c in trusted_certs if c.is_active])}")
    print(f"   - Unused/Orphaned:           {len(unused_trusted)}")
    print(f"   - Expired:                   {len(expired_trusted)}")
    print(f"   - Disabled (Unexpired):      {len(disabled_trusted)}")
    print(f"   - Superceded/Duplicate CAs:  {len(superceded_certs)}")
    print("=" * 80)

    # Section: Orphaned System Certificates
    print("\n\033[93m[!] ORPHAN SYSTEM CERTIFICATES (NOT BOUND TO SERVICES)\033[0m")
    print("These are system certificates installed on specific nodes but not mapped to any active roles.")
    if orphan_sys:
        for idx, c in enumerate(orphan_sys):
            days_str = "Expired"
            if c.expiration_date:
                days = (c.expiration_date - datetime.now()).days
                days_str = f"Expires in {days}d" if days >= 0 else f"Expired ({abs(days)}d ago)"
            friendly_name = c.friendly_name if wide else truncate_friendly(c.friendly_name, 45)
            print(f" {idx+1:2d}. [\033[91m{c.node_name}\033[0m] {friendly_name}")
            print(f"     ID: {c.id} | {days_str} | Serial: {c.serial_number}")
    else:
        print("  None. All system certificates are bound to services.")

    # Section: Expired Trusted Certificates
    print("\n\033[91m[!] EXPIRED TRUSTED CERTIFICATES (IN TRUST STORE)\033[0m")
    print("These certificates are expired and should be removed from the Trust Store to maintain security.")
    if expired_trusted:
        for idx, c in enumerate(expired_trusted):
            days_ago = (datetime.now() - c.expiration_date).days if c.expiration_date else 0
            chain_status = "\033[91mIN ACTIVE CHAIN\033[0m" if c.is_indirectly_active else "Unused"
            friendly_name = c.friendly_name if wide else truncate_friendly(c.friendly_name, 45)
            print(f" {idx+1:2d}. {friendly_name}")
            print(f"     ID: {c.id} | Expired {days_ago}d ago ({c.expiration_date_str}) | Status: {c.status} | Chain: {chain_status}")
    else:
        print("  None. No expired trusted certificates found.")

    # Section: Superceded / Redundant Trusted Certificates
    print("\n\033[93m[!] SUPERCEDED / DUPLICATE TRUST STORE CERTIFICATES\033[0m")
    print("These are older or redundant versions of CAs that are already replaced by a newer active version.")
    if superceded_certs:
        for idx, c in enumerate(superceded_certs):
            days_left = ""
            if c.expiration_date:
                days = (c.expiration_date - datetime.now()).days
                days_left = f" ({days}d left)" if days >= 0 else f" (Expired {abs(days)}d ago)"
            chain_status = "Active Chain" if c.is_indirectly_active else "Unused"
            friendly_name = c.friendly_name if wide else truncate_friendly(c.friendly_name, 45)
            print(f" {idx+1:2d}. {friendly_name}{days_left}")
            print(f"     ID: {c.id} | Status: {c.status} | Chain: {chain_status} | Serial: {c.serial_number}")
    else:
        print("  None. No duplicate CA certificates found.")

    # Section: Unused/Orphan Trusted Certificates
    print("\n\033[93m[!] UNUSED / ORPHAN TRUSTED CERTIFICATES\033[0m")
    print("These certificates are enabled but not part of any active system certificate chain, and have no active usages.")
    if unused_trusted:
        for idx, c in enumerate(unused_trusted):
            days_left = ""
            if c.expiration_date:
                days = (c.expiration_date - datetime.now()).days
                days_left = f" ({days}d left)"
            trusts = shorten_trusts(c.trusted_for) if not wide else c.trusted_for
            trust_str = ", ".join(trusts) if trusts else "None"
            friendly_name = c.friendly_name if wide else truncate_friendly(c.friendly_name, 45)
            print(f" {idx+1:2d}. {friendly_name}{days_left}")
            print(f"     ID: {c.id} | Trusts: {trust_str} | Status: {c.status} | Serial: {c.serial_number}")
    else:
        print("  None. All enabled trusted certificates are either in use or excluded.")

    # Section: Disabled Trusted Certificates
    print("\n\033[90m[-] DISABLED TRUSTED CERTIFICATES\033[0m")
    print("These certificates are explicitly disabled in the Trust Store.")
    if disabled_trusted:
        for idx, c in enumerate(disabled_trusted):
            days_left = ""
            if c.expiration_date:
                days = (c.expiration_date - datetime.now()).days
                days_left = f" ({days}d left)"
            friendly_name = c.friendly_name if wide else truncate_friendly(c.friendly_name, 45)
            print(f" {idx+1:2d}. {friendly_name}{days_left}")
            print(f"     ID: {c.id} | Serial: {c.serial_number}")
    else:
        print("  None.")

def print_usage_guide():
    guide = """
Cisco ISE Certificate Dependency and Orphan Analyzer

This script performs a top-down trust chain analysis to discover orphaned and redundant certificates.

Usage:
  python3 check_ise_orphans.py -H <host> -u <user> -p <password> [options]

Arguments:
  -H, --host        Cisco ISE Primary PAN hostname or IP address (Required)
  -u, --user        ISE ERS or OpenAPI Admin username (Required)
  -p, --password    ISE ERS or OpenAPI Admin password (Required)
  --ssl-verify      Enable SSL certificate verification (Disabled by default)
  -x, --exclude-cisco-services
                    Exclude built-in root CAs that are only used for Cisco Services trust.
                    This reduces noise by hiding certificates like VeriSign G5, Thawte, etc.
  -N, --node        Target a specific node in the deployment for a focused audit and trust chain rendering.
  -w, --wide        Display full certificate names and long fields (disables auto-truncation for narrow screens).
  -v, --verbose     Print detailed discovery logs to stdout.
"""
    print(guide, file=sys.stderr)

def main():
    load_env_file()
    
    host_default = os.environ.get('ISE_HOST')
    user_default = os.environ.get('ISE_USER')
    password_default = os.environ.get('ISE_PASSWORD')
    ssl_verify_default = os.environ.get('ISE_SSL_VERIFY', '').lower() in ('true', '1', 'yes')
    verbose_default = os.environ.get('ISE_VERBOSE', '').lower() in ('true', '1', 'yes')

    if len(sys.argv) == 1 and not (host_default and user_default and password_default):
        print_usage_guide()
        sys.exit(3)

    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument('-H', '--host', required=host_default is None, default=host_default, help='Cisco ISE Primary PAN hostname/IP')
    parser.add_argument('-u', '--user', required=user_default is None, default=user_default, help='API Admin username')
    parser.add_argument('-p', '--password', required=password_default is None, default=password_default, help='API Admin password')
    parser.add_argument('--ssl-verify', action='store_true', default=ssl_verify_default, help='Enable SSL certificate verification')
    parser.add_argument('-x', '--exclude-cisco-services', action='store_true', help='Exclude/hide built-in Cisco Services certificates')
    parser.add_argument('-N', '--node', help='Target a specific node for focused audit')
    parser.add_argument('-w', '--wide', action='store_true', help='Disable name truncation and display long texts')
    parser.add_argument('-v', '--verbose', action='store_true', default=verbose_default, help='Print detailed diagnostic output to stdout')

    args = parser.parse_args()

    if not args.verbose:
        warnings.filterwarnings("ignore")

    try:
        if args.verbose:
            print("[*] Launching Cisco ISE Trust Chain and Orphan Analyzer...")
            
        all_certs = build_trust_graph(
            host=args.host,
            user=args.user,
            password=args.password,
            ssl_verify=args.ssl_verify,
            verbose=args.verbose
        )
        
        if not all_certs:
            print("Error: No certificates could be fetched from Cisco ISE.", file=sys.stderr)
            sys.exit(2)
            
        all_certs, issued_to_map, issued_by_map, superceded_certs = analyze_dependencies(all_certs)
        
        print_ascii_tree(all_certs, issued_to_map, issued_by_map, exclude_cisco_services=args.exclude_cisco_services, wide=args.wide, node_filter=args.node)
        
        print_audit_report(all_certs, superceded_certs, exclude_cisco_services=args.exclude_cisco_services, wide=args.wide, node_filter=args.node)
        
        sys.exit(0)
        
    except Exception as e:
        if args.verbose:
            import traceback
            traceback.print_exc()
        else:
            print(f"Error: An unexpected internal error occurred: {e}", file=sys.stderr)
        sys.exit(3)

if __name__ == "__main__":
    main()
