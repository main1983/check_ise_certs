import sys
import os
import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

# Ensure local path is available
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import check_ise_orphans
from check_ise_orphans import CertificateNode, parse_expiry_date, analyze_dependencies

class TestOrphanAnalyzer(unittest.TestCase):

    def test_parse_expiry_date(self):
        # ISO format
        d1 = parse_expiry_date("2026-06-03T16:05:36.123Z")
        self.assertIsNotNone(d1)
        self.assertEqual(d1.year, 2026)
        self.assertEqual(d1.month, 6)
        
        # Space separated format with timezone abbreviation (e.g. CEST)
        d2 = parse_expiry_date("Thu Sep 03 10:11:48 CEST 2026")
        self.assertIsNotNone(d2)
        self.assertEqual(d2.year, 2026)
        self.assertEqual(d2.month, 9)
        self.assertEqual(d2.day, 3)
        self.assertEqual(d2.hour, 10)
        self.assertEqual(d2.minute, 11)
        self.assertEqual(d2.second, 48)

        # Space separated format with CET
        d3 = parse_expiry_date("Mon Jan 15 22:00:00 CET 2024")
        self.assertIsNotNone(d3)
        self.assertEqual(d3.year, 2024)
        self.assertEqual(d3.month, 1)
        
        # Invalid format
        self.assertIsNone(parse_expiry_date("InvalidDate"))
        self.assertIsNone(parse_expiry_date(None))

    def test_certificate_node_initialization(self):
        # Test system certificate initialization
        sys_cert_raw = {
            "id": "sys-1",
            "friendlyName": "System Cert 1",
            "usedBy": "Admin, Portal",
            "selfSigned": False
        }
        node = CertificateNode(
            cert_type='system',
            id_val='sys-1',
            friendly_name='System Cert 1',
            issued_to='Node1.domain.com',
            issued_by='SubCA-1',
            expiration_date_str='2027-12-31 23:59:59',
            raw_data=sys_cert_raw,
            node_name='Node1'
        )
        self.assertEqual(node.type, 'system')
        self.assertEqual(node.usages, ['Admin', 'Portal'])
        self.assertEqual(node.node_name, 'Node1')
        self.assertTrue(node.is_active)
        self.assertFalse(node.self_signed)
        self.assertFalse(node.is_expired)

        # Test trusted certificate initialization
        trust_cert_raw = {
            "id": "trust-1",
            "friendlyName": "Root CA",
            "trustedFor": "Infrastructure,Endpoints",
            "status": "Enabled",
            "selfSigned": True
        }
        node_t = CertificateNode(
            cert_type='trusted',
            id_val='trust-1',
            friendly_name='Root CA',
            issued_to='RootCA',
            issued_by='RootCA',
            expiration_date_str='2035-01-01 00:00:00',
            raw_data=trust_cert_raw
        )
        self.assertEqual(node_t.type, 'trusted')
        self.assertEqual(node_t.trusted_for, ['Infrastructure', 'Endpoints'])
        self.assertTrue(node_t.self_signed)
        self.assertEqual(node_t.status, 'Enabled')

    def test_dependency_analysis_flow(self):
        # Create a mock set of certificates:
        # RootCA -> SubCA -> LeafCert (Active system cert)
        # UnusedRoot -> UnusedSub -> InactiveLeaf (Orphan system cert)
        # StandaloneCA (Trusted, active flags, no children)
        # SupercededCA_v1 (expired) and SupercededCA_v2 (active, same name)
        
        future_date = (datetime.now() + timedelta(days=365)).strftime("%Y-%m-%d %H:%M:%S")
        past_date = (datetime.now() - timedelta(days=10)).strftime("%Y-%m-%d %H:%M:%S")
        far_future_date = (datetime.now() + timedelta(days=1000)).strftime("%Y-%m-%d %H:%M:%S")

        all_certs = {}
        
        # 1. Active path
        # RootCA
        root = CertificateNode('trusted', 'root-id', 'Active Root CA', 'RootCA', 'RootCA', future_date, {'status': 'Enabled', 'selfSigned': True})
        # SubCA
        sub = CertificateNode('trusted', 'sub-id', 'Active Sub CA', 'SubCA', 'RootCA', future_date, {'status': 'Enabled'})
        # Active Leaf Cert (System)
        leaf = CertificateNode('system', 'leaf-id', 'Active System Cert', 'node1.domain.com', 'SubCA', future_date, {'usedBy': 'Admin, RADIUS'}, 'node1')
        
        # 2. Orphan path
        # Orphan CA
        orphan_ca = CertificateNode('trusted', 'orphan-ca-id', 'Orphan Root CA', 'OrphanCA', 'OrphanCA', future_date, {'status': 'Enabled', 'selfSigned': True})
        # Inactive System Cert
        inactive_leaf = CertificateNode('system', 'inactive-leaf-id', 'Inactive System Cert', 'node1.domain.com', 'OrphanCA', future_date, {'usedBy': 'Not in use'}, 'node1')
        
        # 3. Standalone Active CA (no children, but has trust flags enabled)
        standalone = CertificateNode('trusted', 'standalone-id', 'Standalone Trust Anchor', 'StandaloneCA', 'StandaloneCA', future_date, {'status': 'Enabled', 'trustedFor': 'ClientAuth', 'selfSigned': True})
        
        # 4. Superceded CA versions
        # Older version of Enterprise CA (Expired)
        superceded_v1 = CertificateNode('trusted', 'super-v1-id', 'Enterprise CA Old', 'Enterprise CA', 'Enterprise CA', past_date, {'status': 'Enabled', 'selfSigned': True})
        # Newer version of Enterprise CA (Active & unexpired)
        superceded_v2 = CertificateNode('trusted', 'super-v2-id', 'Enterprise CA New', 'Enterprise CA', 'Enterprise CA', far_future_date, {'status': 'Enabled', 'selfSigned': True})
        
        # System cert using the Enterprise CA
        ent_leaf = CertificateNode('system', 'ent-leaf-id', 'Enterprise System Cert', 'node1.domain.com', 'Enterprise CA', future_date, {'usedBy': 'EAP Authentication'}, 'node1')

        # Add all to list
        for c in [root, sub, leaf, orphan_ca, inactive_leaf, standalone, superceded_v1, superceded_v2, ent_leaf]:
            all_certs[c.key] = c
            
        # Run dependency analysis
        all_certs, issued_to_map, issued_by_map, superceded_certs = analyze_dependencies(all_certs)
        
        # Verify active path tracing:
        self.assertTrue(leaf.is_directly_active)
        self.assertTrue(sub.is_indirectly_active)
        self.assertTrue(root.is_indirectly_active)
        
        # Verify standalone active:
        self.assertTrue(standalone.is_active)
        
        # Verify orphan path is NOT active:
        self.assertFalse(inactive_leaf.is_active)
        self.assertFalse(orphan_ca.is_active)
        self.assertFalse(orphan_ca.is_indirectly_active)
        
        # Verify superceded check:
        # superceded_v1 is expired and has same CN "Enterprise CA" as active/newer superceded_v2.
        # It should be in superceded_certs.
        self.assertIn(superceded_v1, superceded_certs)
        self.assertNotIn(superceded_v2, superceded_certs)

    def test_dependency_loops_and_missing_parents(self):
        future_date = (datetime.now() + timedelta(days=365)).strftime("%Y-%m-%d %H:%M:%S")
        all_certs = {}
        
        # Loop: CA_A issued by CA_B, CA_B issued by CA_A (invalid but tests robustness)
        ca_a = CertificateNode('trusted', 'ca-a', 'CA A', 'CA_A', 'CA_B', future_date, {'status': 'Enabled'})
        ca_b = CertificateNode('trusted', 'ca-b', 'CA B', 'CA_B', 'CA_A', future_date, {'status': 'Enabled'})
        leaf = CertificateNode('system', 'leaf', 'Leaf Cert', 'node1', 'CA_A', future_date, {'usedBy': 'Admin'}, 'node1')
        
        # Missing Parent: Leaf issued by CA_Missing (which is not in the store)
        leaf_missing = CertificateNode('system', 'leaf-missing', 'Leaf Missing Parent', 'node1', 'CA_Missing', future_date, {'usedBy': 'Portal'}, 'node1')
        
        for c in [ca_a, ca_b, leaf, leaf_missing]:
            all_certs[c.key] = c
            
        # This call should complete successfully without infinite recursion
        all_certs, issued_to_map, issued_by_map, superceded_certs = analyze_dependencies(all_certs)
        
        # Verify that tracing marked ca_a and ca_b as active (since they link to active leaf)
        self.assertTrue(ca_a.is_indirectly_active)
        self.assertTrue(ca_b.is_indirectly_active)
        self.assertTrue(leaf_missing.is_directly_active)

    @patch('sys.stdout')
    def test_reporting_methods_run_successfully(self, mock_stdout):
        # Verify tree printer and report generator don't crash
        future_date = (datetime.now() + timedelta(days=365)).strftime("%Y-%m-%d %H:%M:%S")
        all_certs = {}
        root = CertificateNode('trusted', 'root', 'Root CA', 'RootCA', 'RootCA', future_date, {'status': 'Enabled', 'selfSigned': True})
        leaf = CertificateNode('system', 'leaf', 'System Cert', 'node1', 'RootCA', future_date, {'usedBy': 'Admin'}, 'node1')
        
        for c in [root, leaf]:
            all_certs[c.key] = c
            
        all_certs, issued_to_map, issued_by_map, superceded_certs = analyze_dependencies(all_certs)
        
        # Run tree visualization
        check_ise_orphans.print_ascii_tree(all_certs, issued_to_map, issued_by_map, exclude_cisco_services=False)
        # Run report printing
        check_ise_orphans.print_audit_report(all_certs, superceded_certs, exclude_cisco_services=False)

    def test_shortening_and_truncation_helpers(self):
        # Test usage shortening
        usages = ["EAP Authentication", "RADIUS DTLS", "Portal", "CustomUsage"]
        short_u = check_ise_orphans.shorten_usages(usages)
        self.assertEqual(short_u, ["EAP", "RAD-DTLS", "Portal", "CustomUsage"])

        # Test trust shortening
        trusts = ["Infrastructure", "Endpoints", "Cisco Services", "AdminAuth"]
        short_t = check_ise_orphans.shorten_trusts(trusts)
        self.assertEqual(short_t, ["Infra", "Endp", "Cisco", "Admin"])

        # Test friendly name truncation with unique index suffix
        long_name_with_suffix = "CN=VeryLongNameThatExceedsTheLimitForDisplayPurpose#00055"
        trunc_name = check_ise_orphans.truncate_friendly(long_name_with_suffix, max_len=20)
        self.assertTrue(trunc_name.endswith("#00055"))
        self.assertIn("...", trunc_name)

        short_name = "ShortName#123"
        trunc_short = check_ise_orphans.truncate_friendly(short_name, max_len=20)
        self.assertEqual(trunc_short, "ShortName #123")

    def test_node_filtering(self):
        # Test the node-filtering logic in print_ascii_tree and print_audit_report
        future_date = (datetime.now() + timedelta(days=365)).strftime("%Y-%m-%d %H:%M:%S")
        all_certs = {}
        
        # Root CA
        root = CertificateNode('trusted', 'root', 'Root CA', 'RootCA', 'RootCA', future_date, {'status': 'Enabled', 'selfSigned': True})
        
        # Sub CA 1 (leads to node1)
        sub1 = CertificateNode('trusted', 'sub1', 'Sub CA 1', 'Sub1', 'RootCA', future_date, {'status': 'Enabled'})
        leaf1 = CertificateNode('system', 'leaf1', 'System Cert 1', 'node1', 'Sub1', future_date, {'usedBy': 'Admin'}, 'node1')
        
        # Sub CA 2 (leads to node2)
        sub2 = CertificateNode('trusted', 'sub2', 'Sub CA 2', 'Sub2', 'RootCA', future_date, {'status': 'Enabled'})
        leaf2 = CertificateNode('system', 'leaf2', 'System Cert 2', 'node2', 'Sub2', future_date, {'usedBy': 'Admin'}, 'node2')
        
        # Add to collection
        for c in [root, sub1, leaf1, sub2, leaf2]:
            all_certs[c.key] = c
            
        all_certs, issued_to_map, issued_by_map, superceded_certs = analyze_dependencies(all_certs)
        
        # We can capture stdout to verify what is printed
        import io
        from contextlib import redirect_stdout
        
        # Test printing tree with node_filter='node1'
        f = io.StringIO()
        with redirect_stdout(f):
            check_ise_orphans.print_ascii_tree(all_certs, issued_to_map, issued_by_map, node_filter='node1')
        output = f.getvalue()
        
        self.assertIn("node1", output)
        self.assertIn("Sub CA 1", output)
        self.assertNotIn("node2", output)
        self.assertNotIn("Sub CA 2", output)

        # Test printing tree with node_filter='node2'
        f = io.StringIO()
        with redirect_stdout(f):
            check_ise_orphans.print_ascii_tree(all_certs, issued_to_map, issued_by_map, node_filter='node2')
        output = f.getvalue()
        
        self.assertIn("node2", output)
        self.assertIn("Sub CA 2", output)
        self.assertNotIn("node1", output)
        self.assertNotIn("Sub CA 1", output)

    def test_root_ca_loop_prevention(self):
        future_date = (datetime.now() + timedelta(days=365)).strftime("%Y-%m-%d %H:%M:%S")
        all_certs = {}
        
        # Two root CAs with same subject
        root1 = CertificateNode('trusted', 'root1', 'Root CA v1', 'RootCA', 'RootCA', future_date, {'status': 'Enabled', 'selfSigned': True})
        root2 = CertificateNode('trusted', 'root2', 'Root CA v2', 'RootCA', 'RootCA', future_date, {'status': 'Enabled', 'selfSigned': True})
        
        for c in [root1, root2]:
            all_certs[c.key] = c
            
        all_certs, issued_to_map, issued_by_map, superceded_certs = analyze_dependencies(all_certs)
        
        import io
        from contextlib import redirect_stdout
        f = io.StringIO()
        with redirect_stdout(f):
            check_ise_orphans.print_ascii_tree(all_certs, issued_to_map, issued_by_map)
        output = f.getvalue()
        
        self.assertNotIn("Circular Loop Detected", output)

if __name__ == '__main__':
    unittest.main()
