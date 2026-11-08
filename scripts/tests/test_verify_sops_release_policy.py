"""Security-negative tests; generated age strings are public fixtures, NOT key custody."""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / 'verify-sops-release-policy.py'
ALPHABET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
GEN = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)


def checksum(values):
    state = 1
    for value in values:
        top = state >> 25
        state = ((state & 0x1FFFFFF) << 5) ^ value
        for i, generator in enumerate(GEN):
            if (top >> i) & 1:
                state ^= generator
    return state


def fixture_recipient(seed):
    # Encoding fixture only. No production age private key exists for these values.
    source = bytes([seed]) * 32
    data = []
    accumulator = bits = 0
    for byte in source:
        accumulator = (accumulator << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            data.append((accumulator >> bits) & 31)
    if bits:
        data.append((accumulator << (5 - bits)) & 31)
    polymod = checksum([3, 3, 3, 0, 1, 7, 5] + data + [0] * 6) ^ 1
    trailing = [(polymod >> (5 * (5 - i))) & 31 for i in range(6)]
    return 'age1' + ''.join(ALPHABET[v] for v in data + trailing)


DEV, PROD1, PROD2 = (fixture_recipient(i) for i in (1, 2, 3))


def policy(dev=DEV, prod=(PROD1, PROD2)):
    return ("creation_rules:\n"
            "  - path_regex: ^env/enc/dev\\.env\\.enc$\n"
            "    age:\n" + ''.join(f"      - {v}\n" for v in [dev]) +
            "  - path_regex: ^env/enc/prod\\.env\\.enc$\n"
            "    age:\n" + ''.join(f"      - {v}\n" for v in prod))


class PolicyTests(unittest.TestCase):
    def check(self, text, payload=(PROD1, PROD2), success=False):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            (base / '.sops.yaml').write_text(text, encoding='utf-8')
            (base / 'env/enc').mkdir(parents=True)
            (base / 'env/enc/prod.env.enc').write_text(''.join(
                f'sops_age__list_{i}__map_enc=-----BEGIN AGE ENCRYPTED FILE-----\n'
                f'sops_age__list_{i}__map_recipient={value}\n'
                for i, value in enumerate(payload)) +
                'sops_mac=ENC[AES256_GCM,data:fixture]\n', encoding='utf-8')
            p = subprocess.run([sys.executable, str(SCRIPT), str(base / '.sops.yaml'), 'prod'],
                               capture_output=True, text=True, check=False)
            self.assertEqual(p.returncode == 0, success, p.stderr)
            return p.stderr

    def test_two_distinct_recipient_policy_and_matching_payload_pass(self):
        self.check(policy(), success=True)

    def test_bootstrap_one_prod_recipient_fails_closed(self):
        self.assertIn('at least two', self.check(policy(prod=(DEV,)), payload=(DEV,)))

    def test_shared_only_dev_prod_set_fails_closed(self):
        self.check(policy(dev=DEV, prod=(DEV, DEV)))

    def test_checksum_typo_rejected(self):
        self.assertIn('invalid age recipient', self.check(policy(prod=(PROD1[:-1] + 'p', PROD2))))

    def test_noncanonical_padding_with_valid_checksum_rejected(self):
        # Recalculate a legitimate checksum after changing one otherwise
        # hidden padding bit: checksum validation alone is insufficient.
        values = [ALPHABET.index(ch) for ch in PROD1[4:]]
        data = values[:52]
        self.assertEqual(data[51] & 0b1111, 0)
        data[51] |= 0b0100
        polymod = checksum([3, 3, 3, 0, 1, 7, 5] + data + [0] * 6) ^ 1
        trailing = [(polymod >> (5 * (5 - i))) & 31 for i in range(6)]
        malformed = 'age1' + ''.join(ALPHABET[v] for v in data + trailing)
        self.assertIn('invalid age recipient', self.check(policy(prod=(malformed, PROD2))))

    def test_duplicate_prod_rule_rejected(self):
        extra = '\n  - path_regex: ^env/enc/prod\\.env\\.enc$\n    age:\n      - ' + PROD2 + '\n'
        self.assertIn('duplicate exact prod', self.check(policy() + extra))

    def test_unknown_catchall_rule_rejected(self):
        extra = '\n  - path_regex: .*\n    age:\n      - ' + PROD2 + '\n'
        self.assertIn('unrecognized', self.check(policy() + extra))

    def test_duplicate_root_rejected(self):
        self.assertIn("duplicate creation_rules root",
                      self.check(policy() + "\ncreation_rules:\n"))

    def test_unsupported_yaml_merge_anchor_rejected(self):
        self.assertIn("unrecognized SOPS creation rule",
                      self.check(policy() + "\n  <<: *inject\n"))

    def test_unsupported_key_group_rejected(self):
        self.assertIn("unsupported SOPS policy field",
                      self.check(policy().replace("    age:", "    key_groups:")))

    def test_invalid_environment_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            policy_path = Path(root) / '.sops.yaml'
            policy_path.write_text(policy(), encoding='utf-8')
            p = subprocess.run([sys.executable, str(SCRIPT), str(policy_path), 'production'],
                               capture_output=True, text=True, check=False)
            self.assertNotEqual(p.returncode, 0)
            self.assertIn('unsupported environment', p.stderr)

    def test_unrekeyed_prod_payload_rejected(self):
        self.assertIn('sops updatekeys', self.check(policy(), payload=(DEV,)))

    def test_duplicate_age_key_rejected(self):
        self.assertIn('duplicate', self.check(policy(prod=(PROD1, PROD1, PROD2))))

    def check_custom_payload_is_rejected(self, payload_text, expected):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            (base / '.sops.yaml').write_text(policy(), encoding='utf-8')
            (base / 'env/enc').mkdir(parents=True)
            (base / 'env/enc/prod.env.enc').write_text(payload_text, encoding='utf-8')
            p = subprocess.run([sys.executable, str(SCRIPT), str(base / '.sops.yaml'), 'prod'],
                               capture_output=True, text=True, check=False)
            self.assertNotEqual(p.returncode, 0, 'invalid SOPS payload must fail closed')
            self.assertIn(expected, p.stderr)

    def test_missing_production_mac_rejected(self):
        payload = ''.join(
            f'sops_age__list_{i}__map_enc=-----BEGIN AGE ENCRYPTED FILE-----\n'
            f'sops_age__list_{i}__map_recipient={recipient}\n'
            for i, recipient in enumerate((PROD1, PROD2)))
        self.check_custom_payload_is_rejected(payload, 'SOPS MAC or per-recipient')

    def test_missing_production_envelope_rejected(self):
        payload = ''.join(
            f'sops_age__list_{i}__map_recipient={recipient}\n'
            for i, recipient in enumerate((PROD1, PROD2)))
        self.check_custom_payload_is_rejected(
            payload + 'sops_mac=ENC[AES256_GCM,data:fixture]\n',
            'SOPS MAC or per-recipient')

    def test_duplicate_production_envelope_rejected(self):
        payload = ('sops_age__list_0__map_enc=-----BEGIN AGE ENCRYPTED FILE-----\n' * 2 +
                   f'sops_age__list_0__map_recipient={PROD1}\n' +
                   'sops_age__list_1__map_enc=-----BEGIN AGE ENCRYPTED FILE-----\n' +
                   f'sops_age__list_1__map_recipient={PROD2}\n' +
                   'sops_mac=ENC[AES256_GCM,data:fixture]\n')
        self.check_custom_payload_is_rejected(payload, 'missing or invalid')

    def test_unknown_sops_age_metadata_rejected(self):
        payload = ''.join(
            f'sops_age__list_{i}__map_enc=-----BEGIN AGE ENCRYPTED FILE-----\n'
            f'sops_age__list_{i}__map_recipient={recipient}\n'
            for i, recipient in enumerate((PROD1, PROD2)))
        self.check_custom_payload_is_rejected(
            payload + 'sops_age__list_2__map_surprise=ignored\n'
                      'sops_mac=ENC[AES256_GCM,data:fixture]\n',
            'unrecognized SOPS age metadata')

    def test_non_contiguous_payload_indices_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            (base / '.sops.yaml').write_text(policy(), encoding='utf-8')
            (base / 'env/enc').mkdir(parents=True)
            (base / 'env/enc/prod.env.enc').write_text(
                'sops_age__list_0__map_enc=-----BEGIN AGE ENCRYPTED FILE-----\n'
                f'sops_age__list_0__map_recipient={PROD1}\n'
                'sops_age__list_2__map_enc=-----BEGIN AGE ENCRYPTED FILE-----\n'
                f'sops_age__list_2__map_recipient={PROD2}\n'
                'sops_mac=ENC[AES256_GCM,data:fixture]\n', encoding='utf-8')
            p = subprocess.run([sys.executable, str(SCRIPT), str(base / '.sops.yaml'), 'prod'],
                               capture_output=True, text=True, check=False)
            self.assertNotEqual(p.returncode, 0)
            self.assertIn('noncontiguous', p.stderr)


if __name__ == '__main__':
    unittest.main()
