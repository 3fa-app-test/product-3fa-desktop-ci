#!/usr/bin/env python3
"""Fail closed on invalid or unrekeyed production SOPS age recipient policy.

This verifies public-key encoding and file metadata, NOT independent key custody.
Custodians must verify ownership through an out-of-band operational review.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ENV_RULE = re.compile(r"^\s*-\s*path_regex:\s*(?P<value>.+?)\s*$")
LIST_ITEM = re.compile(r"^\s*-\s*(?P<value>\S+)\s*$")
SOPS_AGE_RECIPIENT = re.compile(r"^sops_age__list_(\d+)__map_recipient=(\S+)$")
EXACT_RULES = {
    r"^env/enc/dev\.env\.enc$": "dev",
    r"^env/enc/prod\.env\.enc$": "prod",
}
BECH32_CHARS = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_GEN = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)


def fail(message: str) -> "NoReturn":
    print(f"production SOPS policy: {message}", file=sys.stderr)
    raise SystemExit(1)


def valid_age_recipient(value: str) -> bool:
    """Check canonical age X25519 bech32 encoding, not possession of its key."""
    if len(value) != 62 or not value.startswith("age1"):
        return False
    payload = value[4:]
    if any(ch not in BECH32_CHARS for ch in payload):
        return False
    # The age X25519 public key is 32 bytes, encoded in 52 five-bit groups;
    # the final four padding bits must be zero, followed by six checksum groups.
    data = [BECH32_CHARS.index(ch) for ch in payload]
    if (data[51] & 0b1111) != 0:
        return False
    checksum = 1
    for item in [3, 3, 3, 0, 1, 7, 5] + data:  # bech32 HRP expansion of 'age'
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ item
        for i, generator in enumerate(BECH32_GEN):
            if (top >> i) & 1:
                checksum ^= generator
    return checksum == 1


def parse_recipients(path: Path) -> dict[str, set[str]]:
    recipients: dict[str, set[str]] = {"dev": set(), "prod": set()}
    seen_rules: set[str] = set()
    current: str | None = None
    in_age = False
    rule_indent = age_indent = -1

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        rule_match = ENV_RULE.match(raw_line)
        if rule_match:
            value = rule_match.group("value").strip().strip("\"'")
            current = EXACT_RULES.get(value)
            if current is None:
                fail("unrecognized path_regex creation rule; review its precedence")
            if current in seen_rules:
                fail(f"duplicate exact {current} creation rule")
            seen_rules.add(current)
            rule_indent = indent
            in_age = False
            continue
        if current is None:
            continue
        if stripped == "age:" and indent > rule_indent:
            if in_age or recipients[current]:
                fail(f"multiple age recipient blocks in {current} rule")
            age_indent = indent
            in_age = True
            continue
        if in_age and indent > age_indent:
            match = LIST_ITEM.match(raw_line)
            if not match:
                fail(f"unsupported age entry in {current} rule")
            value = match.group("value").strip().strip("\"'")
            if not valid_age_recipient(value):
                fail(f"invalid age recipient encoding in {current} rule")
            if value in recipients[current]:
                fail(f"duplicate age recipient in {current} rule")
            recipients[current].add(value)
            continue
        if indent <= rule_indent and stripped.startswith("-"):
            fail("unrecognized SOPS creation rule")
        if stripped != "creation_rules:" and current is not None:
            fail(f"unsupported field in {current} SOPS creation rule")

    if seen_rules != {"dev", "prod"}:
        fail("both exact dev and prod creation rules are required")
    return recipients


def encrypted_age_recipients(path: Path) -> set[str]:
    if not path.is_file():
        fail(f"missing encrypted production payload: {path}")
    recipients: set[str] = set()
    indices: set[int] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        match = SOPS_AGE_RECIPIENT.fullmatch(line)
        if not match:
            continue
        index, recipient = int(match.group(1)), match.group(2)
        if index in indices or recipient in recipients or not valid_age_recipient(recipient):
            fail("duplicate or invalid encrypted production recipient metadata")
        indices.add(index)
        recipients.add(recipient)
    if indices != set(range(len(indices))):
        fail("noncontiguous encrypted production age recipient indexes")
    return recipients


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: verify-sops-release-policy.py <.sops.yaml> <environment>", file=sys.stderr)
        return 2
    policy_path = Path(argv[1])
    environment = argv[2].strip().lower()
    if environment != "prod":
        return 0
    if not policy_path.is_file():
        fail(f"missing policy file: {policy_path}")
    recipients = parse_recipients(policy_path)
    dev, prod = recipients["dev"], recipients["prod"]
    if not dev:
        fail("exact dev recipient rule is missing or empty")
    if len(prod) < 2:
        fail("prod must have at least two independently controlled recipients")
    if not prod.difference(dev):
        fail("prod must include at least one recipient not used by dev")
    if prod == dev:
        fail("prod and dev recipient sets must not be identical")
    payload_recipients = encrypted_age_recipients(policy_path.parent / "env/enc/prod.env.enc")
    if payload_recipients != prod:
        fail("encrypted production payload recipients do not match policy; run sops updatekeys")
    print(f"production SOPS policy verified (dev recipients={len(dev)}, prod recipients={len(prod)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
