#!/usr/bin/env python3
"""Offline audit, Python 3.12+ standard library only. Never performs networking."""
import argparse
import json
import stat
import sys
from pathlib import Path

MAX_BYTES = 1024 * 1024
MAX_ITEMS = 256
MAX_FINDINGS = 500

class InputError(ValueError):
    """Safe error containing only a fixed code, never supplied data."""

class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise InputError("invalid_arguments")

def object_schema(value, allowed, required):
    if not isinstance(value, dict) or set(value) - allowed or not required <= set(value):
        raise InputError("invalid_schema")

def integer(value, low, high):
    return type(value) is int and low <= value <= high

def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError("duplicate_json_member")
        result[key] = value
    return result

def reject_constant(value):
    raise InputError("non_finite_json_number")

class Report:
    def __init__(self):
        self.findings, self.count = [], 0
    def add(self, code, **location):
        self.count += 1
        if len(self.findings) < MAX_FINDINGS:
            self.findings.append(dict(code=code, **location))
    def finish(self, **data):
        return {"tool": TOOL, "status": "fail" if self.count else "pass",
                "finding_count": self.count, "findings": self.findings,
                "findings_truncated": self.count > len(self.findings), **data}

def error_result(code):
    return {"tool": TOOL, "status": "error", "error": code}

def audit(data):
    """Audit a JSON-shaped dict; return deterministic JSON-compatible data."""
    try:
        return _audit(data)
    except InputError as exc:
        return error_result(str(exc))

def main(argv=None):
    try:
        parser = Parser(description=__doc__)
        parser.add_argument("--input", default="-", help="JSON file, or - for stdin (default)")
        args = parser.parse_args(argv)
        if args.input == "-":
            raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        else:
            path = Path(args.input)
            if not stat.S_ISREG(path.stat().st_mode):
                raise InputError("regular_file_required")
            with path.open("rb") as stream:
                raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise InputError("input_size_limit")
        try:
            data = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs,
                              parse_constant=reject_constant)
        except (ValueError, RecursionError) as exc:
            if isinstance(exc, InputError):
                raise
            raise InputError("invalid_json") from None
        result = audit(data)
    except InputError as exc:
        result = error_result(str(exc))
    except (OSError, UnicodeError):
        result = error_result("unreadable_utf8_input")
    print(json.dumps(result, sort_keys=True, ensure_ascii=True, indent=2, allow_nan=False))
    return {"pass": 0, "fail": 1, "error": 2}[result["status"]]

import ipaddress
import re

TOOL = "ip-network-overlap-audit"
FLAGS = ("is_private", "is_global", "is_multicast", "is_loopback",
         "is_link_local", "is_reserved", "is_unspecified")

def address_flags(address):
    return {flag: getattr(address, flag) for flag in FLAGS}

def _audit(data):
    object_schema(data, {"networks"}, {"networks"})
    values = data["networks"]
    if not isinstance(values, list) or not 1 <= len(values) <= MAX_ITEMS:
        raise InputError("networks_count_limit")
    if any(not isinstance(value, str) or not 1 <= len(value) <= 128 for value in values):
        raise InputError("invalid_network_entry")
    report, networks, parsed = Report(), [], []
    for index, value in enumerate(values):
        # Decimal prefix CIDR only. No whitespace, scopes, masks, or shorthand hosts.
        if not re.fullmatch(r"[0-9A-Fa-f:.]+/(?:0|[1-9][0-9]{0,2})", value):
            report.add("invalid_cidr", index=index)
            networks.append({"index": index, "valid": False})
            continue
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            report.add("invalid_cidr", index=index)
            networks.append({"index": index, "valid": False})
            continue
        address = ipaddress.ip_address(value.split("/")[0])
        host_bits = address != network.network_address
        if host_bits:
            report.add("host_bits_set", index=index)
        networks.append({"index": index, "valid": True, "cidr": str(network),
                         "version": network.version, "prefix_length": network.prefixlen,
                         "address_count": network.num_addresses,
                         "host_bits_normalized": host_bits,
                         "first_address": str(network.network_address),
                         "last_address": str(network.broadcast_address),
                         "endpoint_classification": {
                             "first": address_flags(network.network_address),
                             "last": address_flags(network.broadcast_address)}})
        parsed.append((index, network))
    overlaps = 0
    for pos, (left_index, left) in enumerate(parsed):
        for right_index, right in parsed[pos + 1:]:
            if left.version != right.version or not left.overlaps(right):
                continue
            overlaps += 1
            relation = ("equal" if left == right else
                        "left_contains_right" if right.subnet_of(left) else
                        "right_contains_left")
            report.add("network_overlap", left_index=left_index, right_index=right_index,
                       relation=relation)
    return report.finish(networks=networks, network_count=len(values),
                         overlap_count=overlaps, valid_network_count=len(parsed),
                         classification_python_version=".".join(map(str, sys.version_info[:3])))

if __name__ == "__main__":
    raise SystemExit(main())
