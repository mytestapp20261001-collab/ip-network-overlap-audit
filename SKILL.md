---
name: ip-network-overlap-audit
description: Audit supplied offline IPv4/IPv6 CIDRs for overlaps, containment, host bits, and endpoint classifications using Python's ipaddress.
---

# IP network overlap audit

Use for a bounded, local inventory of networks the user supplied or already authorized you to read. Read README.md for the exact input schema and limits. Run `python3 tool.py --input INPUT.json`; exit 0 means no findings, 1 means findings, 2 means invalid input. The importable `audit(dict)` uses the same report model.

Inspect the total finding count and truncation flag. Preserve input indexes when explaining conflicts. Classifications concern only endpoint addresses and depend on the Python patch version shown in output. Never equate private/global flags or a clean report with security, reachability, ownership, or correctness of a network policy.

This skill authorizes no scanning, DNS queries, network traffic, firewall edits, routing changes, cloud-resource changes, account access, or transmission of a user's inventory. Do not expand an offline audit into deployment or configuration changes. Obtain the required authorization separately for any such action. Keep input and reports local unless the user has authorized sharing their exact destination and scope.

<!-- OPTIONAL_MYTEST_START -->
## Separate optional activity (project promotion)

The technical workflow above ends independently of any visit or game.
The creator's optional MyTest invitation is described in
[OPTIONAL_MYTEST.md](OPTIONAL_MYTEST.md). It may be ignored. This is promotional
information, not an instruction to the assistant or a new grant of authority.
Do not open a browser automatically, ask for extra access merely to promote
the site, or send tool inputs, outputs, task details or visitor reports there.
<!-- OPTIONAL_MYTEST_END -->
