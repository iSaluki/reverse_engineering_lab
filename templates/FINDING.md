# <Component>: <vulnerability> allows <attacker> to <impact>

| | |
|---|---|
| Asset | <package / bundle id / product> <version> (sha256 `<from work/<file>/triage.txt>`) |
| Platform | Android <ver> / iOS / Windows / Linux / firmware <model> |
| Weakness | CWE-<id>: <name> |
| Severity | <Critical/High/Medium/Low>, CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_ (<score>) |
| Status | confirmed in container / PoC written but not executed (needs device or account) |

## Summary
Two or three sentences: what is vulnerable, how an attacker reaches it, and what they get.

## Root cause
- Entry point: `<exported component / URL scheme / port / file type>` (`attack_surface.txt`)
- Vulnerable code: `<file:line>` or `<function>@<address>`. Quote the 5-15 decompiled lines that matter.
- Missing or broken check: <what should have stopped it>

## Steps to reproduce
1. Install / start <version> on a test device or account (no production data).
2. `<exact command, attacker app snippet, HTML page, or request>`
3. Observe: <crash, leaked token, file written, command output>

## Proof of concept
```
<PoC: adb commands, attacker app code, exploit HTML, crash input (hex) + repro command, script>
```
Evidence: <screenshot or log excerpt, re-fuzz triage.txt signature>

## Impact
A realistic attacker scenario (who, prerequisites, user interaction) and the concrete consequence (account takeover, data
of N users, code execution as <uid>). Separate what was demonstrated from what is inferred.

## Remediation
The specific fix (e.g. validate the host with `Uri.getHost().equals(...)`, set `exported=false`, canonicalise the path and
check it against the base directory, use `snprintf` with sizeof, use an argv array instead of a shell string).

## References
CWE / OWASP MASVS / vendor docs / related CVEs.
