# Confirmation demos

Screen recordings backing the "Confirmations" section of the main
[`README`](../README.md). Each shows RCEKit reaching a **`confirmed`** (or, for
blind timing, a **`needs-review`**) verdict against a real, publicly-documented
vulnerability — the verdict differenced against a payload-free control.

| File | Method | Target |
|---|---|---|
| `reflected-webmin-cve-2019-15107.gif` | `reflected` (OS command injection) | Webmin 1.910 — CVE-2019-15107 |
| `eval-struts2-s2-001.gif` | `eval` (OGNL expression injection) | Apache Struts2 — S2-001 |
| `time-webmin-cve-2019-15107.gif` | `time` (blind timing) | Webmin 1.910 — CVE-2019-15107 |
| `oob-log4shell-cve-2021-44228.gif` | out-of-band DNS callback | Log4Shell — CVE-2021-44228 |

All targets were run locally in disposable Docker labs (vulhub) for authorised testing only.
