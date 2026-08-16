# Security Policy

## Supported Versions

Cowtail is pre-1.0. Only the latest commit on the default branch is supported.

## Reporting a Vulnerability

Found a bug or security issue? **Open a public issue.** Reporting is
encouraged, including for security-related problems. Full disclosure is welcome
and preferred — this is a read-only dashboard for a honeypot, not a product with
sensitive attack surface that needs embargoed coordination.

1. Open a [GitHub issue](https://github.com/jarihu/cowtail/issues/new) with
   the details.
2. If you'd rather not make it public, a
   [private security advisory](https://github.com/jarihu/cowtail/security/advisories/new)
   also works.

Please include:

- A description of the vulnerability and its impact
- Steps to reproduce
- Affected versions (or the commit hash)
- Any suggested fix, if you have one

Credit will be given to the reporter unless you ask to remain anonymous.

## Security Model

Cowtail is a **read-only dashboard** for the [Cowrie](https://github.com/cowrie/cowrie)
honeypot. It tails a log file, resolves IPs, and streams events to a browser
over WebSocket. It is not a honeypot itself and captures no credentials of its
own.

Two things to keep in mind when deploying it:

### 1. The dashboard has no authentication

The web server binds to `127.0.0.1` by default, but anyone who can reach the
port can view the live attack feed, including attacker IPs, usernames, and
passwords. If you bind to a public interface (`--host 0.0.0.0`), put it behind a
reverse proxy with access control or a firewall.

### 2. `--online` makes outbound network calls

By default Cowtail is fully offline and never phones home. Passing `--online`
enables an [ipwho.is](https://ipwho.is) fallback for IPs missing from the
bundled offline database. This sends attacker IP addresses to a third-party
service. Leave it off unless you understand and accept that.

## False Positives in `cowtail/data.py`

The `--demo` simulator is seeded with **fictional** data — common attack
usernames and passwords, malware download URLs, and VirusTotal-style detection
names (`cowtail/data.py`). These are intentional honeypot lures, not real
credentials or leaked secrets, and they may trigger automated secret scanners
(gitleaks, truffleHog, GitHub secret scanning, etc.). None of them are actual
secrets:

- The username/password lists are well-known public Mirai/Gafgyt botnet
  dictionaries.
- The malware URLs are placeholder download endpoints used by real botnets,
  listed for realism only.
- The VirusTotal detection names are illustrative strings, not live scan
  results.

If a scanner flags these files, the findings are false positives and can be
safely suppressed or ignored.
