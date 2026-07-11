![EyalSec - a secure Python](https://raw.githubusercontent.com/EyalSec/.github/main/profile/banner.png)

# EyalSec

**The Python you already run, watching for attacks as your code executes.**

[![Website](https://img.shields.io/badge/website-eyalsec.com-e8b04b)](https://eyalsec.com)
[![Docs](https://img.shields.io/badge/docs-user%20guide-2a2c27)](https://eyalsec.com/docs)

EyalSec is a security-hardened build of Python, `es-python`. You install it next
to your normal Python and run your existing programs and libraries through it
unchanged. As your code runs, EyalSec watches for untrusted data reaching a
risky action, and either reports it to your dashboard or blocks it before it
runs.

That untrusted-data-reaches-a-sink pattern is how most real-world attacks work:
SQL injection, command injection, path traversal, and insecure deserialization.
EyalSec has already flagged two critical CVEs in Django.

## How it works

- **Source** - where untrusted data enters: a network socket, a file, standard
  input, environment variables and command-line arguments, or code another user
  can write.
- **Sink** - a risky action it flows into: running a system command, opening a
  file, running a database query, or deserializing data.
- **Report, or Report and Raise** - chosen per machine. Report logs the event to
  your dashboard and lets the program continue. Report and Raise does both: it
  logs the event **and** stops the risky action before it runs, so an attack is
  blocked, not just recorded.

Your source code and files never leave the machine. Only the detection event is
sent to your dashboard: the sink that fired, the stack trace, where the data
came from, and the data that triggered it.

## What EyalSec can find that others can't

Static scanners and linters read your source and guess. EyalSec watches your
program actually run, so it catches what they miss:

- **Real, exploitable flows, not guesses.** It only flags untrusted data that
  actually reaches a risky call at runtime, so you get real findings instead of a
  wall of maybe-bugs.
- **Vulnerabilities inside your dependencies.** Because it watches execution, it
  sees untrusted data reach a sink deep inside installed third-party libraries and
  frameworks, not just your own code. That is how EyalSec flagged two critical
  CVEs in Django.
- **The blind spots of static analysis.** Code generated or loaded at runtime
  (`exec`, `eval`, dynamic imports) and flows a scanner can't parse are exactly
  where EyalSec is strongest, because it watches the real execution.
- **The actual attack, with evidence.** Every detection is the real event: the
  sink that fired, the payload, where the data came from, and the exact line and
  stack trace, so you can confirm and fix it fast.

## Install

Sign in, add a machine on your dashboard, and run the one-line installer it
gives you. `es-python` installs next to your normal Python; then run your program
through it, no code changes. Full guide: **[eyalsec.com/docs](https://eyalsec.com/docs)**.

## Questions

**How is it different from a static scanner or linter?** A static scanner reads
your source and guesses at possible bugs before it runs. EyalSec watches real
execution and only reports untrusted data that actually reaches a risky action,
so it finds real, exploitable issues with far fewer false positives.

**Do I have to change my code?** No. `es-python` runs your existing code,
frameworks, and packages exactly as they run today.

**Does it work with Django, Flask, and my libraries?** Yes. Your frameworks and
packages run unchanged.

**Does it send my code anywhere?** No. Your source and files stay on the
machine; only the detection event posts to your dashboard.

## Explore

- **[Website](https://eyalsec.com)** - what EyalSec does and how it installs
- **[Documentation](https://eyalsec.com/docs)** - install, run, read events, configure rules
- **[Pricing](https://eyalsec.com/pricing)** - size machines and monthly events for a price
- **[Security](https://eyalsec.com/security)** - the security model; your code stays on your machine

---

Python is a trademark of the Python Software Foundation. EyalSec is not
affiliated with or endorsed by the PSF.
