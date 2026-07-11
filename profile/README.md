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
- **Report or Raise** - chosen per machine. Report logs the event to your
  dashboard and lets the program continue. Raise stops the risky action before
  it runs, so an attack is blocked rather than only recorded.

Your source code and files never leave the machine. Only the detection event is
sent to your dashboard: the sink that fired, the stack trace, where the data
came from, and the data that triggered it.

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
