---
name: log-forensics
description: A method for investigating large or messy logs to find what actually went wrong. Find the first error rather than the loudest, build a timeline across services, normalize timestamps and zones, pivot on request/trace/user IDs, collapse near-duplicate lines into counted fingerprints, and diff against a known-good window. Includes a fingerprinting script that turns 100k lines into a ranked list of distinct events. Use whenever the user shares, pastes, points at, or asks you to look through logs, a stack-trace dump, kubectl/docker/journalctl/CloudWatch output, CI job output, or a crash report to answer "what happened", "why did this fail", "when did it start", or "what's causing these errors", even if they don't say "logs" (for example "here's the output from last night's job, it died around 3am").
---

# Log forensics

Logs are noisy in a misleading way: the loudest message is usually a
*consequence* of the cause. One "connection pool exhausted" is followed by
ten thousand request timeouts. The method is to shrink the volume into
distinct events, line them up in time, and walk back to the first thing that
broke.

## 1. Get oriented before reading anything

- **Size and span:** `wc -l`, plus the first and last timestamps
  (`head -1`, `tail -1`). Know how much there is and what period it covers.
- **Format:** plain text, JSON lines, or a mix? Multi-line stack traces?
  Which timezone are the timestamps in (`Z`, an offset, or none, which means the
  host's local zone)? Different services often log in different zones. Normalize
  them before comparing.
- **Symptom time:** when did the user *notice* the problem? The cause is
  before that, often minutes or hours before.

Don't `cat` a large log into context. Use `grep`, `awk`, `jq` and the
script below to pull out only what you need.

## 2. Collapse to distinct events

```bash
python3 scripts/fingerprint.py app.log --grep 'error|warn|fatal|exception|panic|refused|timeout|killed'
python3 scripts/fingerprint.py app.log --grep 'error|warn' --sort first   # earliest first
python3 scripts/fingerprint.py svc-a.log svc-b.log.gz --top 40            # several sources
kubectl logs deploy/api --since=2h | python3 scripts/fingerprint.py -
```

It masks the parts that vary between occurrences (timestamps, UUIDs, IPs,
numbers, quoted strings) while keeping HTTP status codes. It prints each
distinct event with its count, first and last line and time, and one
example. JSON-lines logs are keyed on their level plus message field.

Read the output two ways:
- `--sort count` shows what's loud. Usually symptoms.
- `--sort first` shows what came first. Usually closer to the cause. A
  fingerprint with **count 1 just before a burst** is the classic root
  cause.

## 3. Build the timeline

Write a short timeline of distinct events with timestamps, oldest first.
Include events that are *not* errors but changed state: deploys, config
reloads, restarts, leader elections, cron jobs starting, autoscaling, and cert
or token expiries. Also note **when something normal stopped**. A heartbeat
or a "processed batch" line that goes quiet is evidence too:

```bash
grep -n 'processed batch' app.log | tail -3      # when did it last happen?
```

For several services, merge on normalized timestamps:
`sort -m -k1,1` on files whose lines start with ISO 8601 UTC, or one `jq`
pass per JSON log into a shared format.

## 4. Pivot on identifiers

Pick one failing request, job, user or trace ID from the symptom and follow
it everywhere:

```bash
grep -n 'req-7f3a' *.log            # all services, in order
jq -c 'select(.trace_id=="abc123")' app.jsonl
```

One end-to-end path through the system usually shows which hop failed and
what it saw. Then check whether *other* failing IDs share that hop.

## 5. Compare against a good window

Run the same fingerprinting on a period when things worked: yesterday at
the same hour, or the hour before the incident. Fingerprints that **appear only in
the bad window** are your leads. Errors present in both are background noise
that was there before the incident started.

## 6. State the conclusion with evidence

```
Timeline (UTC):
  09:02:10  deploy api v412 (line 11873)
  09:04:30  db.pool: connection pool exhausted (max=20, waiting=57)  ← first anomaly, 1 occurrence
  09:04:31+ 11,456 × request timed out after ~3000ms                 ← consequence
Root cause (likely): <one sentence>, because <evidence>.
Not the cause: <the loud symptom>, which starts after the first anomaly.
Unknowns: <what the logs can't show>. Next check: <the one command or metric that would confirm it>.
```

Say how confident you are and why. Logs show correlation and ordering, not
causation. If the explanation needs something the logs don't contain
(metrics, a config diff, the deploy's changelog), say what you'd check
next.

## Pitfalls

- **Clock skew and zone mixing** between hosts can reorder events. Check
  that a request's hops appear in a plausible order before trusting a
  cross-service timeline.
- **Sampling and rate-limited logging** hide volume. Missing lines are not
  proof that something didn't happen.
- **Truncated or rotated logs:** check that the window you need is actually
  in the file. The cause may be in `app.log.1`.
- **Multi-line stack traces:** fingerprinting treats each line separately.
  For traces, grep the exception header line (`Traceback`, `Exception in thread`,
  `panic:`) and read a few full traces by hand.
- **Secrets in logs:** if you quote lines back to the user, mask tokens,
  passwords and auth headers.
