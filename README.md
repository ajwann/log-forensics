# log-forensics

An [Agent Skill](https://agentskills.io): **log forensics**.

A method for investigating large or messy logs to find what actually went wrong. Find the first error rather than the loudest, build a timeline across services, normalize timestamps and zones, pivot on request/trace/user IDs, collapse near-duplicate lines into counted fingerprints, and diff against a known-good window. Includes a fingerprinting script that turns 100k lines into a ranked list of distinct events.

## Install

```bash
npx skills add ajwann/log-forensics
```

Or copy this directory to `~/.claude/skills/log-forensics/` (Claude Code) or your agent's skills folder.

## Contents

- `SKILL.md`: the instructions the agent loads (the frontmatter `description` says when it triggers)
- `scripts/fingerprint.py`

## License

MIT
