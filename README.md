# posture-reference

A read-only AWS posture checker with two checks, published as a reference
implementation of how ZuluSec builds automation.

## What this is not

- Not the ZuluSec audit toolkit. Two checks out of a much larger methodology.
- Not a product, and not maintained as one.
- Not a substitute for a security audit.

It exists to show how the work is built, not how much of it there is.

## Try it without an AWS account

```bash
pip install -e .
posture --demo
```

Demo mode runs the real check code against bundled synthetic fixtures.

## Determinism

The same input always produces the same findings, byte for byte:

```bash
posture --demo --json | sha256sum
posture --demo --json | sha256sum
```

Those hashes match, and a test in CI asserts it on every pull request.
Findings carry no timestamp, no duration, and no generated identifier. Run
metadata that legitimately varies lives in a separate block.

This matters because a finding that cannot be reproduced cannot be
evidence. An assessor will not accept a result that changes between runs.

## The checks

| Check | What it reports |
| --- | --- |
| `S3.PUBLIC_ACCESS` | Block Public Access settings not enabled, and bucket policies granting public access |
| `EC2.OPEN_SECURITY_GROUP` | Inbound rules permitting 0.0.0.0/0 or ::/0, raised to HIGH when the range covers an administration or database port |

## Running against a real account

Only run this against accounts you own or are authorized to assess.

The tool is read-only. It calls only Get, List, and Describe operations and
never writes, modifies, or remediates anything. The minimal IAM policy it
requires is at `docs/iam-policy.json`.

```bash
posture --region us-east-1
posture --region us-east-1 --json
```

## How this was built

AI wrote this code. Version control, tests, and review are what make it
trustworthy, and the deterministic behaviour is enforced by a test rather
than promised in a paragraph. That is the whole argument: AI builds and
orchestrates the tooling, and the tooling is what produces the answer.

Every change landed as a pull request carrying its code, its tests, and a
green CI run. Review happened after the merge, not before it, and each round
of review findings landed as its own pull request. PRs #2, #4, #7 and #9 are
those review rounds: #2 follows #1, #4 follows #3, #7 follows #6, #9 follows
#8. Open any of those four and you can read what the review found and what
the fix was.

GitHub therefore records no approving review on any of the ten pull requests,
and the merges look fast because the merge was not the gate. The gate was the
review pass that produced the next pull request. The tradeoff is real: the
finding and its fix are both permanently in the history rather than squashed
out of it, at the cost of code sitting on `main` for a few minutes before it
had been reviewed. That is stated here because anyone who opens the pull
request list will work it out in thirty seconds, and should not have to.

Review here is by a single practitioner. That is the human gate, and it is
described accurately rather than dressed up as a team process.

## License

MIT. See `LICENSE`.

---

Built by [ZuluSec](https://zulusec.com).
