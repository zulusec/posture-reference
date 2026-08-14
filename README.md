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

Every change here arrived as a pull request carrying generated code, its
tests, and a CI run, reviewed before merge. The git history is the record.

AI wrote this code. Review, version control, and tests are what make it
trustworthy, and the deterministic behaviour is enforced by a test rather
than promised in a paragraph. That is the whole argument: AI builds and
orchestrates the tooling, and the tooling is what produces the answer.

Reviews here are by a single practitioner. That is the human gate, and it
is described accurately rather than dressed up as a team process.

## License

MIT. See `LICENSE`.

---

Built by [ZuluSec](https://zulusec.com).
