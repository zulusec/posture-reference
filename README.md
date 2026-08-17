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
| `EC2.OPEN_SECURITY_GROUP` | Inbound rules whose sources add up to 0.0.0.0/0 or ::/0, raised to HIGH when the port range covers an administration or database port |

Both listings are paginated. `DescribeSecurityGroups` returns at most 1000
groups per page against a default quota of 2500 per VPC, so reading one
page would report a multi-VPC account clean while its exposed group sat on
page two.

Block Public Access is read at both the bucket and the account level,
because the effective setting is the union of the two. An account that
enables it account-wide and configures nothing per bucket is protected, and
a check that reads only the bucket level calls every one of those buckets
exposed.

"From anywhere" is arithmetic on the ranges rather than a match on the
string `0.0.0.0/0`. A rule listing 0.0.0.0/1 and 128.0.0.0/1 is the whole
internet written in two lines, and a string comparison calls that group
restricted. The same pair exists on the v6 side as ::/1 and 8000::/1.

## Running against a real account

Only run this against accounts you own or are authorized to assess.

The tool is read-only. It calls only Get, List, and Describe operations and
never writes, modifies, or remediates anything. The minimal IAM policy it
requires is at `docs/iam-policy.json`.

```bash
posture --region us-east-1
posture --region us-east-1 --json
```

### What these checks do not look at

Written down here rather than left to be discovered, because a limit nobody
states reads as a result.

Security groups are read one region at a time. `DescribeSecurityGroups`
returns the groups in the client's region, so `--region us-east-1` is an
answer about us-east-1 and about nothing else, and exit 0 means every
resource in that scope was read. Run it once per region you use. The S3
check is not regional: `ListBuckets` is account-wide, so a single run covers
every bucket wherever it lives.

A source that is a managed prefix list is not resolved. A prefix list can
contain 0.0.0.0/0 and this check will not see it, because reading one needs
`ec2:GetManagedPrefixListEntries`, which is not in `docs/iam-policy.json`.
A source that is another security group is not the internet, so it sits
outside this check's subject rather than being missed by it.

A rule is reported when its ranges add up to the entire address space.
0.0.0.0/1 on its own is half the internet and is not reported. The finding
says "from anywhere", so the line is drawn where that is provable rather
than estimated.

Port 443 open to 0.0.0.0/0 is reported as MEDIUM, and on an internet-facing
load balancer that is the correct configuration. This check can see a
security group. It cannot see whether a load balancer or an unpatched host
sits behind it, and guessing would mean sometimes reporting clean on an
exposure it could plainly see. A false clean costs more than a finding a
reader dismisses in five seconds, so the severity stays and the triage is
yours. The question to ask of every MEDIUM here is what is listening.

### Incomplete runs

An assessor role gets told no. A bucket policy denies the read, a listing
throttles halfway through. A resource that could not be read is recorded
and printed, because a shorter list of findings is otherwise
indistinguishable from a cleaner account. In the table it is a block at the
top of the output; in JSON it is `metadata.errors`.

| Exit code | Meaning |
| --- | --- |
| 0 | Every resource in scope was read |
| 1 | The run could not start, usually credentials, region, or network |
| 2 | The run finished with gaps, listed in the output |

Exit 0 is the only code that means the account was assessed, so a pipeline
treating it that way cannot be handed that claim by a partial scan.

## How this was built

AI wrote this code. Version control, tests, and review are what make it
trustworthy, and the deterministic behavior is enforced by a test rather
than promised in a paragraph. That is the whole argument: AI builds and
orchestrates the tooling, and the tooling is what produces the answer.

Every change landed as a pull request carrying its code, its tests, and a
green CI run. Review happened after the merge, not before it, and each round
of review findings landed as its own pull request. PRs #2, #4, #7 and #9 are
those review rounds: #2 follows #1, #4 follows #3, #7 follows #6, #9 follows
#8. Open any of those four and you can read what the review found and what
the fix was. A later review of the whole branch produced the same pattern at
a larger scale, and PRs #11 onward are its rounds.

GitHub therefore records no approving review on any pull request in this
repository, and the merges look fast because the merge was not the gate. The
gate was the review pass that produced the next pull request. The tradeoff
is real: the finding and its fix are both permanently in the history rather
than squashed out of it, at the cost of code sitting on `main` for a few
minutes before it had been reviewed. That is stated here because anyone who
opens the pull request list will work it out in thirty seconds, and should
not have to.

Review here is by a single practitioner. That is the human gate, and it is
described accurately rather than dressed up as a team process.

## License

MIT. See `LICENSE`.

---

Built by [ZuluSec](https://zulusec.com).
