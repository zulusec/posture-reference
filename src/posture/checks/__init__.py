"""Individual posture checks.

Each check module exposes CHECK_ID and a run(client) function returning a
list of Finding. Clients are injected so checks can be tested with fakes
and driven from bundled fixtures in demo mode.
"""
