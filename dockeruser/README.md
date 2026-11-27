# dockeruser: persist the TCP 2559 DOCKER-USER limits across reboots

The official validator guide (`postfiatorg/postfiatorg.github.io`, `content/validator-setup.md` and the two
`static/agents/validator-setup.*` copies) added the `DOCKER-USER` rate and connection limits for TCP 2559 with
plain `iptables` commands. Those rules are not saved: after a reboot the chain is empty and peer traffic is no
longer limited, with nothing to say so. This folder holds the evidence tooling for the upstream fix:

- an idempotent `/usr/local/sbin/postfiat-docker-user.sh` that removes only the chain's TCP 2559 rules and its
  RETURN rule (by rule number, highest first), keeps every other `DOCKER-USER` rule, then appends the four 2559
  rules and RETURN (RETURN last);
- a oneshot `postfiat-docker-user.service` (`After=`, `Requires=`, `PartOf=docker.service`, `RemainAfterExit=yes`)
  enabled for boot;
- a read-only check (`sudo sh -s <<'EOF' ... EOF`) that exits 1 when a 2559 rule is missing, changed or out of
  order, when RETURN is not the single last rule, or when the unit is not enabled.

| File | What it does |
| --- | --- |
| `extract_dockeruser.py GUIDE OUTDIR` | cuts the section, the install block, the script and unit it writes, and the check block out of one guide copy |
| `check-guide.sh GUIDE_REPO BASE HEAD OUTDIR` | diff touches exactly the 3 guide copies; extracted parts byte-identical in all 3; shellcheck of every shell part; `systemd-analyze verify` of the unit |
| `tests/test-netns.sh EXTRACT_DIR` | runs the guide's script and check with real iptables inside a throwaway network namespace (`unshare --net`): 13 cases, each asserting exit code and reason, including fail controls and injected iptables errors |
| `sentry-proof.sh pre\|post EXTRACT_DIR` | the live sequence on the sentry only (never the validator), see below |

Run (`sudo` needed for the netns test and `systemd-analyze verify`):

```bash
git clone https://github.com/darkmatter-sudo/postfiatorg.github.io.git guide && git -C guide checkout <PR_SHA>
sudo bash dockeruser/check-guide.sh guide <PR_SHA>~1 <PR_SHA> out
sudo bash dockeruser/tests/test-netns.sh out/copy1
```

## Sentry live sequence

`pre` (inside an Alertmanager silence scoped to `host="sentry"`): rules present -> install the guide block unchanged
-> installed files byte-identical to the guide -> check exit 0 -> stop the unit and flush the TCP 2559 rules and
RETURN -> check exit 1 -> unit start -> check exit 0 -> two more runs with rule count and chain sha256 unchanged.
The reboot goes through `patch/drill/live-run.sh` (`INJECT=sentry-reboot`, every notifier on throwaway topics, outer
silence). `post`: new boot id, unit ran at boot, four 2559 rules with RETURN last, check exit 0, `server_state full`.
Other `DOCKER-USER` rules on the host (an egress-policy jump at position 1) are left alone throughout, which the
previous `iptables -F DOCKER-USER` did not do.
