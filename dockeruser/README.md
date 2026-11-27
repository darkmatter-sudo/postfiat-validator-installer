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

## Results (2026-11-27)

Upstream: issue [postfiatorg/postfiatorg.github.io#58](https://github.com/postfiatorg/postfiatorg.github.io/issues/58),
PR [#59](https://github.com/postfiatorg/postfiatorg.github.io/pull/59), commit `e9d1fc074062ed8e4e6eadd35248ecb041189b5a`
(parent = upstream main `8da236f68fb1dbc050fe6463c427f6e0bb5d5d1c`), 3 files, +192/-24.

| Log | What | Result lines |
| --- | --- | --- |
| `logs/01-guide-static.log` | fresh clones; full diff; check-guide | 276 diff = 3 files; 318-322 5 parts identical in all copies; 324-327 shellcheck; 332 systemd-analyze; 334 exit 0 |
| `logs/02-netns-sentry.log` | netns suite on the sentry | 111 `24 passed, 0 failed`; 9/113 host chain sha256 unchanged |
| `logs/03-sentry-pre.log` | install from the guide, lose rules, detect, restore, idempotency | 57/65 install exit 0 + byte-identical; 84 check 0; 97/100 flushed + check rc=1; 106/125 start + check 0; 128-138 runs 0-2 `lines=7` same sha256; 161 PASS |
| `logs/04-sentry-reboot.log` | sentry reboot via `patch/drill/live-run.sh` | 89-90 reboot, back after 69 s, new boot id; 133 operator topics 0 messages |
| `logs/05-sentry-post.log` | after the reboot | 22/25 unit ran at boot, active/success; 42-47 four rules, RETURN last, check 0; 51 `server_state` full; 61 PASS |

History: the first post-reboot run (unpublished) had one harness FAIL: `systemctl show -p ActiveState -p Result --value`
prints properties in systemd's order, so the string compare failed although the unit was active/success; fixed in
`2ead044c6e65f684210d9aba5df1ed4453419a9e` (one property per call, remote times in UTC) and re-run as log 05.
Log 03 ran `sentry-proof.sh` at `f982b02273efb41ce3dcedeea89eb267fda49118`; that fix changed only the post path and the
remote time zone.
