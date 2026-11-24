# shutdown — graceful-stop budget audit and crash-recovery tooling for postfiatd in Docker

`pft-shutdown.sh` answers one question for a Post Fiat validator (compose container `postfiatd`) or sentry
(`docker run` container `postfiatd-sentry`): **does every stop path give postfiatd enough time to shut down
cleanly before Docker or systemd sends SIGKILL?** postfiatd is PID 1 in the official image (the entrypoint
`exec`s it), so the container's stop signal reaches the daemon directly.

Status: `audit` and its offline tests are in place. `measure`, `apply`/`rollback` and the SIGKILL drill are added
in follow-up commits of this folder.

## audit (read-only)

```
pft-shutdown audit [--json] [--required SEC]
```

One line per finding, then `RESULT`. The required budget is `max(MIN_TIMEOUT, ceil(p100 x SAFETY_FACTOR))`,
where p100 is the slowest **clean** stop recorded by `measure` (`/var/lib/pft-shutdown/measure-<container>.json`);
without measurements it is `MIN_TIMEOUT` (30 s) and the basis line says so.

| id | exit bit | checks | why |
|----|----------|--------|-----|
| F1 | 1  | effective stop signal (container, else image, else SIGTERM) is SIGTERM/SIGINT | anything else is not a clean shutdown request |
| F2 | 2  | running container `StopTimeout` (unset = Docker's 10 s) >= required | budget of `docker stop`, `docker restart`, `docker compose stop/up/down` without `-t` |
| F3 | 4  | what the next re-creation gives: compose `stop_grace_period` (unset = 10 s); for a `docker run` container a recreate tool that carries `--stop-timeout` | a fix that lives only in the running container is lost on the next recreate |
| F4 | 8  | dockerd `shutdown-timeout` (default 15 s) >= required when live-restore is off | with live-restore off, stopping dockerd stops every container within this limit |
| F5 | 16 | `docker.service` `TimeoutStopUSec` >= required (`infinity` passes) | systemd's limit on dockerd's own stop |
| F6 | 32 | reboot budget: with live-restore on, systemd stops the container's `docker-<id>.scope` itself (KillSignal, SIGKILL after its `TimeoutStopUSec`); with live-restore off, `min(StopTimeout, shutdown-timeout, docker.service)` | host shutdown is a stop path too |

Exit code: 0 PASS, otherwise the OR of the failed findings' bits (1..63); 64 error; 65 usage.
`--json` prints `{container, required_s, required_basis, result, exit, checks:[{id,status,message}]}`.

## Tests

```
bash shutdown/tests/run-tests.sh
```

Offline, no root, no Docker: stub `docker` (inspect, image inspect, compose config) and `systemctl show`. A good
compose host and a good `docker run` host pass with no FAIL line; each finding fails on its own fixture with its named
reason and exactly the expected exit bits; controls cover combined findings (bits OR), the live-restore-off reboot
chain, a missing container (64), invalid daemon.json (64), bad usage (65), the required budget from measurement
state (p100 x factor, unclean runs ignored, floor, `--required`), `--json`, and the systemd/compose duration parsers.
