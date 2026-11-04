# Docker default seccomp profile (reference)

`docker-default-29.1.3.json` is Docker's built-in default seccomp profile as vendored in the engine the hosts run
(docker.io 29.1.3, Ubuntu 22.04): moby/moby tag `docker-v29.1.3`, commit fbf3ed25f893e6ce21336f1101590e40a13934f4,
path `vendor/github.com/moby/profiles/seccomp/default.json`.

    curl -sf https://raw.githubusercontent.com/moby/moby/fbf3ed25f893e6ce21336f1101590e40a13934f4/vendor/github.com/moby/profiles/seccomp/default.json | sha256sum
    01536f1d1df938ae611eba20d6349e0de7a99b6ecdee1549427a0b01b8301e28  -

pft_seccomp.py resolves its includes/excludes (arch amd64, the container's capabilities, kernel 5.15) to get the set
the live container runs under today; the tailored profile never allows anything outside that set.
