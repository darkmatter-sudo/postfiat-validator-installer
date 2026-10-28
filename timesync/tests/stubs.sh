#!/usr/bin/env bash
# Stub commands for run-tests.sh. Sourced; mk_env DIR builds a fake host in DIR:
#   DIR/root  PFT_TIMESYNC_ROOT (files on the fake host)   DIR/s  stub state   DIR/bin  one executable per command
# The chronyc CSV fixtures are copied from a real chrony 4.2 run (logs/05). The fake apt-get removes
# systemd-timesyncd when it installs chrony (both provide time-daemon) and records whether policy-rc.d blocked
# service starts at that moment; the fake systemctl "starts" chrony by loading chrony.conf: TEST-NET-1 servers
# (the unreachable injection) give an unsynchronised tracking answer, anything else the good fixture.
# shellcheck disable=SC2016

GOOD_TRACKING='0195CD25,ntppool1.time.nl,2,1793221787.622236053,0.000680615,-0.000187949,0.000187949,-35.187,93.312,536.235,0.276591241,0.021144409,2.6,Normal'
GOOD_SOURCES='^,+,time.cloudflare.com,3,6,17,31,0.003833808,0.003645859,0.173436880
^,-,nts.netnod.se,1,6,17,28,-0.003586549,-0.003586549,0.146273285
^,+,ptbtime1.ptb.de,1,6,17,32,-0.002183796,-0.002371745,0.141923606
^,*,ntppool1.time.nl,1,6,17,31,-0.002717538,-0.002905487,0.138864309
^,+,nts.teambelgium.net,2,6,17,30,0.000417538,0.000305487,0.150864309'
GOOD_AUTH='time.cloudflare.com,NTS,1,15,256,106,0,0,8,96
nts.netnod.se,NTS,1,15,256,36,0,0,8,100
ptbtime1.ptb.de,NTS,1,15,256,105,0,0,8,100
ntppool1.time.nl,NTS,1,15,256,106,0,0,8,96
nts.teambelgium.net,NTS,1,15,256,90,0,0,8,96'
BAD_TRACKING='00000000,,0,0.000000000,0.000000000,0.000000000,0.000000000,0.000,0.000,0.000,1.000000000,1.000000000,0.0,Not synchronised'
BAD_SOURCES='^,?,192.0.2.1,0,6,0,-,0.0,0.0,0.0
^,?,192.0.2.2,0,6,0,-,0.0,0.0,0.0
^,?,192.0.2.3,0,6,0,-,0.0,0.0,0.0
^,?,192.0.2.4,0,6,0,-,0.0,0.0,0.0
^,?,192.0.2.5,0,6,0,-,0.0,0.0,0.0'
BAD_AUTH='192.0.2.1,NTS,0,0,0,-,3,0,0,0
192.0.2.2,NTS,0,0,0,-,3,0,0,0
192.0.2.3,NTS,0,0,0,-,3,0,0,0
192.0.2.4,NTS,0,0,0,-,3,0,0,0
192.0.2.5,NTS,0,0,0,-,3,0,0,0'
TSD_MSG='{ Leap=0, Version=4, Mode=4, Stratum=2, Precision=-25, RootDelay=6.637ms, RootDispersion=686us, Reference=1D586304, Ignored=no PacketCount=308, Jitter=57.910ms }'

mk_env() {
  local d="$1"
  mkdir -p "$d/root/etc/systemd" "$d/root/usr/sbin" "$d/root/proc" "$d/root/var/lib" "$d/s" "$d/bin"
  printf '[Time]\n#NTP=\n' > "$d/root/etc/systemd/timesyncd.conf"; chmod 0644 "$d/root/etc/systemd/timesyncd.conf"
  echo '86400.12 1000.0' > "$d/root/proc/uptime"
  echo systemd-timesyncd > "$d/s/active"
  echo 'systemd-timesyncd 249.11-0ubuntu3.23' > "$d/s/pkgs"
  echo "$GOOD_TRACKING" > "$d/s/tracking"; echo "$GOOD_SOURCES" > "$d/s/sources"; echo "$GOOD_AUTH" > "$d/s/authdata"
  echo "$TSD_MSG" > "$d/s/tsd_msg"; echo yes > "$d/s/synced"; echo no > "$d/s/localrtc"; echo ntp.ubuntu.com > "$d/s/servername"
  echo 2026-10-28T11:33:11.2Z > "$d/s/started"; echo full > "$d/s/state"
  : > "$d/s/calls"

  cat > "$d/bin/systemctl" <<'B'
#!/usr/bin/env bash
S="$STUB_S"; echo "systemctl $*" >> "$S/calls"
case "$1" in
  is-active) u="${3:-$2}"; grep -qx "$u" "$S/active" ;;
  stop) grep -vx "$2" "$S/active" > "$S/a.tmp"; mv "$S/a.tmp" "$S/active" ;;
  start|restart)
    case "$2" in
      chrony) grep -q '^chrony ' "$S/pkgs" || exit 5
              if grep -q '192\.0\.2\.' "$PFT_TIMESYNC_ROOT/etc/chrony/chrony.conf"; then
                echo "$BAD_TRACKING" > "$S/tracking"; echo "$BAD_SOURCES" > "$S/sources"; echo "$BAD_AUTH" > "$S/authdata"
              else echo "$GOOD_TRACKING" > "$S/tracking"; echo "$GOOD_SOURCES" > "$S/sources"; echo "$GOOD_AUTH" > "$S/authdata"; fi ;;
      systemd-timesyncd) grep -q '^systemd-timesyncd ' "$S/pkgs" || exit 5 ;;
    esac
    grep -qx "$2" "$S/active" || echo "$2" >> "$S/active"
    [ -f "$S/restart_hook" ] && . "$S/restart_hook"; exit 0 ;;
  *) exit 0 ;;
esac
B
  cat > "$d/bin/chronyc" <<'B'
#!/usr/bin/env bash
S="$STUB_S"; grep -qx chrony "$S/active" || { echo "506 Cannot talk to daemon" >&2; exit 1; }
[ -f "$S/chronyd_down" ] && { echo "506 Cannot talk to daemon" >&2; exit 1; }
case "${*: -1}" in tracking) cat "$S/tracking" ;; sources) cat "$S/sources" ;; authdata) cat "$S/authdata" ;; *) exit 1 ;; esac
B
  cat > "$d/bin/chronyd" <<'B'
#!/usr/bin/env bash
S="$STUB_S"; echo "chronyd $*" >> "$S/calls"
[ "$1" = -p ] || exit 2
[ -f "$S/chronyd_reject" ] && { echo "Fatal error : Invalid directive at line 3 in file $3"; exit 1; }
grep -q '^server ' "$3" && exit 0 || exit 1
B
  cat > "$d/bin/timedatectl" <<'B'
#!/usr/bin/env bash
S="$STUB_S"
case "$*" in
  "show-timesync -p NTPMessage --value") grep -qx systemd-timesyncd "$S/active" && cat "$S/tsd_msg" ;;
  "show-timesync -p ServerName --value") grep -qx systemd-timesyncd "$S/active" && cat "$S/servername" ;;
  "show -p NTPSynchronized --value") cat "$S/synced" ;;
  "show -p LocalRTC --value") cat "$S/localrtc" ;;
  *) exit 1 ;;
esac
B
  cat > "$d/bin/dpkg-query" <<'B'
#!/usr/bin/env bash
v="$(awk -v p="${*: -1}" '$1==p{print $2}' "$STUB_S/pkgs")"; [ -n "$v" ] && echo "installed $v" || exit 1
B
  cat > "$d/bin/dpkg" <<'B'
#!/usr/bin/env bash
S="$STUB_S"; echo "dpkg $*" >> "$S/calls"
[ -f "$S/dpkg_fail" ] && exit 1
f="${*: -1}"; [ -f "$f" ] || exit 1
grep -q '^chrony ' "$S/pkgs" && { echo "conflicts with chrony"; exit 1; }
echo "systemd-timesyncd $(basename "$f" | cut -d_ -f2)" >> "$S/pkgs"
B
  cat > "$d/bin/apt-get" <<'B'
#!/usr/bin/env bash
S="$STUB_S"; R="$PFT_TIMESYNC_ROOT"; echo "apt-get $*" >> "$S/calls"
case "$*" in
  *download\ -q\ systemd-timesyncd=*) [ -f "$S/download_fail" ] && exit 100; v="${*: -1}"; v="${v#*=}"; : > "systemd-timesyncd_${v}_amd64.deb" ;;
  *--download-only*) [ -f "$S/download_fail" ] && exit 100; exit 0 ;;
  *install*chrony)
    [ -f "$S/install_fail" ] && exit 100
    { [ -x "$R/usr/sbin/policy-rc.d" ] && echo blocked || echo NOT-blocked; } > "$S/policy_at_install"
    grep -v '^systemd-timesyncd ' "$S/pkgs" > "$S/p.tmp"; echo 'chrony 4.2-2ubuntu2.1' >> "$S/p.tmp"; mv "$S/p.tmp" "$S/pkgs"
    grep -vx systemd-timesyncd "$S/active" > "$S/a.tmp"; mv "$S/a.tmp" "$S/active"
    mkdir -p "$R/etc/chrony/conf.d"; printf 'pool ntp.ubuntu.com iburst maxsources 4\nmakestep 1 3\n' > "$R/etc/chrony/chrony.conf"
    : > "$R/etc/chrony/conf.d/README" ;;
  *purge*chrony)
    grep -v '^chrony ' "$S/pkgs" > "$S/p.tmp"; mv "$S/p.tmp" "$S/pkgs"; rm -rf "$R/etc/chrony" ;;
  *) exit 0 ;;
esac
B
  cat > "$d/bin/docker" <<'B'
#!/usr/bin/env bash
S="$STUB_S"
case "$1" in
  inspect) if [ "$2" = -f ]; then [ "$4" = postfiatd ] && cat "$S/started"; else [ "$2" = postfiatd ]; fi ;;
  *) exit 0 ;;
esac
B
  cat > "$d/bin/rpc" <<'B'
#!/usr/bin/env bash
cat "$STUB_S/state"
B
  chmod +x "$d/bin/"*
}

use_env() {
  local d="$1"
  export STUB_S="$d/s" PFT_TIMESYNC_ROOT="$d/root" GOOD_TRACKING GOOD_SOURCES GOOD_AUTH BAD_TRACKING BAD_SOURCES BAD_AUTH
  export PFT_TIMESYNC_SYSTEMCTL="$d/bin/systemctl" PFT_TIMESYNC_CHRONYC="$d/bin/chronyc" PFT_TIMESYNC_CHRONYD="$d/bin/chronyd"
  export PFT_TIMESYNC_TIMEDATECTL="$d/bin/timedatectl" PFT_TIMESYNC_APTGET="$d/bin/apt-get" PFT_TIMESYNC_DPKGQ="$d/bin/dpkg-query"
  export PFT_TIMESYNC_DPKG="$d/bin/dpkg" PFT_TIMESYNC_DOCKER="$d/bin/docker" PFT_TIMESYNC_RPC="$d/bin/rpc"
  export SYNC_BUDGET=3 POLL_SEC=1 RESTART_WAIT=0
  unset PFT_TIMESYNC_INJECT CONTAINER
}

# a host already on chrony with the tool's own config (the good audit fixture)
chrony_host() {
  echo chrony > "$STUB_S/active"; echo 'chrony 4.2-2ubuntu2.1' > "$STUB_S/pkgs"
  mkdir -p "$PFT_TIMESYNC_ROOT/etc/chrony/conf.d" "$PFT_TIMESYNC_ROOT/etc/systemd/system/chrony.service.d"
  bash "$TOOL" plan | sed -n '/^# \/etc\/chrony\/chrony.conf$/,/^# \/etc\/systemd\/system/p' | sed '1d;$d' > "$PFT_TIMESYNC_ROOT/etc/chrony/chrony.conf"
  bash "$TOOL" plan | sed -n '/^# \/etc\/systemd\/system/,/^# boot-gate/p' | sed '1d;$d' > "$PFT_TIMESYNC_ROOT/etc/systemd/system/chrony.service.d/50-pft-timesync.conf"
}
