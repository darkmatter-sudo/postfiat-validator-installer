"""The PFTAlertFlapping digest list must equal the alerts whose rules carry `notify: digest`."""

import glob
import os
import re

ALERTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "alerts")


def digest_alerts():
    names = set()
    for path in glob.glob(os.path.join(ALERTS, "*.rules.yml")):
        current = None
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()
        for line in lines:
            m = re.match(r"\s*- alert:\s*(\S+)", line)
            if m:
                current = m.group(1)
            elif re.match(r"\s*notify:\s*\"?digest\"?\s*$", line) and current:
                names.add(current)
    return names


def flapping_digest_list():
    with open(os.path.join(ALERTS, "alertstats.rules.yml"), encoding="utf-8") as fh:
        text = fh.read()
    m = re.search(r'"notify", "digest", "flapping_alert",\s*"([^"]+)"', text)
    assert m, "digest label_replace missing from PFTAlertFlapping"
    return set(m.group(1).split("|"))


def test_digest_list_matches_rules():
    found = digest_alerts()
    assert {"PFTValwatchValidatorLate", "PFTUpstreamFeedQuiet"} <= found  # presence control
    assert flapping_digest_list() == found
