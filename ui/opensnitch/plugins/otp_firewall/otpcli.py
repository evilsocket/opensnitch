"""Thin wrapper around the otp-toolkit `otp` and `otpfwctl` CLIs.

No Qt here on purpose: this module only shells out to the two binaries and
parses their stable, documented output formats, so it can be exercised and
reasoned about independently of the dialog that polls it.
"""
import os
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor

DEFAULT_OTP_BIN = "/usr/local/bin/otp"
DEFAULT_OTPFWCTL_BIN = "/usr/local/bin/otpfwctl"
DEFAULT_OTP_HOME = os.path.expanduser("~/.otp")
PROC_ENABLED = "/proc/otp_firewall/enabled"

STATE_NOT_LOADED = "not_loaded"
STATE_ENABLED = "enabled"
STATE_DISABLED = "disabled"
STATE_UNKNOWN = "unknown"


def resolve_bin(configured_path, default_abs_path):
    """Resolve a configured binary path: an explicit path wins if it exists,
    then $PATH, then the toolkit's documented install location - never a
    bare name, since that would end up handed to `pkexec` as-is."""
    if configured_path:
        expanded = os.path.expanduser(configured_path)
        if os.path.isfile(expanded):
            return expanded
    found = shutil.which(os.path.basename(default_abs_path))
    if found:
        return found
    return default_abs_path


def read_module_state():
    """Read the kernel module's enabled/disabled state. Never needs root."""
    try:
        with open(PROC_ENABLED, "r") as f:
            value = f.read().strip()
        return STATE_ENABLED if value == "1" else STATE_DISABLED
    except FileNotFoundError:
        return STATE_NOT_LOADED
    except Exception:
        return STATE_UNKNOWN


def set_module_state(otpfwctl_bin, enable):
    """Build the pkexec argv to flip the firewall on/off. Caller runs it
    (e.g. via QProcess) since this module makes no assumption about how the
    privileged prompt should be run asynchronously."""
    return ["pkexec", otpfwctl_bin, "enable" if enable else "disable"]


def list_contacts(otp_bin, otp_home):
    """Returns the contact names, or None if `otp` couldn't be run at all
    (missing binary, bad otp_home, timeout...) - kept distinct from an empty
    list, which means "ran fine, keychain has no contacts yet"."""
    try:
        result = subprocess.run(
            [otp_bin, "--list-contacts"],
            cwd=otp_home, capture_output=True, text=True, timeout=5,
        )
    except Exception:
        return None
    if result.returncode != 0:
        return None
    names = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("- "):
            names.append(line[2:].strip())
    return names


_PORCELAIN_RE = re.compile(r"^([a-zA-Z_]+)=(.*)$")


def contact_status(otp_bin, otp_home, name):
    """Parse `otp --status <name> --porcelain` into a flat dict."""
    try:
        result = subprocess.run(
            [otp_bin, "--status", name, "--porcelain"],
            cwd=otp_home, capture_output=True, text=True, timeout=5,
        )
    except Exception:
        return {}
    data = {}
    for line in result.stdout.splitlines():
        m = _PORCELAIN_RE.match(line.strip())
        if m:
            data[m.group(1)] = m.group(2)
    return data


_OFFSET_RE = re.compile(r"^\s*(EncryptionKeyOffset|DecryptionKeyOffset):\s*(\d+)\s*$")


def contact_offsets(otp_bin, otp_home, name):
    """Parse `otp --show-contact <name>` for the two byte offsets, which
    --status --porcelain deliberately doesn't expose."""
    try:
        result = subprocess.run(
            [otp_bin, "--show-contact", name],
            cwd=otp_home, capture_output=True, text=True, timeout=5,
        )
    except Exception:
        return {}
    offsets = {}
    for line in result.stdout.splitlines():
        m = _OFFSET_RE.match(line)
        if m:
            offsets[m.group(1)] = int(m.group(2))
    return offsets


def contact_snapshot(otp_bin, otp_home, name):
    status = contact_status(otp_bin, otp_home, name)
    offsets = contact_offsets(otp_bin, otp_home, name)
    return {
        "name": name,
        "enc_sequence": status.get("enc_sequence", "?"),
        "enc_offset": offsets.get("EncryptionKeyOffset", "?"),
        "enc_remaining": status.get("enc_key_remaining", "?"),
        "dec_sequence": status.get("dec_sequence", "?"),
        "dec_offset": offsets.get("DecryptionKeyOffset", "?"),
        "dec_remaining": status.get("dec_key_remaining", "?"),
    }


def keychain_snapshot(otp_bin, otp_home):
    """Returns a list of per-contact snapshots, or None if the contact list
    itself couldn't be fetched (propagated from list_contacts())."""
    names = list_contacts(otp_bin, otp_home)
    if names is None:
        return None
    if not names:
        return []
    # Each contact needs two subprocess calls (status + show-contact); run
    # contacts concurrently so a poll tick isn't O(2 * len(names)) sequential
    # `otp` invocations end to end.
    with ThreadPoolExecutor(max_workers=min(8, len(names))) as pool:
        return list(pool.map(lambda name: contact_snapshot(otp_bin, otp_home, name), names))
