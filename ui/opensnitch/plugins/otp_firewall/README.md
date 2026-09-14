# otp_firewall plugin

Adds an "OTP Firewall" entry to the main window's actions menu (Statistics
dialog) that opens a dialog to:

- Enable/disable the [otp-toolkit](https://github.com/) Linux kernel firewall
  (`otp_firewall.ko`), via `pkexec otpfwctl enable|disable`. A polkit prompt
  is shown since this needs root; reading the current state does not (it
  reads `/proc/otp_firewall/enabled` directly).
- Show a live-updating table of the firewall's keychain contacts: sequence
  number, byte offset and remaining key file size, for both the sent
  (encryption) and received (decryption) directions. Refreshed on a timer
  while the dialog is open, by shelling out to `otp --status --porcelain`
  and `otp --show-contact` (both documented as read-only).

## Enabling this plugin

Copy `example/otp_firewall.json` to
`$XDG_CONFIG_HOME/opensnitch/actions/otp_firewall.json` (usually
`~/.config/opensnitch/actions/otp_firewall.json`), adjusting the `config`
block if your `otp`/`otpfwctl` binaries or `~/.otp` keychain live somewhere
non-default, then restart the GUI to pick it up. The Statistics dialog and
this plugin's config are both built once at startup, so simply closing and
reopening the Statistics window does *not* reload a changed `config` block.

## Config keys

| Key | Default | Meaning |
|---|---|---|
| `otp_bin` | `/usr/local/bin/otp` | path to the `otp` CLI |
| `otpfwctl_bin` | `/usr/local/bin/otpfwctl` | path to `otpfwctl` |
| `otp_home` | `~/.otp` | working directory the CLIs are run from (holds `.keychain/`) |
| `poll_interval_ms` | `3000` | how often the dialog refreshes while open |

## Requirements

- otp-toolkit's `otp` and `otpfwctl` built and installed (see
  `firewall/linux-kernel-module/README.md` in otp-toolkit).
- A polkit agent running so `pkexec` can prompt for authentication.
