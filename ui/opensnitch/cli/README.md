# opensnitch-cli

A client for machines with no graphical environment.

`opensnitch-ui` is the usual way to answer "should this program be allowed to
connect?", but it needs Qt and someone in front of the screen. On a server there
is nobody to click, and the daemon only intercepts while a client is connected —
with none attached it falls back to `clientDisconnectedRule.Action`, so an
unattended server ends up allowing everything.

`opensnitch-cli` fills that gap. It is an addition, not a replacement: nothing
about `opensnitch-ui` changes.

* `opensnitch-cli serve` runs as a service, answers the daemon, and records every
  connection it hasn't seen before in a review queue.
* `opensnitch-cli review` goes through that queue afterwards, one connection at a
  time, and turns entries into permanent rules.

**Only one client can own a daemon's socket.** Run `opensnitch-ui` *or*
`opensnitch-cli serve`, not both.

## Why it can't simply ask you

The daemon holds the packet in a netfilter queue while it waits for an answer,
and gives up after 120 seconds. So `serve` cannot wait for a person: it answers
straight away with a short temporary rule and queues the connection. The decision
you take later is what governs every connection after that.

By default an unreviewed connection is **denied** for an hour and queued. The
temporary rule is short lived on purpose, so a connection nobody ever reviews
comes back to the queue instead of being decided for good.

If you would rather a server keep working while the queue waits for you, set
`policy.unreviewed_action = allow`. It is still recorded either way.

## Requirements

Python 3, and three modules that the graphical interface already depends on:

```
python3-grpcio  python3-protobuf  python3-slugify  python3-packaging
```

No PyQt. On Debian and Ubuntu:

```bash
sudo apt install python3-grpcio python3-protobuf python3-slugify python3-packaging
```

## Installing

Until the packaging is split (see "Packaging" below), the deb and rpm both pull
in PyQt6 for the graphical interface, so on a server install from source. The
code itself needs no Qt.

```bash
git clone https://github.com/evilsocket/opensnitch.git /opt/opensnitch
cd /opt/opensnitch/ui
sudo pip3 install .
```

On distributions that refuse a system wide `pip install` (Debian 12 and later,
Ubuntu 24.04 and later) either add `--break-system-packages`, or skip installing
altogether and run it out of the source tree:

```bash
sudo PYTHONPATH=/opt/opensnitch/ui /opt/opensnitch/ui/bin/opensnitch-cli --help
```

`setup.py` declares no dependencies, so installing it will not drag PyQt6 in.

## Pointing the daemon at it

The daemon and the client have to agree on a socket. The default on both sides is
`unix:///tmp/osui.sock`, so if you are keeping that, there is nothing to change.

To use a socket that is not world traversable, set it in
`/etc/opensnitchd/default-config.json`:

```json
{
    "Server": {
        "Address": "unix:///run/opensnitch/cli.sock"
    }
}
```

and the same value in `/etc/opensnitch/cli.conf`:

```ini
[server]
address = unix:///run/opensnitch/cli.sock
```

Then restart the daemon: `sudo systemctl restart opensnitchd`.

## Running it as a service

```bash
sudo cp /opt/opensnitch/ui/resources/init/opensnitch-cli.service /etc/systemd/system/
sudo cp /opt/opensnitch/ui/resources/cli.conf.example /etc/opensnitch/cli.conf
sudo systemctl daemon-reload
sudo systemctl enable --now opensnitch-cli
```

Make sure the graphical interface is not running first:

```bash
sudo systemctl stop opensnitch-ui 2>/dev/null; pkill -f opensnitch-ui
```

The unit keeps its database in `/var/lib/opensnitch` (`StateDirectory=`,
mode 0700). It sets `PrivateTmp=no` because the default socket lives in `/tmp`;
if you moved the socket to `/run/opensnitch` as above, uncomment
`RuntimeDirectory=opensnitch` and set `PrivateTmp=yes`.

## Checking that it works

Run `serve` in the foreground the first time, so you can see what it does.

**1. Start it and confirm the daemon connects.**

```bash
sudo opensnitch-cli serve --log-level debug
```

You should see it listening, and then the daemon's log
(`journalctl -fu opensnitchd`) should show `Connected to the UI service` and
`Start receiving notifications`. Confirm from another terminal:

```bash
sudo opensnitch-cli nodes
```

```
ADDRESS                  HOSTNAME           DAEMON    ONLINE  LAST SEEN
unix:/local              server1            1.9.0     yes     2026-08-14 20:17:05
```

`ONLINE` means `serve` has heard from the daemon in the last minute and a half,
not merely that it connected once. `DAEMON` must be 1.6.0 or later, see
"When something is wrong".

**2. Make a connection that has no rule yet.**

```bash
curl -sS https://example.com
```

With the default policy this should **fail**, and `serve` should log the
connection and the rule it answered with.

**3. It should be in the queue.**

```bash
sudo opensnitch-cli pending
```

```
ID    PROCESS                      DESTINATION                            SEEN
1     /usr/bin/curl                example.com:443                        1x
```

Running `curl` again does **not** increase `SEEN`: the temporary rule now matches,
so the daemon stops asking. That is expected. To watch the counter move, set
`unreviewed_duration = 30s` and try again after it expires.

**4. Approve it.**

```bash
sudo opensnitch-cli review
```

```
──────────────────────────────────────────────────────────────
[1/1]  unix:/local   seen 1x   first 2026-08-13 20:17:05   last 2026-08-13 20:17:05
  /usr/bin/curl   pid 41233  uid 1000
  -> tcp  example.com (93.184.216.34)  port 443
  currently deny for 1h, 59m12s left (temporary rule cli-auto-9f2a1b3c4d5e)

  proposed rule: allow-always-simple-usr-bin-curl
    allow always
      process.path is /usr/bin/curl

  [y]es [n]o [r]eject [e]dit [s]kip [d]rop [i]nfo [q]uit ?
```

Press `y`. It should say the rule was queued, and within a second `serve` should
log a `DELETE_RULE` for the temporary rule followed by a `CHANGE_RULE` for the
new one.

One approval can settle several entries at once: everything still in the queue
that the new rule covers is closed too, and each of their temporary rules is
withdrawn — you are not asked once per destination for the same program. Only a
rule that outlives the queue (`always`, `until restart`) settles other entries;
a temporary decision answers just the one you were shown.

**5. Confirm the rule reached the daemon.**

```bash
ls /etc/opensnitchd/rules/ | grep allow-always
sudo opensnitch-cli status         # notifications failed should be 0
curl -sS https://example.com       # should now succeed
```

Only `always` rules are written to disk by the daemon; everything shorter lives
in its memory.

**6. Check the deny path.**

```bash
curl -sS https://example.org
sudo opensnitch-cli deny $(sudo opensnitch-cli pending --json | python3 -c 'import json,sys;print(json.load(sys.stdin)[0]["id"])')
curl -sS https://example.org       # should still fail
```

**7. Check that a decision survives the service being stopped.**

```bash
sudo systemctl stop opensnitch-cli
sudo opensnitch-cli allow <id>          # queued, not sent
sudo opensnitch-cli status              # notifications queued: 1
sudo systemctl start opensnitch-cli
sudo opensnitch-cli status              # back to 0, the rule was sent on start up
```

## Editing a rule before applying it

`e` in the review loop opens the editor. It offers the same choices the graphical
pop-up does, because both are built from the same code
(`ui/tests/cli/test_operands_parity.py` checks they cannot drift apart):

```
  1) match on     process.path is /usr/bin/curl
  2) action       allow
  3) duration     always
  4) name         allow-always-simple-usr-bin-curl
  5) also require (nothing)
  6) precedence   no
  a) apply    c) cancel
```

`1` lists everything the connection can be matched on:

```
    1) /usr/bin/curl                            simple process.path
    2) /usr/bin/curl -sSL https://api.github.com/repos  simple process.command
    3) api.github.com                           simple dest.host
    4) ^(|.*\.)github\.com$                     regexp dest.host
    5) 140.82.121.6                             simple dest.ip
    6) 140\.82\..*                              regexp dest.ip
    7) 140.82.121.0/24                          network dest.network
    8) 443                                      simple dest.port
    9) 1000                                     simple user.id
    c) something else, typed by hand
```

So you can approve the executable, the exact command line, one host, a whole
domain and its subdomains, an address range, a network, a port, a user, or a
pattern of your own. `c` asks for the type, operand and value directly.

`5` adds further conditions, which produces a `list` rule — the same thing the
pop-up's "also match" checkboxes build.

**The proposed rule matches the executable, not the destination.** That is the
pop-up's default too. So `y` allows the program to reach anywhere, and `n`
blocks it everywhere — not just the destination you were shown. If you only mean
this destination, use `e` and pick the host or address, or
`--match dest.host` on the command line. The rule is always printed before it is
queued, so check the operand line before answering.

Matching on the command line is treated carefully: a program picks its own
`argv[0]`, so when it is not an absolute path (or lives under `/proc`) the
executable is pinned as well, and you are told why. The pop-up does the same
thing.

Patterns are checked before they are sent. The daemon compiles regular
expressions with Go's RE2, which has no lookaround and no backreferences, so
those are refused up front instead of being silently dropped by the daemon. A
pattern with upper case letters on a non case sensitive operand is flagged too,
because the daemon lowercases it and it would never match.

## Commands

| Command | What it does |
| --- | --- |
| `serve` | answer the daemon and record connections |
| `review` | go through the queue one at a time |
| `pending [--json] [--node N] [--limit N] [--decided]` | list what is waiting, or what was decided |
| `allow ID [--match OPERAND] [--duration D] [--name N]` | approve without prompting |
| `deny ID` / `reject ID` | refuse without prompting |
| `drop ID` | remove from the queue without creating a rule |
| `undo ID\|NAME [--node N]` | take a decision back: withdraw its rule, re-queue the connection |
| `rules [--node N] [--json]` | the rules each daemon has |
| `rule delete\|enable\|disable NAME [--node N]` | change a rule the daemon has |
| `nodes [--json]` | daemons that have connected, with their version |
| `status [--json] [--retry\|--clear]` | queue depth, nodes, and rules the daemon rejected |

`status` exits non-zero if any rule was rejected, so it works as a monitoring
check. `--retry` sends the rejected rules once more; `--clear` forgets them and
puts their connections back in the review queue, so the decision can be taken
again differently.

`--match` takes an operand name, for example:

```bash
sudo opensnitch-cli allow 3 --match dest.host --duration always
```

## Managing the rules a daemon has

`rules` lists them, and `rule` changes them:

```bash
sudo opensnitch-cli rules
sudo opensnitch-cli rule disable allow-always-simple-usr-bin-curl
sudo opensnitch-cli rule enable allow-always-simple-usr-bin-curl
sudo opensnitch-cli rule delete allow-always-simple-usr-bin-curl
```

Like a decision from `review`, these go through the outbox: `serve` sends them
within a second, or as soon as the daemon is back. Deleting an `always` rule
removes its file from `/etc/opensnitchd/rules`; deleting a temporary one takes
it out of the daemon's memory, which is the only way to get rid of an
`until restart` rule short of restarting the daemon.

The list starts as what the daemon reported when it connected and is kept in
step with every change the daemon confirms, so it stays accurate while `serve`
runs. It does not see rules that expire on the daemon on their own, or that
were edited on disk by hand, until the daemon reconnects. With more than one
node, `--node` says which daemon is meant; with one, it is implied.

## Changing your mind

A decision is a rule, so taking it back means withdrawing the rule.
`pending --decided` lists what was decided, with the rule each connection
got, and `undo` withdraws that rule and puts the connection back in the
queue, exactly as if it had never been answered. It takes the queue id from
that list, or the rule's name from `rules` — whichever you are looking at:

```bash
sudo opensnitch-cli pending --decided
sudo opensnitch-cli undo 7
sudo opensnitch-cli undo deny-always-simple-usr-bin-curl   # the same thing, by name
sudo opensnitch-cli undo deny-always-simple-usr             # a prefix will do, if only one rule fits
sudo opensnitch-cli review           # it is back, decide again
```

`rule delete|enable|disable` take a prefix the same way. One that fits several
rules is refused and the choices listed.

If one approval settled several queued connections (see "Approve it" above),
undoing any of them brings all of them back, since the one rule that answered
them is going away.

A name given by hand — `allow ... --name`, or `4` in the editor — is refused if
a rule of that name exists, because the daemon would replace it without a word.
Delete the old one first if that is what you mean.

## Configuration

`/etc/opensnitch/cli.conf`, or `~/.config/opensnitch/cli.conf`. Running with no
configuration file at all works; the defaults are the whole contract. See
`resources/cli.conf.example` for the annotated version. The settings that matter
most:

| Setting | Default | Meaning |
| --- | --- | --- |
| `server.address` | `unix:///tmp/osui.sock` | must match the daemon's `Server.Address` |
| `server.auth_type` | `simple` | `simple`, `tls-simple` or `tls-mutual`, same as the GUI |
| `policy.unreviewed_action` | `deny` | `allow` makes it fail open |
| `policy.unreviewed_duration` | `1h` | how long that answer lasts before it is asked about again |
| `policy.default_action` | `deny` | what the daemon does while it is already asking about another connection |
| `policy.queue_max` | `1000` | stop recording past this many; connections are still answered |
| `db.path` | `/var/lib/opensnitch/cli.db` | the queue |

Durations are what Go's `time.ParseDuration` accepts — `30s`, `5m`, `1h30m` —
plus `until restart` and `always`. **Days and weeks are not supported by the
daemon.** `once` is refused: a rule with that duration sent over the
notifications channel is never removed and would live until the daemon restarts.

## TLS

Exactly the same options and certificates the graphical interface uses:

```ini
[server]
auth_type = tls-simple
tls_ca_cert = /etc/opensnitch/ca.crt
tls_cert = /etc/opensnitch/server.crt
tls_key = /etc/opensnitch/server.key
```

## When something is wrong

**The daemon does not connect.** Check both ends agree on the address, and that
the socket exists: `ls -l /tmp/osui.sock` should be `srw-r-----`. If you are
running under systemd with the default socket, `PrivateTmp` must be `no` or the
daemon is looking at a different `/tmp`.

**`could not listen on ...`** — something already owns that socket, almost always
`opensnitch-ui`. Only one client per daemon.

**`daemon version X is older than 1.6.0`** in the `serve` log. The notification
types were renumbered in daemon 1.6.0, and an older daemon does not refuse what
this client sends — it misreads it, so every decision would be thrown away
while `status` reports it delivered. Distribution packages can be that old
(Ubuntu 24.04 ships 1.5.8). Upgrade the daemon; `nodes` shows each daemon's
version.

**`Permission denied` opening the database.** The queue decides what the machine
may connect to, so it is root-only. Use `sudo`.

**A rule never took effect.** `sudo opensnitch-cli status` lists rules the daemon
refused, with its own error message. The usual causes are a regular expression
RE2 cannot compile and a duration Go cannot parse. A refused rule stays listed,
and `status` keeps exiting non-zero, until you deal with it: `status --clear`
drops it and returns the connection to the review queue so you can decide it
again, `status --retry` sends it once more. If `notifications queued` is
not zero, the decisions simply have not been delivered yet: `serve` was not
running, or the daemon was not connected — `review` warns about this when it
finishes. Nothing is lost: they go out as soon as both are back, and until then
`serve` answers a daemon that asks about a covered connection with the decided
rule itself instead of a new temporary one.

**Everything is blocked and you need to get out of it.** Set
`policy.unreviewed_action = allow` and restart, or stop `opensnitch-cli`
entirely: with no client connected the daemon applies its own `DefaultAction`
from `/etc/opensnitchd/default-config.json`.

## Differences from the graphical interface

* No live connection or statistics browsing. The daemon's `Ping` statistics are
  not stored; the review queue is fed by the connections the daemon actually asks
  about.
* No firewall (nftables) configuration.
* No rules editor beyond `rule delete|enable|disable`: to change what a rule
  matches, delete it and approve a new one from the queue.
* Multiple nodes are recorded and can be filtered with `--node`, but there is no
  per-node management beyond that.
* It never blocks waiting for a person, by design.

## Packaging

`setup.py` declares no dependencies, so installing from source or with `pip`
pulls in nothing: a server gets the client and the three modules listed under
Requirements, and no Qt. `ui/tests/cli/test_no_qt.py` imports the whole package
in a fresh interpreter and fails if anything reaches Qt.

The deb and rpm build one binary package, `python3-opensnitch-ui`, which depends
on PyQt6 for the graphical interface, so the client ships inside it. Giving it a
package of its own would mean splitting the shared modules out into a third one —
worth doing only if there is demand for `apt install opensnitch-cli` on servers.

## Tests

```bash
cd ui/tests && pytest -v cli/
```

They need neither Qt nor a display.
