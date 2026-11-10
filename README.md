# hermes-app-platform

Lets a team publish apps their [Hermes Agent](https://github.com/NousResearch/hermes-agent) built, and let guests in
by email, on a self-hosted box behind a Cloudflare Tunnel and Cloudflare Access.

1. A teammate asks the bot to publish an app the AI built.
2. It is immediately open to the team.
3. Any teammate asks the bot to let in Alice and Bob by email, and taps approve.
4. Alice opens the URL, gets a Cloudflare Access PIN at her email, and reaches only that app.

Built for Hermes v0.22.5.

## How it fits together

```
browser ─► Cloudflare Access (any email with a PIN) ─► tunnel *.<domain> ─► router ─► 127.0.0.1:<port> app
                                                                              │ reads
Telegram ─► Hermes ─► plugin ─► inbox ─► root gatekeeper ─► registry ─────────┘
            (hermes-user)                                   team.txt (edited by hand)
```

| Part | Runs as | Job |
|---|---|---|
| `plugin/` | `hermes-user`, inside Hermes | Tools `app_publish`, `app_unpublish`, `app_list`, `app_grant`, `app_revoke`. Takes the sender from the session. Gets a person's approval for grants. Tells the owner. |
| `gatekeeper/` | root, started by a systemd path unit | Validates each request and is the only writer of the registry. Never touches the tunnel. |
| `router/` | `hermes-app-router`, a dedicated low-privilege user | Verifies the Access token itself, and decides who reaches which app. **Once the wildcard Access policy allows any email, this is the real lock.** |

Once the wildcard Access policy allows any email with a PIN, Access only proves someone owns an address. The router alone
decides whether that address gets in.

### Who gets what

| Caller | Result |
|---|---|
| No token, or a forged, expired or wrong-audience one | 401, whatever the hostname |
| Valid token, hostname isn't a published app | 404 |
| Valid token, on the team list | Proxied to any app |
| Valid token, a guest of this app | Proxied to this app only |
| Valid token, anyone else | 403 |
| The registry or team file can't be trusted | 503 |

### Router implementation

Go, using the standard library only: no third-party modules at all, so `go.sum` doesn't exist.

- `net/http` and `httputil.ReverseProxy` are a widely used proxy that handles WebSockets, streaming, and malformed or
  ambiguous HTTP. A hand-written proxy in Python would have to get request parsing right itself, which is how
  smuggling bugs happen; a framework-based one would need `aiohttp`, `cryptography` and a virtual environment, with
  hand-written WebSocket relaying.
- `crypto/rsa` checks the token signature. The JWT handling around it is about 100 lines, accepts only RS256 and is pinned
  to one issuer and one audience. A JWT library would mostly add algorithm options that have to be turned off.
- It builds to one static binary for any platform, including arm64 Linux, with `CGO_ENABLED=0`.

The gatekeeper and plugin use the Python standard library only. The plugin declares no dependencies, so installing it
triggers no dependency prompt or environment rebuild.

## Install

Run these as an admin user on the host. Replace `hermes-user` and `agent-user` if yours differ. Do the steps in order: Access stays
restrictive until the very end.

### 1. Build the router

On any machine with Go 1.22 or newer:

```bash
cd router && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o hermes-app-router .
```

Copy the binary to the host, as `/usr/local/bin/hermes-app-router`, mode `755`.

### 2. Create the user and folders

```bash
sudo adduser --system --group --no-create-home --home /nonexistent hermes-app-router
sudo install -d -m 755 -o root -g root /srv/hermes-apps /etc/hermes-apps /var/lib/hermes-apps
sudo install -d -m 700 -o hermes-user -g hermes-user /srv/hermes-apps/inbox /srv/hermes-apps/inbox/tmp /srv/hermes-apps/inbox/new
sudo install -d -m 750 -o root -g hermes-user /srv/hermes-apps/results
sudo install -d -m 750 -o root -g hermes-app-router /var/lib/hermes-apps/registry
```

The inbox is only reachable by `hermes-user`, so AI-written code running as `agent-user` can't publish by itself. Check that
`agent-user` isn't in the `hermes-user` group.

### 3. Install the gatekeeper

```bash
sudo install -m 755 -o root -g root gatekeeper/hermes-app-gatekeeper /usr/local/sbin/hermes-app-gatekeeper
sudo install -m 644 -o root -g root deploy/gatekeeper.example.json /etc/hermes-apps/gatekeeper.json
sudo install -m 644 deploy/systemd/hermes-app-gatekeeper.path deploy/systemd/hermes-app-gatekeeper.service /etc/systemd/system/
```

Edit `/etc/hermes-apps/gatekeeper.json`. Set `domain` and the users, and list in `reserved_names` every hostname with a fixed tunnel
route, such as the dashboard and browser. Then:

```bash
sudo /usr/local/sbin/hermes-app-gatekeeper --check-config
```

```bash
sudo systemctl daemon-reload
```

```bash
sudo systemctl enable --now hermes-app-gatekeeper.path
```

### 4. Install the router, not yet routed

```bash
sudo install -m 644 -o root -g root deploy/router.example.json /etc/hermes-apps/router.json
sudo install -m 644 -o root -g root deploy/team.example.txt /etc/hermes-apps/team.txt
sudo install -m 644 deploy/systemd/hermes-app-router.service /etc/systemd/system/
```

Edit `router.json`. `aud` is the audience tag of the wildcard Access application, and `team_domain` is `<team>.cloudflareaccess.com`.
Keep `listen` outside the app port range: `agent-user` can reach that range, and the router refuses to start otherwise. Edit
`team.txt` to list the team. It is read on every check, and so is the registry, so neither needs a restart.

```bash
sudo -u hermes-app-router /usr/local/bin/hermes-app-router -config /etc/hermes-apps/router.json -check
```

```bash
sudo systemctl daemon-reload
```

```bash
sudo systemctl enable --now hermes-app-router
```

Without a token it must refuse: this should print 401.

```bash
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: anything.example.com' http://127.0.0.1:8790/
```

Also confirm `agent-user` can't connect to the router's port, if you use a loopback firewall allowlist.

### 5. Install the plugin

```bash
sudo -iu hermes-user hermes plugins install "https://github.com/terrence0488/hermes-app-platform#plugin" --ref <commit>
```

Create `~hermes-user/.hermes/app_platform.json` from `plugin/app_platform.example.json`, with `notify_target` set to the owner's
chat. Mode `600`, owned by `hermes-user`. Then:

```bash
sudo -iu hermes-user hermes plugins enable app_platform
```

Restart the gateway, then see [Verify after install](#verify-after-install).

### 6. Add the tunnel route

Add one rule to `cloudflared`'s ingress, **after** the fixed routes and before the catch-all:

```yaml
  - hostname: "*.example.com"
    service: http://127.0.0.1:8790
    originRequest:
      access:
        required: true
        teamName: <team>
        audTag: [<wildcard app aud>]
```

Publishing an app needs no further `cloudflared` restart. Rules match top-down, so fixed routes such as the dashboard stay
ahead of it, and their own MFA Access apps still apply.

### 7. Test with the Access policy unchanged

The wildcard Access app still allows only the team. Run the checks below with a team login.

### 8. Only then, open the Access policy

**Change the wildcard Access policy to allow any email with a PIN only after every check below has passed.** Until then a mistake in the
router costs nothing, because Access still stands in front of it. After it, the router is the only lock.

1. Router live and refusing without a token (step 4).
2. A team login reaches a published app, through the tunnel.
3. WebSockets work through the tunnel, if any app uses them.
4. Temporarily add a test address to the Access policy. Confirm it gets 403 on an app, then add it as a guest and confirm it reaches that
   app and still gets 403 on another.
5. Confirm fixed routes are unaffected: the dashboard and browser still ask for MFA, and the test address can't open them. The fixed
   apps must have their own, more specific Access applications, and keep their own policies.
6. Change the wildcard policy. Repeat check 4 with an address that isn't in any list, and expect 403.

To back out, restore the Access policy first.

## Verify after install

Run the real-Hermes test as `hermes-user`, from a clone outside `plugin/`. It uses a throwaway Hermes home and sends nothing:

```bash
APP_PLATFORM_REAL_HERMES=1 PYTHONDONTWRITEBYTECODE=1 hermes --run-module unittest discover -v -s <repo>/tests -p 'test_hermes_integration.py'
```

Then in chat:

- Build something small on port 3001, and ask the bot to publish it. Open the URL.
- Ask the bot to let in a test address. The prompt must show the app and the exact address. Tap deny: nobody is added. Ask again and tap
  approve: the address is added, and the owner gets a message naming who added whom.
- From another account, confirm what `app_list` shows. Ask it to remove the guest. An open page should stop working within `recheck_seconds`.
- Turn on `/yolo` and ask for a grant. It must be refused. Turn `/yolo` off.

## Configuration

| File | Owner, mode | Holds |
|---|---|---|
| `/etc/hermes-apps/gatekeeper.json` | root, `644` | Domain, users, port range, caps, folders |
| `/etc/hermes-apps/router.json` | root, `644` | Listen address, domain, Access team and audience, folders |
| `/etc/hermes-apps/team.txt` | root, `644` | One team email per line. No domain rule |
| `/etc/hermes-apps/launcher.json` | root:`hermes-app-router`, `640` | Optional launcher tools and groups (see below) |
| `/var/lib/hermes-apps/registry/<app>.json` | root:`hermes-app-router`, `640` | `{"name", "port", "created_by", "created_at", "guests": []}` |
| `~hermes-user/.hermes/app_platform.json` | `hermes-user`, `600` | Inbox and results paths, allowed platforms, owner's chat |

None of them holds a secret. The router needs outbound HTTPS to fetch `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`.

To add a teammate, edit `team.txt`. To remove one, edit it again: open connections end within `recheck_seconds`.

## Launcher page (optional)

One page, for example `apps.<domain>`, that lists for the signed-in person the fixed tools they may open (set by hand) and
the published apps they can reach (from the registry). It only links: each tool keeps its own Access application, and each app
is still checked as usual. The AI can't change it: both sources are root-owned.

1. Reserve the name: add `apps` to `reserved_names` in `gatekeeper.json`, then `--check-config`.
2. Write `/etc/hermes-apps/launcher.json` from `deploy/launcher.example.json`, owned `root:hermes-app-router`, mode `640` (it names
   people). `groups` are lists of lower-case emails; `visible_to` names groups, or `team` for `team.txt`. A tool's address is always
   `https://<name>.<domain>/`, so a tile can't point anywhere else. Icons are built in: `vault`, `files`, `browser`, `app`, `chart`,
   `chat`. Mirror each tool's own Access policy in `visible_to`; the launcher can't read it.
3. Add `"launcher_host": "apps"` and `"launcher_file": "/etc/hermes-apps/launcher.json"` to `router.json`, run `-check`, restart.
   The wildcard tunnel route and Access app already cover the name.

Who sees what: a tool appears to the members of its `visible_to` groups; an app appears to the team and to its own guests. Someone
with nothing gets "Nothing here for you yet." The page needs a valid token like everything else (401 without), takes `GET`/`HEAD` on
`/` only, carries no external resources, and is sent with a hash-pinned CSP, `X-Frame-Options: DENY`, `no-store` and `noindex`. A
launcher file or registry entry that can't be trusted is left out and the page says some shortcuts couldn't be loaded; `-check`
refuses it outright. Edits apply on the next page view.

## What is enforced in code

**Router**

- Checks the token signature with the team's keys (RS256 only, 2048-bit keys or longer), then issuer, audience and expiry. Keys
  are refreshed hourly and not trusted once 24 hours old. A made-up key id can cause at most one fetch a minute.
- Never reads the email header. An address counts only if it comes out of a verified token.
- Addresses must be ASCII and are then lower-cased, the same way in all three parts. `tests/email_vectors.json` holds the shared cases.
- Removes client-sent identity headers, treating `_` like `-`, and sets `X-Hermes-App-User-Email`, `X-Hermes-App-User-Role` and
  `X-Hermes-App-Name` itself.
- Never passes the Access token or `CF_*` cookies to an app. An app holding them could reach whatever else that user can.
- Won't let an app set `CF_*` cookies, and removes `Domain=` from an app's cookies so each stays on its own hostname.
- Reads the registry and team file on every check. Refuses them if they are symlinks, not root-owned, or writable by group or others.
- Rechecks long-lived connections every `recheck_seconds`, and closes them when the guest or app is removed, the port changes, or the token expires.
- Refuses to start on a non-loopback address, or on a port inside the app range.

**Gatekeeper**

- Reads requests without following links or blocking on a FIFO. Refuses directories, hard links, files of another owner and oversize files.
- Refuses duplicate JSON keys and any field that isn't expected for the action, so a request can't set `guests` or `created_by`.
- Checks the name, reserved names, port range and collisions. The listener must be bound to exactly `127.0.0.1` and owned by the agent user.
- With `require_container`, refuses a port not held by `/usr/bin/rootlesskit`, so apps run in rootless Docker containers. This keeps apps in containers by default and isn't a security boundary: the agent user can run rootlesskit itself.
- Caps apps, guests per app and addresses per request. Refuses to act on a damaged registry.
- Refuses to move an app with guests to a new port. Publishing needs no approval, so this would otherwise show guests something nobody approved.
- Unpublishing forgets the guests, so they don't return if the name is reused.

**Plugin**

- Takes the sender from the Hermes session, and refuses with no sender or on a platform that isn't allowed. An environment variable can't
  stand in for a session.
- Shows the exact app and addresses in the approval prompt. If they would not fit in full, or Hermes's secret redaction would mask part of an address, the call is refused rather than shown altered.
- **Requires proof a person approved.** Hermes skips its prompt and reports approved when YOLO or `approvals.mode: off` is on, and runs
  a tool anyway if hook dispatch itself fails. So the hook opens a ticket for the exact sender, app and addresses; Hermes's `post_approval_response` observer marks
  it only for `once`, `session` or `always`; the handler spends one marked ticket. Denied, timed out, skipped or rewritten arguments all
  mean nobody is added. Each rule key is used once, so an "always" answer can't cover a later grant.
- Writes only to an inbox that `agent-user` can't reach.

## Known limits

- **Who can publish is decided by Hermes.** Anyone allowed to talk to the bot, such as `TELEGRAM_ALLOWED_USERS`, is treated as a teammate by the
  plugin, separately from `team.txt`. Keep the two lists in step.
- **Approval says a person tapped, not which person.** Whoever can answer in that chat can approve. Avoid adding the bot to groups.
- **The AI can publish without approval**, and any teammate's request reaches the whole team at once. That's the design: apps are private to
  the team, and only guests need approval.
- **Strangers can test for app names.** Once anyone can get a PIN, anyone can tell 403 (exists) from 404 (doesn't) with a valid token. Don't put
  secrets in app names.
- **Apps aren't isolated from each other.** They run as one Unix user and can reach each other's ports directly on loopback. A direct request can
  set `X-Hermes-App-User-*` to anything, so an app can trust those headers only for traffic that came through the router.
- **Apps share a site.** Sibling subdomains can still send same-site requests to each other. Cookies are kept host-only, but apps should
  still use their own CSRF protection.
- **A port isn't rechecked after publishing.** If an app dies and something else takes its port, the router sends traffic there. Unpublish apps
  you stop.
- **Address variants aren't merged.** `a.b@gmail.com` and `ab@gmail.com` reach one inbox, but only the exact address listed gets in. This fails safe.
- **Guest access has no expiry.** A guest stays until removed, though Access sessions still expire and need a new PIN.
- **An open connection can outlast a removal by up to `recheck_seconds`.** 30 by default.
- **A compromised `hermes-user` can do anything a teammate can through this platform,** including `grant` directly to the inbox: the approval is enforced
  in the plugin, inside that user's process. The owner notice would also be skipped. It can't touch the registry except through these checked requests, and it can't change the team.
  The gatekeeper logs each change, with the claimed sender, to the journal.
- **The notice is best effort.** It calls the same function as `hermes send`, in the gateway's process: `send_message` is deliberately not a registered Hermes tool, and starting `hermes send` for each grant would add a slow process start and more to go wrong, with the same result. If it fails, the grant stands, the tool result says `owner_notified: false`, and the failure is logged. Hermes also copies the notice into the owner's session, including the sender's cleaned display name.
- **Requests apply in arrival order.** The gatekeeper handles one at a time, so a `grant` and an `unpublish` from different people can race in the ordinary way.
- **HTTP/1.1 only** between cloudflared, the router and apps.

## What has not been tested

Results on real arm64 Ubuntu 24.04 with Hermes v0.22.5 were reported by the deployment at commit `30b01a8`. Later code changes are noted below.

| Check | Status |
|---|---|
| Router: tokens, access rules, headers, cookies, streaming, WebSockets, revocation | **Ran for real** on macOS with `go test -race`: real RSA signatures, real loopback sockets, real upstream servers, hand-framed RFC 6455. The certs endpoint is a local fake |
| Router tests on arm64 Linux | **Ran for real**, without `-race`. Real Access keys were fetched |
| Launcher page: tokens, per-person tiles, bad and untrusted files, escaping, CSP hashes | **Ran for real** in `go test` (no `-race`, in `golang:1.25-alpine`). On the host: 401 without or with a forged token, `-check` passes |
| Launcher with a real Access token in a browser | **Not run yet** |
| Router with a real Access token, through the real tunnel | **Ran for real**: the owner's browser login reached a published app |
| Gatekeeper logic and hostile requests | **Ran for real** on temp folders, as an ordinary user. `check_listener`, `chown` and user lookups are faked |
| Gatekeeper with real `ss`, `/proc`, root, plain and rootless Docker listeners, under the hardened unit | **Ran for real**, as designed. A `hermes-user` listener, `[::1]`, no listener, a reserved name, an out-of-range port, a collision, an extra field and a symlink were refused. A live `0.0.0.0` listener was deliberately not run; unit tests cover it |
| systemd units | `systemd-analyze verify` is clean, and both units run |
| Plugin to real gatekeeper code | **Ran for real** through the inbox, with the same three fakes |
| Registry written by the real gatekeeper, read by the real router | **Ran for real** |
| Real Telegram approval | **Ran for real**: the prompt showed the app and exact address, deny blocked, approve added the guest |
| Install with the command in this README | **Ran for real** |
| `tests/test_hermes_integration.py` | Its earlier 5 tests passed on real Hermes one at a time at `30b01a8`, and interfered when run together. The test setup and owner-notice tests have since been rewritten. **The current file has not been run** |
| Owner notice | The first path never sent (`Unknown tool: send_message`). The replacement has only run against a stand-in. **Not yet run on real Hermes or real Telegram** |
| A second real guest account through the tunnel | **Not run** |
| WebSockets through the real tunnel | **Not run** |
| `/yolo` live | **Not run.** `approvals.mode: off` is covered in the real-Hermes test file |
| The Access policy change | **Not run** |

## Tests

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

```bash
cd router && go test -race ./...
```

To run the Go tests in a container, mount the whole repo, not only `router/`: they read `tests/email_vectors.json` and `tests/write_registry_entry.py`.

The Python suite needs only the standard library, and skips the real-Hermes file unless it is asked for. Don't run the real-Hermes file
with your working directory inside `plugin/`.

## Licence

MIT
