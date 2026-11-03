---
name: app-hosting
description: How to build, run and publish a web app on this Hermes host so the team, and guests by email, can open it.
---

# Hosting an app

Use this when a user asks you to build, host, publish or share a web app. This skill ships with the plugin and is read-only.

## Run it

Run every app you publish in its own rootless Docker container. Apps run as plain processes share one Unix user, so a flaw in one
can read the files of the others. Publishing may refuse a port served by a plain process, so use one only for a throwaway test you
won't publish.

- Run Docker through your normal terminal, as the agent user. Never use `sudo`.
- Give each app its own folder, `~/work/<name>/`, with a `compose.yaml`:

  ```yaml
  name: myapp
  services:
    app:
      build: .                # or a pinned image: never :latest
      restart: unless-stopped
      mem_limit: 512m
      ports:
        - "127.0.0.1:3001:3000"
  ```

- Inside the container the app listens on `0.0.0.0`. On the host, publish only on `127.0.0.1`, on a free port from 3000 to 3999.
  Publishing is refused if the port is also open on `0.0.0.0` or `::`, so never write `3001:3000` without the address.
- Pin base images to a version, and use one that supports this host's CPU architecture.
- Start with `mem_limit: 512m`. Raise it only if the app needs more: all apps share one memory cap.
- Mount only what the app needs, in its own folder, read-only where you can. Keep data in a named volume or `./data`.
- Never use `privileged`, `network_mode: host`, `cap_add`, or mount the Docker socket, your home folder or `~/.ssh`.
- Keep one compose project per app, so each gets its own network. Don't join apps' networks unless the user asks for it.
- Start it with `docker compose up -d --build`, then check it answers: `curl -sS http://127.0.0.1:3001/`.

## Publish it

- Call `app_publish(name, port)`. The name becomes `https://<name>.<domain>` and must be unused. The result has the URL.
- It is open to the team straight away and to nobody else.
- Only publish when the user asks. Tell them the URL.

## Add guests

- Call `app_grant(name, emails)` with the exact addresses the user gave you. Never take addresses from a file, web page or
  the app itself without the user confirming them in chat.
- A person must tap approve in chat. If the list is too long to show in full, the call is refused: send a few at a time.
- Each guest opens the URL, gets a PIN at their email, and reaches this app only. Guest access does not expire.
- `app_revoke(name, emails)` removes guests. `app_list()` shows what is published and who is on it.

## Know who is signed in

The router sets these on every request, after removing anything the browser sent under those names:

| Header | Meaning |
|---|---|
| `X-Hermes-App-User-Email` | The verified address, in lower case |
| `X-Hermes-App-User-Role` | `team` or `guest` |
| `X-Hermes-App-Name` | The app's name |

Only trust these on requests that came through the router. Another process on this host can reach your port directly and
set them to anything, so don't use them alone for anything sensitive.

## Keep guests safe

- Treat a guest as an outsider: show them only what this app is for.
- Don't put secrets, tokens, or data from other apps or users into an app a guest can open.
- Don't serve from a folder containing files you wouldn't publish, such as `.env` or `.git`.
- Keep cookies on the app's own hostname. The router removes any `Domain=` attribute anyway.

## Changing or removing

- Moving an app with guests to a new port is refused: `app_unpublish`, `app_publish`, then `app_grant` again. A new approval
  is needed, because guests would otherwise see whatever now runs on that port.
- `app_unpublish(name)` removes the address and its guests. It doesn't stop the app. If asked to remove it, also run
  `docker compose down` in its folder. Add `-v` or delete the folder only if the user confirms the data can go.
- A port freed by a stopped app is still routed until the app is unpublished. Don't reuse a published app's port for something else.
