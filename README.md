# WebDecoy CLI

`webdecoy` connects AI assistants that run MCP servers as local commands to
[WebDecoy](https://webdecoy.com). Sign in once with a code in your browser;
your assistant then runs `webdecoy mcp` and gets WebDecoy's tools: install
WebDecoy in your app, check it is reporting, and ask about your sites' bot
traffic and protection.

Assistants that connect to remote MCP servers directly (Claude.ai, Claude
Code, ChatGPT, Codex) don't need this: see
[Connect an AI assistant](https://docs.webdecoy.com/installation/ai-assistants/).

## Install

```sh
brew install webdecoy/tap/webdecoy
```

Or download a binary from [Releases](https://github.com/WebDecoy/cli/releases)
(macOS and Linux, Intel and Apple silicon / ARM) and check it against
`checksums.txt`.

## Use

```sh
webdecoy login            # prints a code; approve it in your browser
webdecoy status           # who is signed in, which sites this app can read
```

After signing in, approve which sites the CLI may read at
https://app.webdecoy.com/connect/mcp?client_id=wuNBtlyJLEInlcYwpKrEgIOAURZQqWyF

Then add it to your assistant:

```sh
claude mcp add webdecoy -- webdecoy mcp     # Claude Code
codex mcp add webdecoy -- webdecoy mcp      # Codex
```

Claude Desktop, `claude_desktop_config.json`:

```json
{"mcpServers": {"webdecoy": {"command": "webdecoy", "args": ["mcp"]}}}
```

Use the full path from `which webdecoy` if your assistant does not see your
shell's `PATH`.

```sh
webdecoy logout                 # sign out on this machine
webdecoy logout --disconnect    # also remove this app's site approval in WebDecoy
```

`--profile name` on any command keeps a separate login, for a second account.

## Security

- The login code is written only to your terminal, never to output an
  assistant could capture.
- The only thing stored is the refresh credential, in the macOS Keychain or
  the Linux Secret Service (`secret-tool`), passed to them on stdin. Nothing
  is written to files, environment variables or assistant configuration.
  Systems without one of those stores are refused; there is no plain-file
  fallback.
- `webdecoy mcp` relays messages unchanged to `https://mcp.webdecoy.com/mcp`.
  It has no tools or permissions of its own: what the assistant can see is
  exactly what you approved for this app, read-only unless you also allow
  setup.
- Access tokens stay in memory and last at most 15 minutes. The CLI sends
  them only to `mcp.webdecoy.com`, and to WebDecoy's API for
  `logout --disconnect`. Redirects are never followed.

On Linux, install `secret-tool` (Debian/Ubuntu: `libsecret-tools`) and run a
Secret Service such as gnome-keyring.

## Source

This repository is published from WebDecoy's main codebase; changes are made
there and synced here. Issues and questions: https://webdecoy.com/contact

## License

MIT
