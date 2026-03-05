# Remote IDA Setup

Run Claude Code on your local machine while IDA runs on a remote machine. No Python/uv environment needed on remote.

## Architecture

```
Local Machine                              Remote Machine
┌──────────────────────────┐              ┌─────────────────────┐
│  Claude Code             │              │  IDA Pro            │
│       │ stdio            │              │  + MCP Plugin       │
│  server.py (MCP)         │              │       │ HTTP        │
│       │ HTTP             │              │  localhost:13337    │
│  Broker (:13337) ◄───────┼── SSH -R ────┼──┘                  │
└──────────────────────────┘              └─────────────────────┘
```

Claude Code launches `server.py` which auto-starts a Broker on `localhost:13337`. The SSH reverse tunnel maps the remote machine's `localhost:13337` back to the local Broker. The IDA plugin on remote connects to `localhost:13337` as if the Broker were local.

## Prerequisites

- Local machine: Claude Code + ida-pro-mcp installed (the normal setup)
- Remote machine: IDA Pro installed, SSH server running
- Network: SSH access from local to remote

## Step 1: Install Plugin on Remote

Copy the plugin files to the remote IDA plugins directory:

```bash
# Linux
scp src/ida_pro_mcp/ida_mcp.py  user@remote:~/.idapro/plugins/
scp -r src/ida_pro_mcp/ida_mcp/ user@remote:~/.idapro/plugins/

# macOS (same location)
scp src/ida_pro_mcp/ida_mcp.py  user@remote:~/.idapro/plugins/
scp -r src/ida_pro_mcp/ida_mcp/ user@remote:~/.idapro/plugins/
```

Only these files are needed. No Python packages or uv required on remote.

Optionally, install the decompile_timeout plugin for timeout-safe decompilation:

```bash
scp decompile_timeout/decompile_timeout.dylib user@remote:~/.idapro/plugins/
scp decompile_timeout/decompile_timeout.py    user@remote:~/.idapro/plugins/
```

## Step 2: Establish SSH Reverse Tunnel

```bash
ssh -R 127.0.0.1:13337:127.0.0.1:13337 user@remote -N
```

| Flag | Meaning |
|------|---------|
| `-R 127.0.0.1:13337:127.0.0.1:13337` | Reverse tunnel: remote's localhost:13337 → local's localhost:13337 |
| `-N` | No remote shell, port forwarding only |

Add `-f` to run in background. Keep this terminal open (or use `-f`) for the duration of the session.

> **Note**: If port 13337 is already in use on the remote machine (e.g. an old broker process), the tunnel will silently fail. Check with:
> ```bash
> ssh user@remote "lsof -i :13337 -P"
> ```
> Kill any conflicting process before establishing the tunnel.

## Step 3: Start IDA on Remote

Launch IDA on the remote machine and open a binary. The MCP plugin auto-connects to `localhost:13337` (tunneled to your local Broker).

The plugin has auto-reconnect with exponential backoff (3s → 30s), so startup order doesn't matter strictly. If the tunnel isn't ready yet, the plugin will keep retrying.

## Step 4: Use Claude Code Locally

Start Claude Code normally. No configuration changes needed. The MCP server auto-starts the Broker on local port 13337.

Verify the remote instance appears:

```bash
# Via curl
curl -s http://127.0.0.1:13337/api/instances | python3 -m json.tool

# Or via MCP tool
# instance_list will show the remote instance with its IP, e.g.:
#   ida-19684-[192.168.1.34]: binary_name.o
```

All MCP tools work transparently. Use `instance_id` parameter to target the remote instance:

```
decompile addr=0x1234 instance_id=ida-19684-[192.168.1.34]
```

## Custom Port

Default port is `13337`. To use a different port (e.g. `14000`), update three places:

**Local** — Broker and MCP server:
```bash
# Option A: CLI args
ida-pro-mcp --port 14000 --broker-url http://127.0.0.1:14000

# Option B: Environment variable (overrides default for MCP mode)
export IDA_MCP_BROKER_URL=http://127.0.0.1:14000
```

**SSH tunnel** — match the port:
```bash
ssh -R 127.0.0.1:14000:127.0.0.1:14000 user@remote -N
```

**Remote IDA plugin** — set environment variable before launching IDA:
```bash
export IDA_MCP_URL=http://127.0.0.1:14000
```

All three must agree on the same port.

## Troubleshooting

### Remote instance not appearing

1. **Check tunnel is alive**:
   ```bash
   ps aux | grep "ssh.*13337"
   ```

2. **Check remote port binding**:
   ```bash
   ssh user@remote "lsof -i :13337 -P"
   ```
   Should show `sshd` listening, not a Python process. If Python is listening, something else grabbed the port — kill it and re-establish the tunnel.

3. **Check plugin loaded in IDA**: Look for `[MCP]` messages in IDA's Output window.

### High latency

SSH tunneling adds ~1-2ms per round-trip on LAN. For WAN connections, consider using SSH connection multiplexing:

```bash
# In ~/.ssh/config
Host remote
    HostName 192.168.1.34
    User apple
    ControlMaster auto
    ControlPath ~/.ssh/sockets/%r@%h-%p
    ControlPersist 600
```

### Plugin update on remote

`ida_mcp/` package changes take effect with Ctrl+Alt+M (hot reload). But changes to `ida_mcp.py` (the loader) require an IDA restart.

```bash
# Push updates
scp src/ida_pro_mcp/ida_mcp.py  user@remote:~/.idapro/plugins/
scp -r src/ida_pro_mcp/ida_mcp/ user@remote:~/.idapro/plugins/
```
