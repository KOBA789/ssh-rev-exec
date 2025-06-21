# ssh-rev-exec

ssh-rev-exec enables the remote host to run commands on the local host via SSH agent socket forwarding. This is useful when you need to access local resources (like `pbpaste`, `code`, or other local tools) from a remote SSH session.

## How it works

ssh-rev-exec extends the SSH agent protocol to support reverse command execution. It consists of two components:

- **agent**: A proxy that runs on your local machine, intercepting special requests to execute local commands
- **exec**: A client that runs on the remote machine to send command execution requests back to your local machine

## Installation

```bash
cargo install --git https://github.com/KOBA789/ssh-rev-exec.git
```

## Usage

### Step 1: Start the agent on your local machine

```bash
# Start the reverse SSH agent
ssh-rev agent -A $SSH_AUTH_SOCK -R /tmp/ssh-rev.sock

# Export the new socket as your SSH_AUTH_SOCK
export SSH_AUTH_SOCK=/tmp/ssh-rev.sock
```

The agent will:
- Listen on the socket specified by `-R` (reverse socket)
- Forward regular SSH agent requests to the socket specified by `-A` (upstream agent)
- Handle reverse execution requests from remote hosts

### Step 2: Connect to a remote host

```bash
# SSH to your remote host with agent forwarding
ssh -A remote-host
```

### Step 3: Execute commands on your local machine from the remote host

```bash
# On the remote host, run commands on your local machine
ssh-rev exec -- hostname
# Output: your-local-hostname

# Run commands with arguments
ssh-rev exec -- ls -la /tmp

# Run interactive commands
ssh-rev exec -- vim /local/file.txt
```

## Examples

### Open VS Code on local machine for remote files

Create an alias on the remote host:

```bash
alias code-local='ssh-rev exec -- code --remote ssh-remote+REMOTE_HOST'
```

Then use it:

```bash
code-local /path/to/remote/file.txt
```

### Access local clipboard

```bash
# Copy from remote to local clipboard
echo "Hello" | ssh-rev exec -- pbcopy

# Paste from local clipboard to remote
ssh-rev exec -- pbpaste
```

## Automatic startup

For convenience, you can set up the agent to start automatically:

### macOS (launchctl)

Create `~/Library/LaunchAgents/com.github.koba789.ssh-rev.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.github.koba789.ssh-rev</string>
    <key>ProgramArguments</key>
    <array>
        <string>/path/to/ssh-rev</string>
        <string>agent</string>
        <string>-A</string>
        <string>/path/to/original/ssh-agent.sock</string>
        <string>-R</string>
        <string>/tmp/ssh-rev.sock</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```

Then load it:

```bash
launchctl load ~/Library/LaunchAgents/com.github.koba789.ssh-rev.plist
```

### Linux (systemd)

Create `~/.config/systemd/user/ssh-rev.service`:

```ini
[Unit]
Description=SSH Reverse Execution Agent
After=default.target

[Service]
Type=simple
ExecStart=/path/to/ssh-rev agent -A %t/ssh-agent.socket -R %t/ssh-rev.socket
Restart=always

[Install]
WantedBy=default.target
```

Then enable and start it:

```bash
systemctl --user enable ssh-rev.service
systemctl --user start ssh-rev.service
```

## Security Considerations

ssh-rev-exec allows remote hosts to execute commands on your local machine. Only use this tool when:

- You trust the remote host
- You understand the security implications
- The SSH connection is properly secured

The tool respects SSH agent forwarding settings, so remote command execution is only possible when you explicitly forward your agent with `ssh -A`.
