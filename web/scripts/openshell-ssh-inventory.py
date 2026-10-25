#!/usr/bin/env python3
"""Read-only SSH inventory, intended to run inside an OpenShell sandbox."""

import base64
import hashlib
import socket
import sys

import paramiko


COMMAND = "; ".join([
    "printf 'user='; id -un",
    "printf 'hostname='; hostname",
    "printf 'kernel='; uname -sr",
    "printf 'os='; . /etc/os-release && printf '%s\\n' \"$PRETTY_NAME\"",
    "printf 'openssh_server='; (dpkg-query -W -f='${Version}' openssh-server 2>/dev/null || printf 'unknown'); printf '\\n'",
    "printf 'ssh_service='; (systemctl is-active ssh 2>/dev/null || printf 'unknown'); printf '\\n'",
    "printf 'listening_tcp_ports='; (ss -lntH 2>/dev/null | awk '{print $4}' | sed -E 's/.*:([0-9]+)$/\\1/' | sort -un | paste -sd, - || true); printf '\\n'",
])


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: openshell-ssh-inventory.py HOST FINGERPRINT")
    host, fingerprint = sys.argv[1:]
    password = sys.stdin.readline().rstrip("\n")
    if not password:
        raise SystemExit("SSH password missing")
    connection = socket.create_connection((host, 22), timeout=8)
    transport = paramiko.Transport(connection)
    try:
        transport.start_client(timeout=8)
        key = transport.get_remote_server_key()
        digest = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
        if f"SHA256:{digest}" != fingerprint:
            raise paramiko.SSHException("SSH host key does not match the pinned fingerprint")
        try:
            transport.auth_password("dell", password)
        except paramiko.BadAuthenticationType as error:
            if "keyboard-interactive" not in error.allowed_types:
                raise
            transport.auth_interactive("dell", lambda _title, _instructions, prompts: [
                password if "password" in prompt.lower() else "" for prompt, _echo in prompts
            ])
        channel = transport.open_session(timeout=8)
        channel.exec_command(COMMAND)
        output = channel.makefile("rb").read(16384).decode("utf-8", errors="replace")
        error = channel.makefile_stderr("rb").read(1024).decode("utf-8", errors="replace")
        if channel.recv_exit_status() != 0 or "user=dell\n" not in output:
            raise RuntimeError(error or "SSH inventory failed")
        print(output, end="")
    finally:
        transport.close()


if __name__ == "__main__":
    main()
