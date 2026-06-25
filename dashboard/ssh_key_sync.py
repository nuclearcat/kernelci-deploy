#!/usr/bin/env python3
"""
Synchronize one local user's SSH authorized_keys from GitHub users.

The username source is a plain text file in a GitHub repository. Each non-empty,
non-comment line is treated as one GitHub username. For each username, this
script fetches the public SSH keys from GitHub and rewrites the configured
local user's authorized_keys file.

The generated authorized_keys file is fully managed by this script. Existing
content is backed up before replacement, then overwritten atomically.

Usage:
  # Preview only:
  ./dashboard/ssh_key_sync.py

  # Rewrite authorized_keys:
  sudo ./dashboard/ssh_key_sync.py --apply

  # Install/update this script plus a systemd service and timer:
  sudo ./dashboard/ssh_key_sync.py --install
"""

import argparse
import json
import logging
import os
import pwd
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Configuration. Keep operational config in this file, as requested.
# ---------------------------------------------------------------------------

# Local Unix account whose ~/.ssh/authorized_keys will be rewritten.
TARGET_USER = "dashboard"

# GitHub source of truth, one username per line. Blank lines and '#' comments
# are ignored.
SOURCE_REPO = "kernelci/dashboard"
SOURCE_PATH = ".github/dashboard-team"
SOURCE_REF = ""  # Optional branch/tag/SHA. Leave empty for the default branch.

# Optional token environment variable. Public GitHub keys do not require auth,
# but a token raises rate limits and allows reading a private source repo.
GITHUB_TOKEN_ENV = "GITHUB_TOKEN"

# Optional Discord webhook URL. Leave empty to disable notifications. If set,
# a message is sent only after authorized_keys is actually changed.
DISCORD_WEBHOOK_URL = ""
DISCORD_USERNAME = "dashboard-ssh-key-sync"

# Where --install copies this script on the server.
INSTALL_PATH = "/usr/local/sbin/dashboard-ssh-key-sync.py"

# systemd names and schedule used by --install.
SYSTEMD_SERVICE_NAME = "dashboard-ssh-key-sync.service"
SYSTEMD_TIMER_NAME = "dashboard-ssh-key-sync.timer"
SYSTEMD_ON_BOOT = "5min"
SYSTEMD_INTERVAL = "1h"
SYSTEMD_RANDOM_DELAY = "10min"

# Refuse to replace authorized_keys if the generated key count is suspiciously
# small. Set to 0 to disable.
MIN_KEYS_REQUIRED = 1

# Accepted key algorithms. This intentionally includes modern OpenSSH security
# key formats and RSA for compatibility with existing GitHub user keys.
ALLOWED_KEY_TYPES = {
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
}


# ---------------------------------------------------------------------------

API_BASE = "https://api.github.com"
API_VERSION = "2022-11-28"
USER_AGENT = "kernelci-dashboard-ssh-key-sync"
MAX_RETRIES = 4

USERNAME_RE = re.compile(r"^[A-Za-z\d](?:[A-Za-z\d]|-(?=[A-Za-z\d])){0,38}$")
KEY_DATA_RE = re.compile(r"^[A-Za-z0-9+/]+={0,3}$")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
log = logging.getLogger("ssh_key_sync")


def die(message):
    """Log a fatal error and terminate the process with a non-zero exit."""
    log.error(message)
    sys.exit(1)


def github_request(method, path, accept="application/vnd.github+json"):
    """Call the GitHub API and return ``(status, data, headers)``.

    ``path`` may be an API-relative path or a full URL from a pagination Link
    header. Retryable server, rate-limit, and network failures are retried with
    exponential backoff. Non-retryable HTTP errors are returned to the caller so
    endpoint-specific handling, such as 404 checks, can stay local.
    """
    if path.startswith("http"):
        url = path
    else:
        url = API_BASE + path

    headers = {
        "Accept": accept,
        "X-GitHub-Api-Version": API_VERSION,
        "User-Agent": USER_AGENT,
    }

    token = os.environ.get(GITHUB_TOKEN_ENV)
    if token:
        headers["Authorization"] = f"Bearer {token}"

    last_err = None
    for attempt in range(MAX_RETRIES):
        req = urllib.request.Request(url, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read().decode("utf-8", "replace")
                return resp.status, parse_response(raw, accept), dict(resp.headers)
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", "replace")
            retryable = exc.code >= 500 or exc.code == 429 or (
                exc.code == 403 and "rate limit" in raw.lower()
            )
            if retryable and attempt < MAX_RETRIES - 1:
                wait = retry_after(exc.headers, attempt)
                log.warning("%s %s -> %s, retrying in %ss", method, url, exc.code, wait)
                time.sleep(wait)
                last_err = exc
                continue
            return exc.code, parse_response(raw, accept), dict(exc.headers)
        except urllib.error.URLError as exc:
            if attempt < MAX_RETRIES - 1:
                wait = 2 ** attempt
                log.warning("%s %s failed (%s), retrying in %ss", method, url, exc, wait)
                time.sleep(wait)
                last_err = exc
                continue
            die(f"{method} {url} failed: {exc}")

    die(f"{method} {url} failed after {MAX_RETRIES} attempts: {last_err}")


def parse_response(raw, accept):
    """Parse an HTTP response body according to the requested Accept header."""
    if not raw:
        return None
    if "json" not in accept:
        return raw
    try:
        return json.loads(raw)
    except ValueError:
        return raw


def retry_after(headers, attempt):
    """Return the retry delay for a GitHub request attempt."""
    value = headers.get("Retry-After")
    if value and value.isdigit():
        return int(value)
    return 2 ** attempt


def get_paginated(path):
    """Fetch all pages from a GitHub list endpoint and return one list."""
    sep = "&" if "?" in path else "?"
    url = API_BASE + path + f"{sep}per_page=100"
    results = []

    while url:
        status, data, headers = github_request("GET", url)
        if status != 200 or not isinstance(data, list):
            die(f"GET {url} returned {status}: {data}")
        results.extend(data)
        url = next_link(headers.get("Link"))

    return results


def next_link(link_header):
    """Extract the ``rel=next`` URL from a GitHub Link header, if present."""
    if not link_header:
        return None
    for part in link_header.split(","):
        bits = part.split(";")
        if len(bits) < 2:
            continue
        target = bits[0].strip().strip("<>")
        if any(bit.strip() == 'rel="next"' for bit in bits[1:]):
            return target
    return None


def fetch_usernames():
    """Fetch, validate, normalize, deduplicate, and sort source usernames."""
    owner_repo = SOURCE_REPO.strip("/")
    if owner_repo.count("/") != 1:
        die(f"invalid SOURCE_REPO: {SOURCE_REPO!r}")

    encoded_path = "/".join(
        urllib.parse.quote(part, safe="") for part in SOURCE_PATH.strip("/").split("/")
    )
    url_path = f"/repos/{owner_repo}/contents/{encoded_path}"
    if SOURCE_REF:
        url_path += "?ref=" + urllib.parse.quote(SOURCE_REF, safe="")

    status, content, _ = github_request(
        "GET",
        url_path,
        accept="application/vnd.github.raw",
    )
    if status == 404:
        die(f"source file not found: {SOURCE_REPO}:{SOURCE_PATH}")
    if status != 200 or not isinstance(content, str):
        die(f"could not fetch {SOURCE_REPO}:{SOURCE_PATH} (status {status})")

    invalid = []
    usernames = set()
    for line_no, line in enumerate(content.splitlines(), start=1):
        username = line.split("#", 1)[0].strip()
        if not username:
            continue
        if not USERNAME_RE.match(username):
            invalid.append(f"line {line_no}: {username!r}")
            continue
        usernames.add(username.lower())

    if invalid:
        die("invalid GitHub username(s): " + ", ".join(invalid))
    if not usernames:
        die(f"refusing to run: {SOURCE_REPO}:{SOURCE_PATH} contains no usernames")

    return sorted(usernames)


def fetch_github_keys(username):
    """Fetch one GitHub user's public SSH keys as normalized key/id tuples."""
    quoted = urllib.parse.quote(username, safe="")
    keys = get_paginated(f"/users/{quoted}/keys")
    valid_keys = []

    for entry in keys:
        if not isinstance(entry, dict):
            continue
        key_id = entry.get("id")
        key = entry.get("key")
        if not isinstance(key, str):
            continue
        normalized_key = normalize_public_key(key)
        if not normalized_key:
            log.warning("Skipping invalid public key for %s: id=%s", username, key_id)
            continue
        valid_keys.append((normalized_key, key_id))

    return sorted(valid_keys, key=lambda item: (item[0], str(item[1])))


def normalize_public_key(key):
    """Return a canonical ``type data`` public key string, or ``""`` if invalid."""
    if "\n" in key or "\r" in key:
        return ""
    parts = key.split()
    if len(parts) < 2:
        return ""
    if parts[0] not in ALLOWED_KEY_TYPES:
        return ""
    if not KEY_DATA_RE.match(parts[1]):
        return ""
    return f"{parts[0]} {parts[1]}"


def build_authorized_keys(usernames):
    """Build complete managed authorized_keys content from GitHub usernames.

    Returns ``(content, key_count, users_without_keys)``. Duplicate public keys
    are skipped so one key cannot appear multiple times with different comments.
    The function aborts if the generated key count is below ``MIN_KEYS_REQUIRED``.
    """
    lines = [
        "# This file is managed by dashboard-ssh-key-sync.py.",
        f"# Source: {SOURCE_REPO}:{SOURCE_PATH}",
        "# Manual edits will be overwritten.",
        "",
    ]

    key_count = 0
    users_without_keys = []
    seen_keys = set()

    for username in usernames:
        keys = fetch_github_keys(username)
        if not keys:
            users_without_keys.append(username)
            continue
        lines.append(f"# GitHub user: {username}")
        for key, key_id in keys:
            if key in seen_keys:
                log.warning("Skipping duplicate key for %s: id=%s", username, key_id)
                continue
            seen_keys.add(key)
            comment = f"github:{username}"
            if key_id is not None:
                comment += f" github-key-id:{key_id}"
            lines.append(f"{key} {comment}")
            key_count += 1
        lines.append("")

    if users_without_keys:
        log.warning("Users without public GitHub SSH keys: %s", ", ".join(users_without_keys))
    if key_count < MIN_KEYS_REQUIRED:
        die(f"refusing to write authorized_keys: generated only {key_count} key(s)")

    return "\n".join(lines).rstrip() + "\n", key_count, users_without_keys


def target_user_info():
    """Return the passwd entry for ``TARGET_USER`` or abort if it is missing."""
    try:
        return pwd.getpwnam(TARGET_USER)
    except KeyError:
        die(f"local user does not exist: {TARGET_USER}")


def authorized_keys_path(user_info):
    """Return the target authorized_keys path for a passwd entry."""
    return Path(user_info.pw_dir) / ".ssh" / "authorized_keys"


def ensure_can_write(user_info):
    """Abort unless the current process can safely write the target user's keys."""
    if os.geteuid() == 0:
        return
    if os.geteuid() == user_info.pw_uid:
        return
    die(f"must run as root or as local user {TARGET_USER!r} to update authorized_keys")


def write_authorized_keys(content, dry_run):
    """Replace the target authorized_keys file atomically.

    Returns ``True`` only when a real write occurred. Dry-runs and no-op updates
    return ``False``. Before replacement, existing content is backed up next to
    the target file.
    """
    user_info = target_user_info()
    ensure_can_write(user_info)

    auth_path = authorized_keys_path(user_info)
    ssh_dir = auth_path.parent
    old_content = ""
    if auth_path.exists():
        old_content = auth_path.read_text(encoding="utf-8", errors="replace")

    if dry_run:
        action = "would update" if old_content != content else "already up to date"
        log.info("DRY-RUN: %s %s", action, auth_path)
        return False

    if old_content == content:
        log.info("%s is already up to date", auth_path)
        return False

    ssh_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chown(ssh_dir, user_info.pw_uid, user_info.pw_gid)
    os.chmod(ssh_dir, 0o700)

    if auth_path.exists():
        # TODO: Backups accumulate unbounded. Every content change writes
        # authorized_keys.backup.<UTC ts> and nothing prunes them. Over time
        # ~/.ssh fills with backups. Consider keeping the last N.
        backup_path = auth_path.with_name(
            "authorized_keys.backup." + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        )
        shutil.copy2(auth_path, backup_path)
        os.chown(backup_path, user_info.pw_uid, user_info.pw_gid)
        os.chmod(backup_path, 0o600)
        log.info("Backed up existing authorized_keys to %s", backup_path)

    fd, tmp_name = tempfile.mkstemp(prefix=".authorized_keys.", dir=str(ssh_dir), text=True)
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.chown(tmp_path, user_info.pw_uid, user_info.pw_gid)
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, auth_path)
        sync_directory(ssh_dir)
    finally:
        if tmp_path.exists():
            tmp_path.unlink()

    log.info("Updated %s", auth_path)
    return True


def send_discord_update(usernames, key_count, users_without_keys):
    """Send an optional Discord notification after a successful key update."""
    webhook_url = DISCORD_WEBHOOK_URL.strip()
    if not webhook_url:
        return
    if not is_allowed_discord_webhook(webhook_url):
        log.warning("Discord webhook URL is not a supported HTTPS Discord webhook")
        return

    host = socket.getfqdn() or socket.gethostname()
    shown_users = ", ".join(usernames[:30])
    if len(usernames) > 30:
        shown_users += f", ... and {len(usernames) - 30} more"

    content = (
        f"SSH authorized_keys updated on `{host}` for local user `{TARGET_USER}`.\n"
        f"Source: `{SOURCE_REPO}:{SOURCE_PATH}`\n"
        f"Users: {len(usernames)}; keys: {key_count}\n"
        f"GitHub users: {shown_users}"
    )
    if users_without_keys:
        missing = ", ".join(users_without_keys[:20])
        if len(users_without_keys) > 20:
            missing += f", ... and {len(users_without_keys) - 20} more"
        content += f"\nUsers without public SSH keys: {missing}"

    payload = {
        "username": DISCORD_USERNAME,
        "content": content[:2000],
    }
    post_json(webhook_url, payload)


def is_allowed_discord_webhook(webhook_url):
    """Validate that a webhook URL targets Discord over HTTPS."""
    parsed = urllib.parse.urlparse(webhook_url)
    allowed_hosts = {
        "discord.com",
        "www.discord.com",
        "canary.discord.com",
        "ptb.discord.com",
        "discordapp.com",
        "www.discordapp.com",
    }
    return (
        parsed.scheme == "https"
        and parsed.netloc.lower() in allowed_hosts
        and parsed.path.startswith("/api/webhooks/")
    )


def post_json(url, payload):
    """POST a JSON payload with retries for transient webhook failures."""
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
    }

    for attempt in range(MAX_RETRIES):
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                if 200 <= resp.status < 300:
                    log.info("Sent Discord notification")
                    return
                log.warning("Discord webhook returned HTTP %s", resp.status)
                return
        except urllib.error.HTTPError as exc:
            retryable = exc.code >= 500 or exc.code == 429
            if retryable and attempt < MAX_RETRIES - 1:
                raw = exc.read().decode("utf-8", "replace")
                wait = discord_retry_after(exc.headers, raw, attempt)
                log.warning("Discord webhook returned %s, retrying in %ss", exc.code, wait)
                time.sleep(wait)
                continue
            log.warning("Discord webhook failed with HTTP %s", exc.code)
            return
        except urllib.error.URLError as exc:
            if attempt < MAX_RETRIES - 1:
                wait = 2 ** attempt
                log.warning("Discord webhook failed (%s), retrying in %ss", exc, wait)
                time.sleep(wait)
                continue
            log.warning("Discord webhook failed: %s", exc)
            return


def discord_retry_after(headers, raw_body, attempt):
    """Return Discord retry delay from headers/body, falling back to backoff."""
    retry_after = headers.get("Retry-After")
    if retry_after:
        try:
            return max(1, int(float(retry_after)))
        except ValueError:
            pass
    try:
        data = json.loads(raw_body)
    except ValueError:
        return 2 ** attempt
    value = data.get("retry_after") if isinstance(data, dict) else None
    if isinstance(value, (int, float)):
        return max(1, int(value))
    return 2 ** attempt


def sync_directory(path):
    """Best-effort fsync of a directory after atomic file replacement."""
    try:
        fd = os.open(path, os.O_DIRECTORY)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def install_systemd():
    """Install this script and enable its systemd service/timer."""
    if os.geteuid() != 0:
        die("--install must be run as root")

    user_info = target_user_info()
    install_path = Path(INSTALL_PATH)
    install_path.parent.mkdir(parents=True, exist_ok=True)

    source_path = Path(__file__).resolve()
    if source_path != install_path:
        shutil.copy2(source_path, install_path)
    os.chown(install_path, 0, 0)
    os.chmod(install_path, 0o755)

    service_path = Path("/etc/systemd/system") / SYSTEMD_SERVICE_NAME
    timer_path = Path("/etc/systemd/system") / SYSTEMD_TIMER_NAME
    ssh_dir = authorized_keys_path(user_info).parent

    service_path.write_text(render_service(install_path, ssh_dir), encoding="utf-8")
    timer_path.write_text(render_timer(), encoding="utf-8")
    os.chmod(service_path, 0o644)
    os.chmod(timer_path, 0o644)

    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", "--now", SYSTEMD_TIMER_NAME])

    log.info("Installed %s", install_path)
    log.info("Installed and enabled %s", SYSTEMD_TIMER_NAME)
    log.info("Run a one-shot sync with: systemctl start %s", SYSTEMD_SERVICE_NAME)


def render_service(script_path, ssh_dir):
    """Render the systemd service unit used by ``--install``."""
    return f"""[Unit]
Description=Sync {TARGET_USER} SSH authorized_keys from GitHub users
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
User=root
Group=root
ExecStart=/usr/bin/python3 {script_path} --apply
Nice=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths={ssh_dir}
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LockPersonality=true
MemoryDenyWriteExecute=true
PrivateDevices=true
ProtectClock=true
ProtectControlGroups=true
ProtectHostname=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
RestrictRealtime=true
SystemCallArchitectures=native
"""


def render_timer():
    """Render the systemd timer unit used by ``--install``."""
    return f"""[Unit]
Description=Run {SYSTEMD_SERVICE_NAME} periodically

[Timer]
OnBootSec={SYSTEMD_ON_BOOT}
OnUnitActiveSec={SYSTEMD_INTERVAL}
RandomizedDelaySec={SYSTEMD_RANDOM_DELAY}
Persistent=true
Unit={SYSTEMD_SERVICE_NAME}

[Install]
WantedBy=timers.target
"""


def run(argv):
    """Run a subprocess command and abort on failure."""
    log.info("Running: %s", " ".join(argv))
    try:
        subprocess.run(argv, check=True)
    except FileNotFoundError:
        die(f"command not found: {argv[0]}")
    except subprocess.CalledProcessError as exc:
        die(f"command failed with exit code {exc.returncode}: {' '.join(argv)}")


def parse_args():
    """Parse command-line options."""
    parser = argparse.ArgumentParser(
        description="Sync a local authorized_keys file from GitHub users."
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="rewrite authorized_keys; default is dry-run",
    )
    parser.add_argument(
        "--install",
        action="store_true",
        help="install this script and enable a systemd timer",
    )
    return parser.parse_args()


def main():
    """Command-line entry point."""
    args = parse_args()

    if args.install:
        install_systemd()
        return

    usernames = fetch_usernames()
    content, key_count, users_without_keys = build_authorized_keys(usernames)

    log.info("Source users: %d", len(usernames))
    log.info("Generated SSH keys: %d", key_count)
    if users_without_keys:
        log.info("Users without keys: %d", len(users_without_keys))

    changed = write_authorized_keys(content, dry_run=not args.apply)
    if changed:
        send_discord_update(usernames, key_count, users_without_keys)


if __name__ == "__main__":
    main()
