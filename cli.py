#!/usr/bin/env python3
"""Local private settings init/render, plus one-click Compose build/up/down.

Direct actions (init/render/build/up/down/logs/logs-follow/status/diagnose) use the standard library
only. The interactive menu additionally needs requirements-menu.txt.
Nothing here rewrites host configuration; the deploy actions only drive the
single service declared in compose.yml.
"""

import argparse
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from service import Invalid, atomic_write, encode, load_settings, device_settings

ROOT = Path(__file__).resolve().parent
PROXY_KEYS = ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY")
LOG_LEVEL_KEY = "SINGBOX_LOG_LEVEL"
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")
DEPLOY_ACTIONS = ("build", "up", "down", "logs", "logs-follow", "status", "diagnose")

# Static error identifiers mapped to actionable English, so the menu never
# shows a bare code and never echoes user-supplied values.
ERROR_HELP = {
    "unfilled_template": "settings.json still contains <PLACEHOLDER> values",
    "api_key_format": "api_key must be 32-128 URL-safe characters: A-Z a-z 0-9 _ -",
    "settings_owner_permissions": "private-config/settings.json must be owned by you, mode 0600",
    "settings_fields": "settings.json has missing or unexpected top-level keys",
    "devices_list": "devices must contain 1-64 device objects",
    "device_fields": "each device needs id and api_key; wireguard is optional",
    "wireguard_not_configured": "this device has no WireGuard; use a proxyonly config URL",
    "device_id": "device id must be unique and use 1-64 URL-safe characters",
    "shared_settings": "shared must contain exactly the server-wide settings",
    "duplicate_api_key": "each device needs a distinct api_key",
    "duplicate_wireguard_address": "each device needs a distinct WireGuard address",
    "duplicate_wireguard_private_key": "each device needs a distinct WireGuard private key",
    "rule_fields": "direct/singapore must each contain ip_cidr, domain and domain_suffix",
    "manual_nodes_list": "manual_nodes must be a list of at most 200 URI strings",
    "manual_node_entry": "each manual_nodes entry must be one single-line URI string",
    "manual_node_scheme": "manual_nodes entry scheme must be one of vmess/vless/trojan/hysteria2/hysteria/tuic/anytls/ss/socks/http",
    "manual_node_rejected": "the local converter dropped a manual_nodes entry; check that link",
    "singapore_unavailable": "no usable Singapore node: fix the subscription or the sg_pattern",
    "hong_kong_unavailable": "no usable Hong Kong node and the own_hy2 backup is unreachable too",
    "candidate_limit": "more region candidates than max_candidates; raise the limit or narrow the patterns",
    "ambiguous_region": "a node name matches both hk_pattern and sg_pattern; make the patterns disjoint",
    "no_nodes": "the subscription and manual_nodes produced no usable outbound",
    "unsupported_node": "the subscription contains a protocol the service will not publish",
    "rule_list": "a rule list is missing, not a list, or too long",
    "invalid_domain": "one rule entry is not a plain domain",
    "domain_is_ip": "use ip_cidr for IP addresses, not domain/domain_suffix",
    "invalid_ip_cidr": "one ip_cidr entry is not a valid IP or CIDR",
    "subscription_https_required": "subscription_url must be a plain https:// URL without credentials",
    "wireguard_address_must_be_host_32": "wireguard.address must be a host address inside 10.77.0.0/24 (a bare IP is read as /32)",
    "wireguard_key": "wireguard private_key/peer_public_key must be 32-byte base64 keys",
    "wireguard_public_ipv6_required": "wireguard.endpoint must be a domain or a global IPv6 address (IPv4 is rejected)",
    "wireguard_mtu": "wireguard.mtu must be an integer between 1280 and 1420",
    "hy2_tls": "own_hy2.tls must be {enabled: true, server_name: ...}",
    "invalid_top_k": "top_k must be an integer between 1 and 50",
    "directory_ownership": "private directories must be owned by you and must not be symlinks",
    "render_required": "run 'render' first: runtime/settings.json and .env are missing",
    "compose_unavailable": "docker compose (or docker-compose) is not installed",
    "docker_daemon_unreachable": "the Docker daemon is not reachable with or without sudo",
    "log_level": "SINGBOX_LOG_LEVEL must be DEBUG, INFO, WARNING or ERROR",
    "unknown_action": "unknown action",
}


def explain(error):
    """Render a static error code plus fixed guidance, never raw exception text."""
    code = error if isinstance(error, str) else "operation_failed"
    help_text = ERROR_HELP.get(code)
    return code if not help_text else code + " - " + help_text


def private_dir(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or path.stat().st_uid != os.getuid():
        raise Invalid("directory_ownership")
    path.chmod(0o700)


def initialize(root=ROOT):
    path = root / "private-config"
    private_dir(path)
    target = path / "settings.json"
    template = (root / "templates/private-config/settings.json").read_bytes()
    # Never overwrite a user-populated file: keep the original private settings.
    with target.open("xb") as f:
        os.chmod(target, 0o600)
        f.write(template)
    return target


def render(root=ROOT):
    s = copy.deepcopy(load_settings(root / "private-config/settings.json"))
    builtin = json.loads((root / "data/direct.json").read_bytes())
    for field in builtin:
        s["shared"]["direct"][field] = sorted(set(builtin[field] + s["shared"]["direct"][field]))
    device_settings(s)
    for name in ("runtime", "state"):
        private_dir(root / name)
    # Atomic replace: the read-only bind mount always sees a complete file.
    atomic_write(root / "runtime/settings.json", encode(s))
    # Compose runs the service as the same owner as the host 0600 settings.
    atomic_write(root / ".env", f"LOCAL_UID={os.getuid()}\nLOCAL_GID={os.getgid()}\n".encode())
    return root / "runtime/settings.json"


def proxy_environment():
    """Only the standard proxy variables ever cross a privilege boundary."""
    env = {}
    for key in PROXY_KEYS:
        value = os.environ.get(key) or os.environ.get(key.lower())
        if value:
            env[key] = value
    return env


def log_level_environment():
    value = os.environ.get(LOG_LEVEL_KEY) or os.environ.get(LOG_LEVEL_KEY.lower())
    if not value:
        return {}
    value = value.upper()
    if value not in LOG_LEVELS:
        raise Invalid("log_level")
    return {LOG_LEVEL_KEY: value}


def _child_environment():
    env = dict(os.environ)
    env.update(proxy_environment())
    env.update(log_level_environment())
    return env


def _daemon_probe(elevated):
    """Probe with 'docker info'; compose has no 'info' subcommand."""
    if not shutil.which("docker"):
        return None
    base = ["docker", "info", "--format", "{{.ServerVersion}}"]
    return (["sudo"] + base) if elevated else base


def _daemon_reachable(argv):
    if argv is None:
        return False
    try:
        return subprocess.run(argv, capture_output=True, text=True,
                              env=_child_environment()).returncode == 0
    except OSError:
        return False


def _sudo_ready():
    """Validate sudo with inherited stdio so a password prompt stays visible."""
    try:
        if subprocess.run(["sudo", "-n", "true"], capture_output=True, text=True).returncode == 0:
            return True
        print("Docker needs elevated privileges; enter your sudo password if asked.", file=sys.stderr)
        sys.stderr.flush()
        return subprocess.run(["sudo", "-v"]).returncode == 0
    except OSError:
        return False


def compose_prefix(root=ROOT):
    """Return (argv prefix, elevated). Plain first so docker-group users are not prompted."""
    candidates = [c for c in (["docker", "compose"], ["docker-compose"]) if shutil.which(c[0])]
    if not candidates:
        raise Invalid("compose_unavailable")
    if _daemon_reachable(_daemon_probe(elevated=False)):
        return candidates[0] + ["-f", str(root / "compose.yml")], False
    if not _sudo_ready():
        raise Invalid("docker_daemon_unreachable")
    if not _daemon_reachable(_daemon_probe(elevated=True)):
        raise Invalid("docker_daemon_unreachable")
    keys = sorted({**proxy_environment(), **log_level_environment()})
    sudo = ["sudo", "--preserve-env=" + ",".join(keys)] if keys else ["sudo"]
    return sudo + candidates[0] + ["-f", str(root / "compose.yml")], True


def deploy(action, root=ROOT, run=subprocess.run):
    """Drive the single compose service. Inherited stdio keeps logs visible."""
    if action not in DEPLOY_ACTIONS:
        raise Invalid("unknown_action")
    if not (root / "runtime/settings.json").is_file() or not (root / ".env").is_file():
        raise Invalid("render_required")
    env = _child_environment()
    prefix, _ = compose_prefix(root)
    extra = {"build": ["build"], "up": ["up", "--detach"], "down": ["down"],
             "logs": ["logs", "--tail", "100"],
             "logs-follow": ["logs", "--follow", "--tail", "100"], "status": ["ps"],
             "diagnose": ["exec", "config", "python3", "/app/service.py", "diagnose"]}[action]
    return run(prefix + extra, env=env)


MENU = [
    ("Initialize private settings template", "init",
     "Create private-config/settings.json from the placeholder template? An existing file is never overwritten."),
    ("Render private runtime settings", "render",
     "Validate the private settings and refresh runtime/? No container is started."),
    ("Build service image", "build", "Build the pinned image now?"),
    ("Start service", "up", "Start the Compose service now?"),
    ("Stop service", "down", "Stop and remove the Compose service now?"),
    ("Show service logs", "logs", "Show the last 100 log lines?"),
    ("Follow service logs", "logs-follow", "Stream logs until you press Ctrl+C?"),
    ("Show service status", "status", "Show Compose service status?"),
    ("Show last refresh error detail", "diagnose",
     "Print the container's recorded tool-failure detail? It can contain node names and endpoints."),
    ("Exit", None, None),
]


def menu():
    try:
        import questionary
        from rich.console import Console
    except ImportError:
        print("The menu needs the optional dependencies in requirements-menu.txt "
              "(install them in a virtual environment). Direct actions need only the standard library.")
        return 1
    console = Console()
    while True:
        console.print("[bold]sing-box config service - local operations[/bold]")
        labels = [entry[0] for entry in MENU]
        label = questionary.select("Select an action", choices=labels).ask()
        if not label or label == "Exit":
            return 0
        _, action, prompt = next(entry for entry in MENU if entry[0] == label)
        if not questionary.confirm(prompt, default=True).ask():
            continue
        try:
            if action in ("init", "render"):
                console.print(str(initialize() if action == "init" else render()))
            else:
                deploy(action)  # Compose and the service print through inherited stdio.
        except FileExistsError:
            console.print("[yellow]Private settings already exist; left untouched.[/yellow]")
        except Invalid as exc:
            console.print("[red]failed: " + explain(str(exc)) + "[/red]")
        except Exception:
            console.print("[red]failed: operation_failed - check local files, JSON syntax and permissions[/red]")


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("action", nargs="?", default="menu",
                        choices=["init", "render", "menu"] + list(DEPLOY_ACTIONS))
    action = parser.parse_args().action
    if action == "menu":
        return menu()
    try:
        if action == "init":
            print(initialize())
        elif action == "render":
            print(render())
        else:
            deploy(action)
    except Invalid as exc:
        print("failed: " + explain(str(exc)), file=sys.stderr)
        return 1
    except FileExistsError:
        print("failed: private settings already exist; left untouched", file=sys.stderr)
        return 1
    except Exception:
        print("failed: operation_failed - check local files, JSON syntax and permissions", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
