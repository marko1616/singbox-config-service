#!/usr/bin/env python3
"""Local-only private settings initialization/render. Never deploys anything."""
import argparse
import copy
import json
import os
from pathlib import Path
import sys

from service import Invalid, atomic_write, encode, load_settings, validate

ROOT = Path(__file__).resolve().parent


def private_dir(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or path.stat().st_uid != os.getuid():
        raise Invalid('directory_ownership')
    path.chmod(0o700)


def initialize(root=ROOT):
    path = root / 'private-config'
    private_dir(path)
    target = path / 'settings.json'
    # Never overwrite a user-populated file.
    template = (root / 'templates/private-config/settings.json').read_bytes()
    with target.open('xb') as f:
        os.chmod(target, 0o600)
        f.write(template)
    return target


def render(root=ROOT):
    s = copy.deepcopy(load_settings(root / 'private-config/settings.json'))
    builtin = json.loads((root / 'data/direct.json').read_bytes())
    for field in builtin:
        s['direct'][field] = sorted(set(builtin[field] + s['direct'][field]))
    validate(s)
    for name in ('runtime', 'state'):
        private_dir(root / name)
    atomic_write(root / 'runtime/settings.json', encode(s))
    # Compose uses the same owner as the host's 0600 settings and 0700 snapshot directory.
    atomic_write(root / '.env', f'LOCAL_UID={os.getuid()}\nLOCAL_GID={os.getgid()}\n'.encode())
    return root / 'runtime/settings.json'


def menu():
    try:
        import questionary
        from rich.console import Console
    except ImportError:
        print('菜单需要 requirements-menu.txt 中的依赖（仅在 venv 内安装）。init/render 直接动作只需标准库。')
        return 1
    console = Console()
    while True:
        console.print('[bold]sing-box 配置下发 — 本地私有配置[/bold]')
        action = questionary.select('选择操作', choices=['初始化 private-config 模板', '渲染私有运行配置', '退出']).ask()
        if not action or action == '退出':
            return 0
        if action == '初始化 private-config 模板':
            if not questionary.confirm('创建占位模板？已有文件不会覆盖。', default=True).ask():
                continue
            fn = initialize
        else:
            if not questionary.confirm('检查已填写的私有配置并更新 runtime？不会启动容器。', default=True).ask():
                continue
            fn = render
        try:
            console.print(str(fn()))
        except FileExistsError:
            console.print('[yellow]私有文件已存在，保持原样。[/yellow]')
        except Exception as exc:
            console.print('[red]未完成：' + (str(exc) if isinstance(exc, Invalid) else '检查模板、文件权限和 JSON 格式') + '[/red]')


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['init', 'render', 'menu'], nargs='?', default='menu')
    action = parser.parse_args().action
    if action == 'menu':
        return menu()
    try:
        print(initialize() if action == 'init' else render())
    except Exception as exc:
        print(str(exc) if isinstance(exc, Invalid) else 'operation_failed; check local file/JSON/permissions', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
