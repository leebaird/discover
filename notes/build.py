#!/usr/bin/env python3
"""Build static HTML notes site from .txt sources and manifest.json."""

from __future__ import annotations

import html
import json
import os
import re
import sys
from pathlib import Path

NOTES_DIR = Path(__file__).resolve().parent
PAGES_DIR = NOTES_DIR / 'pages'
MANIFEST_PATH = NOTES_DIR / 'manifest.json'

HEADER_RE = re.compile(r'^(#{1,3})\s+(.*)$')
CMD_LINE_RE = re.compile(r'^(\S.*?)\s{2,}(.+)$')
NOTE_LINK_RE = re.compile(r'^([A-Za-z0-9_./-]+\.txt)\s{2,}(.+)$')
TXT_LINK_RE = re.compile(r'\b([A-Za-z0-9_./-]+\.txt)\b')


def load_manifest() -> dict:
    with MANIFEST_PATH.open(encoding='utf-8') as fh:
        return json.load(fh)


def iter_manifest_items(manifest: dict):
    for section in manifest.get('sections', []):
        for item in section.get('items', []):
            yield section['title'], item


def note_page_path(file_path: str) -> str:
    if file_path.endswith('.txt'):
        return 'pages/' + file_path[:-4] + '.html'
    return 'pages/' + file_path + '.html'


def rel_href(from_page: str, to_page: str) -> str:
    return os.path.relpath(to_page, Path(from_page).parent).replace('\\', '/')


def linkify_txt(text: str, current_page: str, known_txt: set[str]) -> str:
    def repl(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in known_txt:
            return html.escape(name)
        href = rel_href(current_page, note_page_path(name))
        return f'<a href="{href}">{html.escape(name)}</a>'

    return TXT_LINK_RE.sub(repl, html.escape(text))


def is_cmd_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped or stripped.startswith('#'):
        return False
    if stripped.startswith('- '):
        return False
    if line.startswith('    '):
        return False
    if NOTE_LINK_RE.match(line):
        return False
    return bool(CMD_LINE_RE.match(line))


def convert_txt_to_html(text: str, current_page: str, known_txt: set[str]) -> str:
    lines = text.splitlines()
    out: list[str] = []
    i = 0
    title = ''

    while i < len(lines) and not lines[i].strip():
        i += 1
    if i < len(lines) and not lines[i].startswith('#'):
        title = lines[i].strip()
        i += 1

    if title:
        out.append(f'<h1>{html.escape(title)}</h1>')

    cmd_buf: list[str] = []
    code_buf: list[str] = []

    def flush_cmd():
        nonlocal cmd_buf
        if cmd_buf:
            body = '\n'.join(html.escape(x) for x in cmd_buf)
            out.append(f'<pre class="cmd-block">{body}</pre>')
            cmd_buf = []

    def flush_code():
        nonlocal code_buf
        if code_buf:
            body = '\n'.join(html.escape(x.rstrip()) for x in code_buf)
            out.append(f'<pre class="cmd-block">{body}</pre>')
            code_buf = []

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if not stripped:
            flush_cmd()
            flush_code()
            i += 1
            continue

        header = HEADER_RE.match(line)
        if header:
            flush_cmd()
            flush_code()
            level = len(header.group(1))
            tag = 'h2' if level == 1 else 'h3' if level == 2 else 'h4'
            out.append(f'<{tag}>{html.escape(header.group(2))}</{tag}>')
            i += 1
            continue

        if line.startswith('    '):
            flush_cmd()
            code_buf.append(line[4:])
            i += 1
            while i < len(lines) and (lines[i].startswith('    ') or not lines[i].strip()):
                if lines[i].strip():
                    code_buf.append(lines[i][4:])
                elif code_buf:
                    code_buf.append('')
                i += 1
            flush_code()
            continue

        if is_cmd_line(line):
            flush_code()
            cmd_buf.append(line.rstrip())
            i += 1
            continue

        flush_cmd()
        flush_code()

        if stripped.startswith('- '):
            items = []
            while i < len(lines) and lines[i].strip().startswith('- '):
                item = lines[i].strip()[2:]
                items.append(f'<li>{linkify_txt(item, current_page, known_txt)}</li>')
                i += 1
            out.append('<ul>' + ''.join(items) + '</ul>')
            continue

        note_match = NOTE_LINK_RE.match(line)
        if note_match and note_match.group(1) in known_txt:
            name, desc = note_match.group(1), note_match.group(2)
            href = rel_href(current_page, note_page_path(name))
            out.append(
                f'<p><a href="{href}">{html.escape(name)}</a>'
                f' — {linkify_txt(desc, current_page, known_txt)}</p>'
            )
            i += 1
            continue

        if stripped.startswith('http://') or stripped.startswith('https://'):
            out.append(f'<p><a href="{html.escape(stripped, quote=True)}">{html.escape(stripped)}</a></p>')
            i += 1
            continue

        out.append(f'<p>{linkify_txt(stripped, current_page, known_txt)}</p>')
        i += 1

    flush_cmd()
    flush_code()
    return '\n'.join(out)


def build_nav(manifest: dict, current_page: str, active_file: str | None) -> str:
    chunks = []
    for section in manifest.get('sections', []):
        chunks.append(
            f'<div class="nav-section"><h2>{html.escape(section["title"])}</h2><ul>'
        )
        for item in section.get('items', []):
            file_path = item['file']
            item_type = item.get('type', 'note')
            label = item.get('title', file_path)

            if item_type == 'script':
                chunks.append(
                    f'<li><span class="script-note">{html.escape(label)} (script)</span></li>'
                )
            else:
                page = note_page_path(file_path)
                href = rel_href(current_page, page)
                active = ' class="active"' if file_path == active_file else ''
                chunks.append(
                    f'<li><a href="{href}"{active}>{html.escape(label)}</a></li>'
                )
        chunks.append('</ul></div>')
    return ''.join(chunks)


def page_shell(
    manifest: dict,
    body: str,
    current_page: str,
    active_file: str | None,
    asset_depth: int,
) -> str:
    prefix = '../' * asset_depth
    css = f'{prefix}assets/css/notes.css'
    home = f'{prefix}index.htm'
    nav = build_nav(manifest, current_page, active_file)
    title = manifest.get('title', 'Notes')

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{html.escape(title)}</title>
    <link rel="stylesheet" href="{css}">
</head>
<body>
<div class="notes-layout">
    <aside class="notes-sidebar">
        <a class="home-link" href="{home}">← Home</a>
        {nav}
    </aside>
    <main class="notes-main">
        {body}
    </main>
</div>
</body>
</html>'''


def build_home_card(section: dict) -> str:
    items_html = []
    for item in section.get('items', []):
        if item.get('type') == 'script':
            continue
        page = note_page_path(item['file'])
        label = item.get('title', item['file'])
        items_html.append(f'<li><a href="{page}">{html.escape(label)}</a></li>')
    return (
        '<div class="home-card">'
        f'<h2>{html.escape(section["title"])}</h2>'
        f'<ul>{"".join(items_html)}</ul>'
        '</div>'
    )


def build_index(manifest: dict) -> str:
    sections = manifest.get('sections', [])
    primary = ''.join(build_home_card(s) for s in sections[:8])
    remainder = ''.join(build_home_card(s) for s in sections[8:])
    remainder_block = (
        f'<div class="home-grid--remainder">{remainder}</div>' if remainder else ''
    )

    title = html.escape(manifest.get('title', 'Notes'))

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{title}</title>
    <link rel="stylesheet" href="assets/css/notes.css">
</head>
<body>
<div class="notes-home">
    <header class="notes-home-header">
        <h1>{title}</h1>
    </header>
    <div class="home-grid">
        {primary}
    </div>
    {remainder_block}
</div>
</body>
</html>'''


def main() -> int:
    manifest = load_manifest()
    known_txt = {
        item['file']
        for _, item in iter_manifest_items(manifest)
        if item['file'].endswith('.txt')
    }

    PAGES_DIR.mkdir(parents=True, exist_ok=True)

    built = 0
    for _, item in iter_manifest_items(manifest):
        if item.get('type') == 'script':
            continue
        src = NOTES_DIR / item['file']
        if not src.exists():
            print(f'warning: missing {src}', file=sys.stderr)
            continue

        page_rel = note_page_path(item['file'])
        page_path = NOTES_DIR / page_rel
        page_path.parent.mkdir(parents=True, exist_ok=True)

        text = src.read_text(encoding='utf-8')
        body = convert_txt_to_html(text, page_rel, known_txt)
        depth = len(Path(page_rel).parent.parts)
        html_doc = page_shell(manifest, body, page_rel, item['file'], depth)
        page_path.write_text(html_doc, encoding='utf-8')
        built += 1

    index_path = NOTES_DIR / 'index.htm'
    index_path.write_text(build_index(manifest), encoding='utf-8')

    print(f'Built {built} note pages and index.htm')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())