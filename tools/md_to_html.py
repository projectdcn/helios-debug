"""Render docs/*.md as self-contained HTML pages (no dependencies): headings with a table of contents, paragraphs,
tables, fenced code (also inside list items), ordered / unordered / checkbox lists, inline code and bold.

    python tools/md_to_html.py docs/link-debug-guide.md            # -> docs/link-debug-guide.html
"""
from __future__ import annotations

import html
import re
import sys
from pathlib import Path

CSS = """
:root{--bg:#fbfbfa;--fg:#1d1f21;--mut:#5f6368;--line:#dcdcd8;--card:#ffffff;--code:#f1f1ee;--acc:#0b6bcb;--th:#f3f3f0}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#16181b;--fg:#e6e6e3;--mut:#a0a4a8;
--line:#33363b;--card:#1d2024;--code:#23272c;--acc:#6aaef5;--th:#22262b}}
:root[data-theme="dark"]{--bg:#16181b;--fg:#e6e6e3;--mut:#a0a4a8;--line:#33363b;--card:#1d2024;--code:#23272c;
--acc:#6aaef5;--th:#22262b}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,
Helvetica,Arial,sans-serif}
.page{max-width:980px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:28px;margin:0 0 4px}h2{font-size:20px;margin:36px 0 10px;padding-top:12px;border-top:1px solid var(--line)}
.date{color:var(--mut);margin:0 0 18px}
a{color:var(--acc)}
nav.toc{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 16px;margin:16px 0}
nav.toc ol{margin:6px 0;padding-left:20px;columns:2;column-gap:28px}
@media (max-width:640px){nav.toc ol{columns:1}}
code{font:13px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--code);padding:1px 4px;
border-radius:4px;overflow-wrap:anywhere}
pre{background:var(--code);border:1px solid var(--line);border-radius:6px;padding:10px 12px;overflow-x:auto}
pre code{background:none;padding:0;overflow-wrap:normal;white-space:pre}
.tw{overflow-x:auto;margin:10px 0;border:1px solid var(--line);border-radius:6px}
table{border-collapse:collapse;width:100%;background:var(--card);font-size:14px}
th,td{text-align:left;vertical-align:top;padding:7px 10px;border-bottom:1px solid var(--line)}
th{background:var(--th);font-weight:600}tr:last-child td{border-bottom:none}
li{margin:3px 0}ul.check{list-style:none;padding-left:4px}ul.check li::before{content:"\\2610  ";color:var(--mut)}
"""

ESC = re.compile(r"\\([\\`*_{}\[\]()#+\-.!|<>~])")


def inline(text: str) -> str:
    codes: list[str] = []

    def keep(m):
        codes.append(f"<code>{html.escape(m.group(1))}</code>")
        return "\x01%d\x01" % (len(codes) - 1)
    text = re.sub(r"`([^`]+)`", keep, text)                      # code first: bold may wrap code spans
    text = html.escape(ESC.sub(lambda m: "\x00%d\x00" % ord(m.group(1)), text), quote=False)
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub("\x00(\\d+)\x00", lambda m: html.escape(chr(int(m.group(1)))), text)
    return re.sub("\x01(\\d+)\x01", lambda m: codes[int(m.group(1))], text)


def slug(t: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", re.sub(r"<[^>]+>", "", t).lower()).strip("-")


def cells(row: str) -> list[str]:
    row = row.strip()
    row = row[1:] if row.startswith("|") else row
    row = row[:-1] if row.endswith("|") and not row.endswith("\\|") else row
    return [c.strip().replace("\\|", "|") for c in re.split(r"(?<!\\)\|", row)]   # GFM: \\| is a pipe, in code too


def render(md: str) -> tuple[str, str, list[tuple[str, str]]]:
    lines, body, toc, title = md.splitlines(), [], [], "Document"
    i = 0

    def code_block(start: int, indent: int) -> tuple[str, int]:
        j, buf = start + 1, []
        while j < len(lines) and lines[j].strip() != "```":
            buf.append(lines[j][indent:] if lines[j][:indent].strip() == "" else lines[j].lstrip())
            j += 1
        return f"<pre><code>{html.escape(chr(10).join(buf))}</code></pre>", j + 1

    while i < len(lines):
        ln = lines[i]
        if not ln.strip():
            i += 1
        elif ln.startswith("# "):
            title = ln[2:].strip()
            body.append(f"<h1>{inline(title)}</h1>")
            i += 1
            if i + 1 < len(lines) and not lines[i].strip() and re.match(r"^\d{1,2} \w+ \d{4}$", lines[i + 1].strip()):
                body.append(f"<p class='date'>{html.escape(lines[i + 1].strip())}</p>")
                i += 2
        elif ln.startswith("## "):
            t = inline(ln[3:].strip())
            toc.append((slug(t), t))
            body.append(f"<h2 id='{slug(t)}'>{t}</h2>")
            i += 1
        elif ln.strip() == "```":
            block, i = code_block(i, 0)
            body.append(block)
        elif ln.lstrip().startswith("|"):
            rows = []
            while i < len(lines) and lines[i].lstrip().startswith("|"):
                rows.append(cells(lines[i]))
                i += 1
            head, rest = rows[0], [r for r in rows[1:] if not all(re.fullmatch(r":?-{3,}:?", c) for c in r)]
            t = "<tr>" + "".join(f"<th>{inline(c)}</th>" for c in head) + "</tr>"
            t += "".join("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in r) + "</tr>" for r in rest)
            body.append(f"<div class='tw'><table>{t}</table></div>")
        elif re.match(r"^(\d+\.|-) ", ln):
            ordered = ln[0].isdigit()
            check = ln.startswith("- [ ] ")
            items: list[list[str]] = []
            while i < len(lines):
                cur = lines[i]
                m = re.match(r"^(\d+\.|-) (\[ \] )?(.*)", cur)
                if m and (m.group(1)[0].isdigit()) == ordered:
                    items.append([inline(m.group(3))])
                    i += 1
                elif cur.startswith("   ") and items:
                    if cur.strip() == "```":
                        block, i = code_block(i, 3)
                        items[-1].append(block)
                    elif cur.strip():
                        items[-1].append(f"<p>{inline(cur.strip())}</p>")
                        i += 1
                    else:
                        i += 1
                elif not cur.strip() and i + 1 < len(lines) and (lines[i + 1].startswith("   ")
                                                                 or re.match(r"^(\d+\.|-) ", lines[i + 1])):
                    i += 1
                else:
                    break
            tag = "ol" if ordered else "ul"
            cls = " class='check'" if check else ""
            body.append(f"<{tag}{cls}>" + "".join(f"<li>{''.join(it)}</li>" for it in items) + f"</{tag}>")
        else:
            buf = []
            while i < len(lines) and lines[i].strip() and not re.match(r"^(#|\||```|\d+\. |- )", lines[i].lstrip()):
                buf.append(lines[i].strip())
                i += 1
            body.append(f"<p>{inline(' '.join(buf))}</p>")
    return title, "\n".join(body), toc


def page(md_path: Path) -> str:
    title, body, toc = render(md_path.read_text())
    nav = "<nav class='toc'><strong>Contents</strong><ol>" + "".join(
        f"<li><a href='#{s}'>{t}</a></li>" for s, t in toc) + "</ol></nav>"
    first_h2 = body.find("<h2")
    body = body[:first_h2] + nav + body[first_h2:] if first_h2 >= 0 else body + nav
    return (f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{html.escape(title)}</title><style>{CSS}</style></head>"
            f"<body><div class='page'>{body}</div></body></html>\n")


def main(argv: list[str]) -> int:
    for a in argv or ["docs/link-debug-guide.md"]:
        src = Path(a)
        dst = src.with_suffix(".html")
        dst.write_text(page(src))
        print(dst)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
