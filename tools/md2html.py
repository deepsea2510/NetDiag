"""极简 Markdown → 单文件 HTML 转换器（仅供 docs/ 下评估报告渲染使用）。

支持：标题、表格（含对齐）、围栏代码块、有序/无序列表、引用块、分隔线、
粗体、行内代码、链接。刻意不引第三方库，保证零依赖。

用法：
    python tools/md2html.py docs/xxx.md docs/xxx.html "文档标题"
"""
from __future__ import annotations

import html
import re
import sys

_INLINE_CODE = re.compile(r"`([^`]+)`")
_BOLD = re.compile(r"\*\*([^*]+)\*\*")
_ITALIC = re.compile(r"\*([^*\n]+)\*")
_LINK = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")


def _inline(text: str) -> str:
    """先整段转义，再还原行内标记，避免把标签当正文。"""
    slots: list[str] = []

    def stash(fragment: str) -> str:
        slots.append(fragment)
        return f"\x00{len(slots) - 1}\x00"

    text = _INLINE_CODE.sub(lambda m: stash(f"<code>{html.escape(m.group(1))}</code>"), text)
    text = _LINK.sub(
        lambda m: stash(
            f'<a href="{html.escape(m.group(2), quote=True)}">{html.escape(m.group(1))}</a>'
        ),
        text,
    )
    text = html.escape(text)
    text = _BOLD.sub(lambda m: f"<strong>{m.group(1)}</strong>", text)
    text = _ITALIC.sub(lambda m: f"<em>{m.group(1)}</em>", text)
    # 表格单元格里用 <br> 手动换行，转义后再还原成真标签
    text = text.replace("&lt;br&gt;", "<br>")
    return re.sub(r"\x00(\d+)\x00", lambda m: slots[int(m.group(1))], text)


def _split_row(line: str) -> list[str]:
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|"):
        line = line[:-1]
    return [c.strip() for c in line.split("|")]


def _aligns(sep: str) -> list[str]:
    out = []
    for cell in _split_row(sep):
        left, right = cell.startswith(":"), cell.endswith(":")
        out.append("center" if left and right else "right" if right else "left")
    return out


def convert(md: str) -> tuple[str, list[tuple[int, str, str]]]:
    lines = md.splitlines()
    out: list[str] = []
    toc: list[tuple[int, str, str]] = []
    i, n = 0, len(lines)
    list_stack: list[str] = []          # 记录当前打开的 ul/ol
    in_code = False
    code_buf: list[str] = []
    para: list[str] = []

    def flush_para() -> None:
        if para:
            out.append("<p>" + _inline(" ".join(para)) + "</p>")
            para.clear()

    def close_lists(to: int = 0) -> None:
        while len(list_stack) > to:
            out.append(f"</{list_stack.pop()}>")

    while i < n:
        raw = lines[i]
        line = raw.rstrip()
        stripped = line.strip()

        # 围栏代码块
        if stripped.startswith("```"):
            if not in_code:
                flush_para()
                close_lists()
                in_code, code_buf = True, []
                lang = stripped[3:].strip()
                out.append(f'<pre class="code" data-lang="{html.escape(lang)}"><code>')
            else:
                out.append(html.escape("\n".join(code_buf)))
                out.append("</code></pre>")
                in_code = False
            i += 1
            continue
        if in_code:
            code_buf.append(raw)
            i += 1
            continue

        if not stripped:
            flush_para()
            close_lists()
            i += 1
            continue

        # 分隔线
        if re.fullmatch(r"-{3,}|\*{3,}", stripped):
            flush_para()
            close_lists()
            out.append("<hr>")
            i += 1
            continue

        # 标题
        m = re.match(r"^(#{1,4})\s+(.*)$", stripped)
        if m:
            flush_para()
            close_lists()
            level, text = len(m.group(1)), m.group(2).strip()
            anchor = ""
            if level == 2:
                anchor = f"h-{len(toc)}"
                toc.append((level, text, anchor))
            id_attr = f' id="{anchor}"' if anchor else ""
            out.append(f"<h{level}{id_attr}>{_inline(text)}</h{level}>")
            i += 1
            continue

        # 表格
        if stripped.startswith("|") and i + 1 < n and re.match(r"^\|?[\s:|-]+\|?$", lines[i + 1].strip()):
            flush_para()
            close_lists()
            headers = _split_row(stripped)
            aligns = _aligns(lines[i + 1])
            i += 2
            body: list[list[str]] = []
            while i < n and lines[i].strip().startswith("|"):
                body.append(_split_row(lines[i]))
                i += 1
            out.append('<div class="table-wrap"><table>')
            out.append("<thead><tr>")
            for idx, cell in enumerate(headers):
                al = aligns[idx] if idx < len(aligns) else "left"
                out.append(f'<th style="text-align:{al}">{_inline(cell)}</th>')
            out.append("</tr></thead><tbody>")
            for row in body:
                out.append("<tr>")
                for idx in range(len(headers)):
                    cell = row[idx] if idx < len(row) else ""
                    al = aligns[idx] if idx < len(aligns) else "left"
                    out.append(f'<td style="text-align:{al}">{_inline(cell)}</td>')
                out.append("</tr>")
            out.append("</tbody></table></div>")
            continue

        # 引用块
        if stripped.startswith(">"):
            flush_para()
            close_lists()
            buf = []
            while i < n and lines[i].strip().startswith(">"):
                buf.append(lines[i].strip()[1:].strip())
                i += 1
            out.append("<blockquote>" + _inline(" ".join(buf)) + "</blockquote>")
            continue

        # 列表
        lm = re.match(r"^(\s*)([-*]|\d+\.)\s+(.*)$", line)
        if lm:
            flush_para()
            indent, marker, text = len(lm.group(1)), lm.group(2), lm.group(3)
            want = "ol" if marker[0].isdigit() else "ul"
            depth = indent // 2 + 1
            close_lists(depth)
            if len(list_stack) < depth:
                out.append(f'<{want} class="lv{depth}">')
                list_stack.append(want)
            out.append(f"<li>{_inline(text)}</li>")
            i += 1
            continue

        para.append(stripped)
        i += 1

    flush_para()
    close_lists()
    if in_code:
        out.append("</code></pre>")
    return "\n".join(out), toc


CSS = """
:root{
  --fg:#1a1a1a; --muted:#5c5c5c; --line:#e2e2e2; --bg:#ffffff;
  --accent:#185fa5; --accent-soft:#e6f1fb; --code-bg:#f6f7f8;
  --warn-bg:#fdf3e7; --warn-line:#e0a458;
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{
  margin:0; background:#f4f4f2; color:var(--fg);
  font-family:-apple-system,"Segoe UI","Microsoft YaHei","PingFang SC",sans-serif;
  font-size:15px; line-height:1.75;
}
.page{
  max-width:1040px; margin:0 auto; background:var(--bg);
  padding:56px 60px 72px; box-shadow:0 1px 3px rgba(0,0,0,.08);
}
h1{font-size:28px; line-height:1.35; font-weight:600; margin:0 0 28px; letter-spacing:-.2px}
h1+p{margin-top:-14px}
h2{
  font-size:21px; font-weight:600; margin:52px 0 16px; padding-bottom:10px;
  border-bottom:1px solid var(--line);
}
h3{font-size:17px; font-weight:600; margin:32px 0 12px; color:#111}
h4{font-size:15px; font-weight:600; margin:24px 0 8px; color:#333}
p{margin:14px 0}
strong{font-weight:600; color:#000}
a{color:var(--accent); text-decoration:none; word-break:break-all}
a:hover{text-decoration:underline}
code{
  font-family:"Cascadia Mono",Consolas,"SF Mono",Menlo,monospace;
  font-size:13px; background:var(--code-bg); padding:2px 5px;
  border-radius:4px; color:#8a2c2c;
}
pre.code{
  background:var(--code-bg); border:1px solid var(--line); border-radius:6px;
  padding:16px 18px; overflow-x:auto; margin:18px 0; line-height:1.55;
}
pre.code code{background:none; padding:0; color:#222; font-size:12.5px; white-space:pre}
.block-wrap{overflow-x:auto}
.table-wrap{overflow-x:auto; margin:18px 0}
table{
  border-collapse:collapse; width:100%; max-width:100%;
  font-size:13px; line-height:1.6; table-layout:auto;
}
thead th{
  background:#f7f7f5; font-weight:600; color:#111; padding:9px 11px;
  border:1px solid var(--line); white-space:normal; word-break:keep-all;
}
tbody td{
  padding:8px 11px; border:1px solid var(--line);
  vertical-align:top; word-break:normal; overflow-wrap:anywhere;
}
tbody td:first-child code,
tbody td:last-child code{white-space:nowrap}
tbody tr:nth-child(even){background:#fbfbfa}
blockquote{
  margin:18px 0; padding:12px 18px; border-left:3px solid var(--warn-line);
  background:var(--warn-bg); color:#4a3a20; font-size:14px;
}
blockquote p{margin:0}
ul,ol{margin:12px 0; padding-left:26px}
li{margin:5px 0}
ul.lv2,ol.lv2{padding-left:22px; margin:4px 0}
hr{border:0; border-top:1px solid var(--line); margin:36px 0}
.toc{
  border:1px solid var(--line); border-radius:8px; padding:18px 22px;
  margin:0 0 40px; background:#fafafa;
}
.toc-title{font-size:13px; font-weight:600; color:var(--muted); letter-spacing:1px; margin-bottom:10px}
.toc a{display:block; padding:3px 0; font-size:14px; color:#333}
.toc a.lv3{padding-left:16px; font-size:13px; color:var(--muted)}
.doc-foot{
  margin-top:56px; padding-top:18px; border-top:1px solid var(--line);
  font-size:12.5px; color:var(--muted); text-align:center;
}
@media print{
  body{background:#fff; font-size:10.5pt}
  .page{box-shadow:none; max-width:none; padding:0; margin:0}
  h2{page-break-after:avoid; break-after:avoid}
  table,pre.code,blockquote{page-break-inside:avoid; break-inside:avoid}
  .toc{page-break-after:always; break-after:page}
  @page{size:A4; margin:18mm 16mm}
}
@media (max-width:720px){
  .page{padding:28px 20px}
  body{font-size:14px}
}
"""


def build(md: str, title: str) -> str:
    body, toc = convert(md)
    # 首个 h1 作为文档标题，正文里不再重复
    body = re.sub(r"<h1>.*?</h1>\n?", "", body, count=1, flags=re.S)
    toc_html = ""
    if toc:
        items = "".join(
            f'<a class="lv{level}" href="#{anchor}">{html.escape(text)}</a>'
            for level, text, anchor in toc
        )
        toc_html = (
            '<nav class="toc"><div class="toc-title">目录</div>' + items + "</nav>"
        )
        # 目录放在文档信息的表格之后、首个二级标题之前
        pos = body.find("<h2")
        if pos > 0:
            body = body[:pos] + toc_html + "\n" + body[pos:]
        else:
            body = toc_html + "\n" + body
        toc_html = ""
    return (
        "<!DOCTYPE html>\n<html lang=\"zh-CN\">\n<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{html.escape(title)}</title>\n<style>{CSS}</style>\n</head>\n<body>\n"
        f'<main class="page">\n<h1>{html.escape(title)}</h1>\n{toc_html}\n{body}\n'
        '<div class="doc-foot">NetDiag 评估报告 · 生成于 2026-11-23 · 单文件离线可读</div>\n'
        "</main>\n</body>\n</html>\n"
    )


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print("用法: python tools/md2html.py <input.md> <output.html> [标题]")
        return 2
    src, dst = argv[1], argv[2]
    with open(src, "r", encoding="utf-8") as fh:
        md = fh.read()
    title = argv[3] if len(argv) > 3 else "评估报告"
    html_doc = build(md, title)
    with open(dst, "w", encoding="utf-8") as fh:
        fh.write(html_doc)
    print(f"已生成 {dst}（{len(html_doc)} 字符）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
