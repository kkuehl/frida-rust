#
# Copyright © 2026 Kirby Kuehl
#
# Licence: wxWindows Library Licence, Version 3.1
#
"""GIR `<doc>` text (gi-docgen markdown) as rustdoc."""
from __future__ import annotations

import re
from typing import Callable, List, Optional

# [kind@Namespace.Target], gi-docgen's link syntax.
_LINK = re.compile(r"\[(\w+)@([\w.:\-]+)\]")
_CONSTANT = re.compile(r"%(TRUE|FALSE|NULL)\b")
_PARAM = re.compile(r"(?<![\w`@])@(\w+)")
_HTMLISH = re.compile(r"<(/?[A-Za-z][^<>]*)>")

_CONSTANTS = {"TRUE": "`true`", "FALSE": "`false`", "NULL": "`None`"}

# Resolves a gi-docgen link: (kind, target) -> markdown.
Resolver = Callable[[str, str], str]


def _looks_like_code(lines: List[str]) -> bool:
    """A block markdown would take for code, or that is code (JSON, say)."""
    for line in lines[1:]:
        if line.startswith("    ") or line.startswith("\t"):
            return True
    return any(line.strip() in ("{", "}", "},", "[", "]") for line in lines)


def _inline(text: str, resolve: Resolver) -> str:
    # Inline code spans are left alone.
    parts = re.split(r"(`[^`]*`)", text)
    out = []
    for part in parts:
        if part.startswith("`") and part.endswith("`") and len(part) > 1:
            out.append(part)
            continue
        links: List[str] = []

        def keep(m) -> str:
            links.append(resolve(m.group(1), m.group(2)))
            return f"\x00{len(links) - 1}\x00"

        part = _LINK.sub(keep, part)
        # Brackets that are not gi-docgen links are text, not rustdoc links.
        part = part.replace("[", "\\[").replace("]", "\\]")
        part = _CONSTANT.sub(lambda m: _CONSTANTS[m.group(1)], part)
        part = _PARAM.sub(lambda m: f"`{m.group(1)}`", part)
        # Anything that looks like an HTML tag is literal text here.
        part = _HTMLISH.sub(lambda m: f"`<{m.group(1)}>`", part)
        part = re.sub("\x00(\\d+)\x00", lambda m: links[int(m.group(1))], part)
        out.append(part)
    return "".join(out)


def _dedent(lines: List[str]) -> List[str]:
    indents = [len(l) - len(l.lstrip()) for l in lines if l.strip()]
    cut = min(indents) if indents else 0
    return [l[cut:].rstrip() for l in lines]


def to_rustdoc(text: Optional[str], resolve: Resolver) -> List[str]:
    """The lines of a doc comment, without the `///`."""
    if text is None:
        return []
    text = text.replace("\r\n", "\n").strip("\n")
    if not text.strip():
        return []
    blocks: List[List[str]] = [[]]
    for line in text.split("\n"):
        if line.strip():
            blocks[-1].append(line.rstrip())
        elif blocks[-1]:
            blocks.append([])
    result: List[str] = []
    in_fence = False
    fence_lines: List[str] = []
    for block in blocks:
        if not block:
            continue
        if result:
            result.append("")
        if any(l.lstrip().startswith("```") for l in block) or in_fence:
            # A fenced block in the source: keep it, as text, never as a doctest.
            for line in block:
                stripped = line.strip()
                if stripped.startswith("```"):
                    in_fence = not in_fence
                    result.append("```text" if in_fence else "```")
                else:
                    result.append(line.rstrip() if in_fence else _inline(line.strip(), resolve))
            continue
        if _looks_like_code(block):
            result.append("```text")
            result.extend(_dedent(block))
            result.append("```")
            continue
        for line in block:
            result.append(_inline(line.strip(), resolve))
    if in_fence:
        result.append("```")
    return result


def one_line(text: Optional[str], resolve: Resolver) -> str:
    """A parameter's or a return value's doc, on a single line."""
    if not text:
        return ""
    return _inline(" ".join(text.split()), resolve)
