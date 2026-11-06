"""Web pack parsers: whatweb, feroxbuster, gobuster, dirsearch, ffuf (dir and vhost modes).

Each reads the tool's own machine-readable output where it has one, and returns Url, Software,
Hostname and User findings. Redirects to a hostname become Hostname findings, because on HTB a
redirect to ``box.htb`` is the classic sign that the site needs an /etc/hosts entry.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urljoin, urlsplit

from cyberdeck.core.models import Finding, Hostname, Software, Url, User
from cyberdeck.plugins.parsers import ParseContext, json_lines, parser

# --- whatweb --------------------------------------------------------------------------------

# Plugins that describe the response rather than the software behind it.
_WHATWEB_SKIP = frozenset(
    {
        "Country",
        "IP",
        "Title",
        "HTTPServer",
        "X-Powered-By",
        "RedirectLocation",
        "Script",
        "HTML5",
        "Cookies",
        "HttpOnly",
        "UncommonHeaders",
        "MetaGenerator",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-XSS-Protection",
        "X-UA-Compatible",
        "Content-Security-Policy",
        "Frame",
        "Open-Graph-Protocol",
        "PasswordField",
        "Email",
        "Via-Proxy",
        "Access-Control-Allow-Methods",
        "Allow",
        "Meta-Refresh-Redirect",
        "Object",
        "Meta-Author",
        "Bootstrap",  # usually just front-end noise; kept out to reduce clutter
    }
)


def _first(plugin: dict[str, Any], key: str) -> str | None:
    values = plugin.get(key)
    if isinstance(values, list) and values:
        return str(values[0])
    return None


def _load_json(text: str) -> Any:
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        # An interrupted whatweb leaves "[ {...},\n" without the closing bracket.
        return [obj for obj in json_lines(text.replace("},\n", "}\n"))]


@parser("whatweb_json")
def parse_whatweb(ctx: ParseContext) -> list[Finding]:
    data = _load_json(ctx.read())
    entries = data if isinstance(data, list) else [data] if isinstance(data, dict) else []
    found: list[Finding] = []
    for entry in entries:
        if not isinstance(entry, dict) or "target" not in entry:
            continue
        target = str(entry["target"])
        plugins: dict[str, Any] = entry.get("plugins") or {}
        title = _first(plugins.get("Title") or {}, "string")
        redirect = _first(plugins.get("RedirectLocation") or {}, "string")
        tags = ["login"] if "PasswordField" in plugins else []
        status = entry.get("http_status")
        url = Url(
            url=target,
            status=int(status) if isinstance(status, int) else None,
            title=title,
            redirect=redirect,
        )
        found.append(ctx.finding(url, tags=tags))
        for name in (target, redirect):
            host = ctx.hostname_from_url(
                name, f"whatweb:{'redirect' if name == redirect else 'url'}"
            )
            if host is not None:
                found.append(host)
        for name, plugin in plugins.items():
            if name in _WHATWEB_SKIP or not isinstance(plugin, dict):
                continue
            version = _first(plugin, "version")
            found.append(
                ctx.finding(Software(name=name, version=version, where=target), confidence=0.8)
            )
        generator = _first(plugins.get("MetaGenerator") or {}, "string")
        if generator and not any(g in plugins for g in generator.split()[:1]):
            found.append(ctx.finding(Software(name=generator, where=target), confidence=0.6))
        for email in (plugins.get("Email") or {}).get("string") or []:
            local, _, domain = str(email).partition("@")
            if local:
                user = User(name=local, realm=domain or None)
                found.append(ctx.finding(user, confidence=0.4, tags=["email"]))
    return found


# --- directory brute-forcers ---------------------------------------------------------------


def _url_findings(
    ctx: ParseContext,
    url: str,
    status: int | None,
    length: int | None,
    redirect: str | None,
    tool: str,
) -> list[Finding]:
    found = [ctx.finding(Url(url=url, status=status, length=length, redirect=redirect or None))]
    host = ctx.hostname_from_url(redirect, f"{tool}:redirect")
    if host is not None:
        found.append(host)
    return found


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


@parser("feroxbuster_json")
def parse_feroxbuster(ctx: ParseContext) -> list[Finding]:
    found: list[Finding] = []
    for obj in json_lines(ctx.read()):
        if obj.get("type") != "response" or obj.get("wildcard"):
            continue
        headers = obj.get("headers") or {}
        location = headers.get("location") if isinstance(headers, dict) else None
        found += _url_findings(
            ctx,
            str(obj.get("url")),
            _as_int(obj.get("status")),
            _as_int(obj.get("content_length")),
            str(location) if location else None,
            "feroxbuster",
        )
    return found


# "admin (Status: 301) [Size: 0] [--> http://box.htb/admin/]"   (gobuster 3.x; older: "/admin")
_GOBUSTER_RE = re.compile(
    r"^(?P<path>\S+)\s+\(Status:\s*(?P<status>\d+)\)"
    r"(?:\s*\[Size:\s*(?P<size>\d+)\])?(?:\s*\[-->\s*(?P<redirect>[^\]\s]+)\])?"
)
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


@parser("gobuster_dir")
def parse_gobuster(ctx: ParseContext) -> list[Finding]:
    base = str(ctx.values.get("url") or "")
    if base and not base.endswith("/"):
        base += "/"
    found: list[Finding] = []
    for raw in ctx.read().splitlines():
        match = _GOBUSTER_RE.match(_ANSI.sub("", raw).strip())
        if not match:
            continue
        path = match.group("path")
        url = path if "://" in path else urljoin(base, path.lstrip("/"))
        found += _url_findings(
            ctx,
            url,
            _as_int(match.group("status")),
            _as_int(match.group("size")),
            match.group("redirect"),
            "gobuster",
        )
    return found


@parser("dirsearch_json")
def parse_dirsearch(ctx: ParseContext) -> list[Finding]:
    data = _load_json(ctx.read())
    results = data.get("results") if isinstance(data, dict) else None
    found: list[Finding] = []
    for item in results or []:
        if not isinstance(item, dict) or not item.get("url"):
            continue
        found += _url_findings(
            ctx,
            str(item["url"]),
            _as_int(item.get("status")),
            _as_int(item.get("contentLength")),
            str(item.get("redirect") or "") or None,
            "dirsearch",
        )
    return found


# --- ffuf -----------------------------------------------------------------------------------


@parser("ffuf_dir")
def parse_ffuf_dir(ctx: ParseContext) -> list[Finding]:
    """ffuf ``-u <url>FUZZ -of json`` results: each hit is a URL on the site."""
    data = _load_json(ctx.read())
    results = data.get("results") if isinstance(data, dict) else None
    found: list[Finding] = []
    for item in results or []:
        if not isinstance(item, dict) or not item.get("url"):
            continue
        found += _url_findings(
            ctx,
            str(item["url"]),
            _as_int(item.get("status")),
            _as_int(item.get("length")),
            str(item.get("redirectlocation") or "") or None,
            "ffuf",
        )
    return found


@parser("ffuf_vhost")
def parse_ffuf_vhost(ctx: ParseContext) -> list[Finding]:
    """ffuf ``-H "Host: FUZZ.<domain>"`` results: each hit is a virtual host."""
    data = _load_json(ctx.read())
    results = data.get("results") if isinstance(data, dict) else None
    base = urlsplit(str(ctx.values.get("url") or "http://x/"))
    scheme = base.scheme or "http"
    default_port = {"http": 80, "https": 443}.get(scheme)
    port = f":{base.port}" if base.port and base.port != default_port else ""
    found: list[Finding] = []
    for item in results or []:
        if not isinstance(item, dict):
            continue
        host = str(item.get("host") or "")
        fuzz = (item.get("input") or {}).get("FUZZ")
        if (not host or "FUZZ" in host) and fuzz and ctx.values.get("domain"):
            host = f"{fuzz}.{ctx.values['domain']}"
        payload_host = host.split(":")[0]
        try:
            name = Hostname(
                fqdn=payload_host, ip=ctx.target_ip, kind="host", origins=["ffuf:vhost"]
            )
        except ValueError:
            continue
        found.append(ctx.finding(name, confidence=0.9, tags=["vhost"]))
        url = Url(
            url=f"{scheme}://{name.fqdn}{port}/",  # same port as the fuzzed URL
            status=_as_int(item.get("status")),
            length=_as_int(item.get("length")),
            redirect=str(item.get("redirectlocation") or "") or None,
        )
        found.append(ctx.finding(url, tags=["vhost"]))
    return found


# --- page inspection (page-inspect: curl -s -i -L -o page.txt) ---------------------------
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_TITLE_SPLIT = re.compile(r"\s+[-|–—:·»]\s+")
_GENERIC_TITLE = re.compile(
    r"^(?:log ?in|sign ?in|log ?on|login page|home|home page|welcome|index|dashboard|portal|"
    r"admin|administration|main|default|untitled|page|error|not found)$",
    re.I,
)
_VERSION = re.compile(r"\b(?:version|ver\.?|v)\s?(\d+(?:\.\d+){1,3}[a-z0-9-]*)\b", re.I)
_META_GENERATOR = re.compile(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)", re.I)
_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
_ATTR_TEXT = re.compile(
    r"\b(?P<attr>title|placeholder|alt|aria-label|data-[\w-]+)\s*=\s*[\"'](?P<text>[^\"']{6,300})[\"']",
    re.I,
)
# tooltips and data-* attributes: any of these words; placeholders/alt text describe the field
# ("Password", "Device password"), so they only count with the strong phrases of _HINT_TEXT.
_HINT_ATTR = re.compile(
    r"password|passwd|default|serial|credential|username|secret|token|api[ _-]?key|"
    r"todo|fixme|debug|temporary|backdoor",
    re.I,
)
_HINT_TEXT = re.compile(
    r"default (?:password|credential|login|user)|serial number|todo|fixme", re.I
)
_FORM = re.compile(r"<form\b([^>]*)>", re.I)
_JS_CALL = re.compile(
    r"(?:fetch|axios\.(?P<amethod>get|post|put|delete|patch)|\$\.(?P<jmethod>get|post|ajax)|"
    r"\.open)\(\s*(?:[\"'](?P<omethod>GET|POST|PUT|DELETE|PATCH)[\"']\s*,\s*)?"
    r"[\"'`](?P<path>/[^\"'`\s?#]*|https?://[^\"'`\s]+)",
    re.I,
)
_JS_METHOD = re.compile(r"method\s*:\s*[\"'](\w+)[\"']", re.I)
_STRIP = re.compile(r"<(script|style)\b.*?</\1>", re.I | re.S)
_TAG = re.compile(r"<[^>]+>")
_HEADER_SOFTWARE = ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator")


def _attr(tag: str, name: str) -> str | None:
    match = re.search(rf"\b{name}\s*=\s*[\"']([^\"']*)[\"']", tag, re.I)
    return match.group(1) if match else None


def _split_response(text: str, url: str) -> tuple[str, int | None, dict[str, str], str]:
    """Last response of a ``curl -i -L`` dump: (final URL, status, headers, body). The final
    URL follows each redirect's Location header from the requested ``url``."""
    status: int | None = None
    headers: dict[str, str] = {}
    while text.startswith("HTTP/"):
        if headers.get("location") and status in (301, 302, 303, 307, 308):
            url = urljoin(url, headers["location"])
        parts = re.split(r"\r?\n\r?\n", text, maxsplit=1)
        head, text = parts[0], (parts[1] if len(parts) > 1 else "")
        lines = head.splitlines()
        code = re.match(r"HTTP/\S+\s+(\d{3})", lines[0])
        status = int(code.group(1)) if code else None
        headers = {}
        for line in lines[1:]:
            key, _, value = line.partition(":")
            if value:
                headers[key.strip().lower()] = value.strip()
    return url, status, headers, text


def _clean(text: str) -> str:
    import html

    return re.sub(r"\s+", " ", html.unescape(text)).strip()


@parser("html_inspect")
def parse_html_inspect(ctx: ParseContext) -> list[Finding]:
    """What a person reads in a page's source: product name and version, hints in tooltips,
    placeholders and comments, and endpoints called from forms and JavaScript."""
    import hashlib

    from cyberdeck.core.models import Note

    url, status, headers, body = _split_response(ctx.read(), str(ctx.values.get("url") or ""))
    found: list[Finding] = []
    title_match = _TITLE.search(body)
    title = _clean(title_match.group(1)) if title_match else None
    if url:
        found.append(ctx.finding(Url(url=url, status=status, length=len(body), title=title)))
    visible = _clean(_TAG.sub(" ", _STRIP.sub(" ", body)))
    version_match = _VERSION.search(visible)
    version = version_match.group(1) if version_match else None
    if title:
        parts = [p.strip() for p in _TITLE_SPLIT.split(title) if p.strip()]
        product = next((p for p in parts if not _GENERIC_TITLE.match(p)), None)
        if product and len(product) <= 60:
            software = Software(name=product, version=version, where=url or None)
            found.append(ctx.finding(software, confidence=0.5, tags=["from-title"]))
    generator = _META_GENERATOR.search(body)
    if generator:
        name, _, gen_version = _clean(generator.group(1)).partition(" ")
        software = Software(name=name, version=gen_version or None, where=url or None)
        found.append(ctx.finding(software, confidence=0.7))
    for key in _HEADER_SOFTWARE:
        if key in headers:
            name, _, head_version = headers[key].partition("/")
            software = Software(name=name.strip(), version=head_version.strip() or None, where=url)
            found.append(ctx.finding(software, confidence=0.7))

    def hint(text: str, where: str) -> None:
        text = _clean(text)
        if not text:
            return
        digest = hashlib.sha256(f"{url}\n{text}".encode()).hexdigest()[:12]
        path = urlsplit(url).path or "/"
        note = Note(note_id=f"hint-{digest}", title=f"Hint in {where} on {path}", text=text)
        found.append(ctx.finding(note, confidence=0.6, tags=["hint"]))

    for comment in _COMMENT.findall(body):
        if len(comment.strip()) > 3 and not comment.strip().startswith("[if"):
            hint(comment, "an HTML comment")
    for match in _ATTR_TEXT.finditer(body):
        attr, text = match.group("attr").lower(), match.group("text")
        if attr in ("placeholder", "alt"):
            if _HINT_TEXT.search(text):
                hint(text, f"a {attr}")
        elif _HINT_ATTR.search(text) and len(text) >= 20:
            hint(text, "a tooltip" if attr == "title" else f"the {attr} attribute")
    for sentence in re.split(r"(?<=[.!?])\s+", visible):
        if _HINT_TEXT.search(sentence) and len(sentence) <= 300:
            hint(sentence, "the page text")

    seen: set[tuple[str, str]] = set()

    def endpoint(path: str, method: str, how: str) -> None:
        target = urljoin(url, path) if url else path
        key = (target, method)
        if key in seen or not target.startswith("http"):
            return
        seen.add(key)
        tags = [how, method.lower(), "from-page"]
        found.append(ctx.finding(Url(url=target), confidence=0.7, tags=tags))

    for form in _FORM.finditer(body):
        attrs = form.group(1)
        endpoint(_attr(attrs, "action") or url, (_attr(attrs, "method") or "GET").upper(), "form")
    for call in _JS_CALL.finditer(body):
        method = call.group("amethod") or call.group("omethod") or ""
        if call.group("jmethod") and call.group("jmethod").lower() != "ajax":
            method = call.group("jmethod")
        if not method:
            window = body[call.end() : call.end() + 200]
            method_match = _JS_METHOD.search(window)
            method = method_match.group(1) if method_match else "GET"
        endpoint(call.group("path"), method.upper(), "js")
    return found
