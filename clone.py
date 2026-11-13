#!/usr/bin/env python3
"""
clone_site.py - Clona un sitio web (HTML + CSS + assets) SIN JavaScript.

Uso:
    python clone_site.py https://ejemplo.com -o ./mirror
    python clone_site.py https://ejemplo.com -o ./mirror --max-pages 200 --delay 0.3

Requisitos:
    pip install requests beautifulsoup4
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse, urldefrag, unquote

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    sys.exit("Faltan dependencias. Ejecuta: pip install requests beautifulsoup4")

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SiteCloner/1.0"

# Extensiones que NUNCA descargamos (JS)
SKIP_EXT = {".js", ".mjs", ".cjs", ".map"}

# Extensiones que tratamos como "página"
PAGE_EXTS = {"", ".html", ".htm", ".xhtml", ".php", ".asp", ".aspx", ".jsp"}

# Extensión local según Content-Type (para URLs sin extensión)
CONTENT_TYPE_EXT = {
    "image/png": ".png", "image/jpeg": ".jpg", "image/jpg": ".jpg",
    "image/gif": ".gif", "image/svg+xml": ".svg", "image/webp": ".webp",
    "image/x-icon": ".ico", "image/vnd.microsoft.icon": ".ico",
    "image/bmp": ".bmp", "image/avif": ".avif",
    "font/woff": ".woff", "font/woff2": ".woff2",
    "font/ttf": ".ttf", "font/otf": ".otf",
    "application/font-woff": ".woff", "application/font-woff2": ".woff2",
    "application/x-font-ttf": ".ttf",
    "application/vnd.ms-fontobject": ".eot",
    "application/pdf": ".pdf",
    "video/mp4": ".mp4", "video/webm": ".webm", "video/ogg": ".ogv",
    "audio/mpeg": ".mp3", "audio/ogg": ".ogg", "audio/wav": ".wav",
    "text/css": ".css",
}


def is_page_path(path: str) -> bool:
    if path.endswith("/") or path == "":
        return True
    return os.path.splitext(path)[1].lower() in PAGE_EXTS


class SiteCloner:
    def __init__(self, base_url, output_dir, max_pages=500, delay=0.2, verbose=True):
        if not urlparse(base_url).scheme:
            base_url = "https://" + base_url
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc
        self.output_dir = Path(output_dir).resolve()
        self.max_pages = max_pages
        self.delay = delay
        self.verbose = verbose

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": UA})

        self.visited = set()     # URLs de páginas visitadas
        self.queued = set()      # URLs en cola
        self.queue = []          # cola FIFO
        self.assets = {}         # url -> Path
        self.pages = {}          # url -> Path

    # ----------------- utilidades -----------------
    def log(self, msg):
        if self.verbose:
            print(msg)

    def same_domain(self, url):
        return urlparse(url).netloc == self.domain

    def should_skip(self, url):
        return os.path.splitext(urlparse(url).path.lower())[1] in SKIP_EXT

    def url_to_path(self, url, is_page=None):
        parsed = urlparse(url)
        path = unquote(parsed.path) or "/"

        if is_page is None:
            is_page = is_page_path(path)

        if is_page:
            if path.endswith("/") or path == "":
                path += "index.html"
            elif os.path.splitext(path)[1] == "":
                path = path.rstrip("/") + "/index.html"

        if parsed.query:
            h = abs(hash(parsed.query)) % 100000
            p = Path(path)
            suf = p.suffix or (".html" if is_page else "")
            path = str(p.with_name(f"{p.stem}_{h}{suf}"))

        path = path.lstrip("/") or "index.html"
        return self.output_dir / path

    def save_bytes(self, url, content, is_page=False, content_type=None):
        path = self.url_to_path(url, is_page=is_page)
        # Si la URL no tenía extensión pero el content-type la delata, la añadimos
        if not is_page and path.suffix == "" and content_type:
            ext = CONTENT_TYPE_EXT.get(content_type.split(";")[0].strip().lower(), "")
            if ext:
                path = path.with_suffix(ext)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    # ----------------- CSS -----------------
    def rewrite_css_urls(self, text: str, base_url: str, local_dir: Path) -> str:
        if not text:
            return text

        import_re = re.compile(r'@import\s+([\'"])([^\'"]+)\1', re.IGNORECASE)
        url_re = re.compile(r'url\(\s*[\'"]?([^\'")]+)[\'"]?\s*\)', re.IGNORECASE)

        def resolve(raw: str):
            raw = raw.strip()
            if not raw or raw.startswith(("data:", "#")):
                return None
            absolute = urljoin(base_url, raw)
            if self.should_skip(absolute):
                return None
            local = self.download_asset(absolute)
            if not local:
                return None
            return os.path.relpath(local, local_dir).replace(os.sep, "/")

        def repl_import(m):
            rel = resolve(m.group(2))
            return m.group(0) if rel is None else f"@import {m.group(1)}{rel}{m.group(1)}"

        def repl_url(m):
            rel = resolve(m.group(1))
            return m.group(0) if rel is None else f'url("{rel}")'

        text = import_re.sub(repl_import, text)
        text = url_re.sub(repl_url, text)
        return text

    def process_css_file(self, css_path: Path, css_url: str):
        try:
            text = css_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return
        new_text = self.rewrite_css_urls(text, css_url, css_path.parent)
        if new_text != text:
            css_path.write_text(new_text, encoding="utf-8")

    # ----------------- assets -----------------
    def download_asset(self, url):
        url, _ = urldefrag(url)
        if not url or url.startswith(("data:", "mailto:", "tel:", "javascript:", "#")):
            return None
        if self.should_skip(url):
            self.log(f"  [skip-js] {url}")
            return None
        if url in self.assets:
            return self.assets[url]

        try:
            r = self.session.get(url, timeout=30)
            r.raise_for_status()
        except Exception as e:
            self.log(f"  [err]     {url} -> {e}")
            self.assets[url] = None
            return None

        ctype = r.headers.get("Content-Type", "")
        local_path = self.save_bytes(url, r.content, is_page=False, content_type=ctype)
        self.assets[url] = local_path
        self.log(f"  [asset]   {url} -> {local_path.relative_to(self.output_dir)}")

        if "text/css" in ctype or urlparse(url).path.lower().endswith(".css"):
            self.process_css_file(local_path, url)

        return local_path

    # ----------------- HTML -----------------
    def process_html(self, html: str, page_url: str) -> str:
        soup = BeautifulSoup(html, "html.parser")

        # 1) eliminar scripts / noscript / base / meta-refresh
        for tag in soup.find_all(["script", "noscript", "base"]):
            tag.decompose()
        for meta in soup.find_all("meta", attrs={"http-equiv": "refresh"}):
            meta.decompose()

        page_local = self.url_to_path(page_url, is_page=True)
        page_dir = page_local.parent

        def rel(local: Path) -> str:
            return os.path.relpath(local, page_dir).replace(os.sep, "/")

        # 2) CSS inline (<style> y style="")
        for st in soup.find_all("style"):
            if st.string:
                st.string = self.rewrite_css_urls(st.string, page_url, page_dir)
        for tag in soup.find_all(style=True):
            tag["style"] = self.rewrite_css_urls(tag["style"], page_url, page_dir)

        # 3) <link>
        for link in soup.find_all("link", href=True):
            href = link["href"].strip()
            if href.startswith(("data:", "#")):
                continue
            absolute = urljoin(page_url, href)
            if self.should_skip(absolute):
                link.decompose()
                continue
            local = self.download_asset(absolute)
            if local:
                link["href"] = rel(local)
            else:
                link.decompose()

        # 4) <img src> y <img srcset>
        for img in soup.find_all("img"):
            if img.get("src"):
                absolute = urljoin(page_url, img["src"].strip())
                if not self.should_skip(absolute):
                    local = self.download_asset(absolute)
                    if local:
                        img["src"] = rel(local)
                    else:
                        img.decompose()
                        continue
            if img.get("srcset"):
                new_set = self.process_srcset(img["srcset"], page_url, page_dir)
                if new_set:
                    img["srcset"] = new_set
                else:
                    del img["srcset"]

        # 5) <source>
        for src in soup.find_all("source"):
            if src.get("src"):
                absolute = urljoin(page_url, src["src"].strip())
                if not self.should_skip(absolute):
                    local = self.download_asset(absolute)
                    if local:
                        src["src"] = rel(local)
            if src.get("srcset"):
                new_set = self.process_srcset(src["srcset"], page_url, page_dir)
                if new_set:
                    src["srcset"] = new_set
                else:
                    del src["srcset"]

        # 6) video / audio / embed / object
        for tag_name, attr in [("video", "src"), ("video", "poster"),
                               ("audio", "src"), ("embed", "src"),
                               ("object", "data")]:
            for tag in soup.find_all(tag_name):
                val = tag.get(attr)
                if not val:
                    continue
                absolute = urljoin(page_url, val.strip())
                if self.should_skip(absolute):
                    continue
                local = self.download_asset(absolute)
                if local:
                    tag[attr] = rel(local)

        # 7) <a href> (solo mismo dominio)
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if href.startswith(("mailto:", "tel:", "javascript:", "#", "data:")):
                continue
            absolute = urljoin(page_url, href)
            if not self.same_domain(absolute) or self.should_skip(absolute):
                continue
            absolute, _ = urldefrag(absolute)
            self.enqueue_page(absolute)
            # Si la URL apunta a un archivo conocido => asset; si no => página
            is_page = is_page_path(urlparse(absolute).path)
            a["href"] = rel(self.url_to_path(absolute, is_page=is_page))

        return str(soup)

    def process_srcset(self, srcset: str, page_url: str, page_dir: Path):
        out = []
        for chunk in srcset.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            bits = chunk.split(None, 1)
            url_part = bits[0]
            rest = bits[1] if len(bits) > 1 else ""
            absolute = urljoin(page_url, url_part)
            if self.should_skip(absolute):
                continue
            local = self.download_asset(absolute)
            if not local:
                continue
            rel = os.path.relpath(local, page_dir).replace(os.sep, "/")
            out.append(f"{rel} {rest}".strip())
        return ", ".join(out) if out else None

    # ----------------- crawl -----------------
    def enqueue_page(self, url: str):
        url, _ = urldefrag(url)
        if not url or not self.same_domain(url) or self.should_skip(url):
            return
        if url in self.visited or url in self.queued:
            return
        self.queued.add(url)
        self.queue.append(url)

    def crawl_page(self, url: str):
        url, _ = urldefrag(url)
        if url in self.visited:
            return
        self.visited.add(url)

        self.log(f"\n[page] {url}")
        try:
            r = self.session.get(url, timeout=30)
            r.raise_for_status()
        except Exception as e:
            self.log(f"  [err] {url} -> {e}")
            return

        ctype = r.headers.get("Content-Type", "")
        if "text/html" not in ctype and "application/xhtml" not in ctype:
            # no es HTML => guardar como asset (ej. PDF enlazado con <a>)
            local = self.save_bytes(url, r.content, is_page=False, content_type=ctype)
            self.assets[url] = local
            self.log(f"  [asset] {url} -> {local.relative_to(self.output_dir)}")
            return

        cleaned = self.process_html(r.text, url)
        page_path = self.url_to_path(url, is_page=True)
        page_path.parent.mkdir(parents=True, exist_ok=True)
        page_path.write_text(cleaned, encoding="utf-8")
        self.pages[url] = page_path
        self.log(f"  [saved] {page_path.relative_to(self.output_dir)}")

        if self.delay:
            time.sleep(self.delay)

    def run(self):
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.enqueue_page(self.base_url)

        while self.queue and len(self.visited) < self.max_pages:
            self.crawl_page(self.queue.pop(0))

        if len(self.visited) >= self.max_pages:
            self.log(f"\n[!] Límite de {self.max_pages} páginas alcanzado.")

        n_assets = len([v for v in self.assets.values() if v])
        self.log(f"\n✅ Listo. {len(self.pages)} páginas, {n_assets} assets.")
        self.log(f"   Abre: {self.output_dir / 'index.html'}")
        self.log("   O sirve con: python -m http.server 8000 --directory "
                 f"\"{self.output_dir}\"")


def main():
    ap = argparse.ArgumentParser(description="Clona un sitio web sin JavaScript.")
    ap.add_argument("url", help="URL de inicio (ej. https://ejemplo.com)")
    ap.add_argument("-o", "--output", default="./mirror", help="Carpeta de salida")
    ap.add_argument("--max-pages", type=int, default=500,
                    help="Límite de páginas HTML a crawlear (default 500)")
    ap.add_argument("--delay", type=float, default=0.2,
                    help="Pausa entre páginas (seg, default 0.2)")
    ap.add_argument("-q", "--quiet", action="store_true", help="Silencioso")
    args = ap.parse_args()

    cloner = SiteCloner(
        base_url=args.url,
        output_dir=args.output,
        max_pages=args.max_pages,
        delay=args.delay,
        verbose=not args.quiet,
    )
    try:
        cloner.run()
    except KeyboardInterrupt:
        print("\nInterrumpido por el usuario.")
        sys.exit(130)


if __name__ == "__main__":
    main()