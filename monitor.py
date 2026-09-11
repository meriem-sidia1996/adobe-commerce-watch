#!/usr/bin/env python3
"""
Agent de veille quotidienne Adobe Commerce Cloud / Magento.

Surveille plusieurs sources (bulletins de sécurité Adobe, CVE NVD,
releases GitHub, flux RSS) et envoie un email récapitulatif dès qu'un
nouvel élément est détecté par rapport à la dernière exécution.

Utilisation :
    python monitor.py
Variables d'environnement requises (email) :
    SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, MAIL_FROM, MAIL_TO
"""

import hashlib
import json
import os
import re
import smtplib
import sys
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import requests
import yaml

try:
    import feedparser
except ImportError:
    feedparser = None

STATE_FILE = os.environ.get("STATE_FILE", "state.json")
SOURCES_FILE = os.environ.get("SOURCES_FILE", "sources.yaml")
DIGEST_FILE = os.environ.get("DIGEST_FILE", "latest_digest.json")
USER_AGENT = "adobe-commerce-watch-bot/1.0 (+daily security & release watcher)"
TIMEOUT = 20


def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_state(state):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2, sort_keys=True)


def item_id(*parts):
    raw = "||".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


# ---------------------------------------------------------------------------
# Collecteurs par type de source
# ---------------------------------------------------------------------------

def fetch_nvd_cve(source):
    """Interroge l'API NVD 2.0 par mot-clé et renvoie les CVE trouvées.

    Sans clé API, le NVD limite fortement (voire bloque avec un 403) les
    requêtes anonymes, en particulier depuis des IP partagées comme celles
    des runners GitHub Actions. Une clé gratuite lève cette limite :
    https://nvd.nist.gov/developers/request-an-api-key
    Définissez-la dans le secret GitHub NVD_API_KEY (optionnel).
    """
    keyword = source["keyword"]
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": keyword, "resultsPerPage": 50}
    headers = {"User-Agent": USER_AGENT}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    resp = requests.get(url, params=params, headers=headers, timeout=TIMEOUT)
    resp.raise_for_status()
    data = resp.json()

    items = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        descriptions = cve.get("descriptions", [])
        desc_en = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            descriptions[0]["value"] if descriptions else "",
        )
        published = cve.get("published", "")
        link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        items.append(
            {
                "uid": item_id(source["id"], cve_id),
                "title": f"{cve_id}",
                "summary": desc_en[:400],
                "link": link,
                "date": published,
            }
        )
    return items


def fetch_html_links(source):
    """Scrape une page HTML et remonte les liens correspondant au motif défini."""
    url = source["url"]
    pattern = source.get("link_pattern", "").lower()
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,fr;q=0.8",
    }
    last_exc = None
    html = None
    for attempt in range(2):
        try:
            resp = requests.get(url, headers=headers, timeout=30)
            resp.raise_for_status()
            html = resp.text
            break
        except requests.RequestException as exc:
            last_exc = exc
    if html is None:
        raise last_exc

    # Extraction simple des liens <a href="...">texte</a>
    link_re = re.compile(r'<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
    items = []
    seen_urls = set()
    for href, text in link_re.findall(html):
        href_l = href.lower()
        if pattern and pattern not in href_l:
            continue
        full_url = href if href.startswith("http") else requests.compat.urljoin(url, href)
        if full_url in seen_urls:
            continue
        seen_urls.add(full_url)
        title = re.sub(r"<[^>]+>", "", text).strip() or full_url
        items.append(
            {
                "uid": item_id(source["id"], full_url),
                "title": title,
                "summary": "",
                "link": full_url,
                "date": "",
            }
        )
    return items


def fetch_github_releases(source):
    """Récupère les dernières releases d'un dépôt GitHub."""
    repo = source["repo"]
    url = f"https://api.github.com/repos/{repo}/releases"
    headers = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_API_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    resp = requests.get(url, headers=headers, params={"per_page": 20}, timeout=TIMEOUT)
    resp.raise_for_status()
    releases = resp.json()

    items = []
    for rel in releases:
        tag = rel.get("tag_name", "")
        name = rel.get("name") or tag
        items.append(
            {
                "uid": item_id(source["id"], tag),
                "title": f"{repo} - {name}",
                "summary": (rel.get("body") or "")[:400],
                "link": rel.get("html_url", ""),
                "date": rel.get("published_at", ""),
            }
        )
    return items


def fetch_rss(source):
    """Lit un flux RSS/Atom générique."""
    if feedparser is None:
        raise RuntimeError("Le paquet 'feedparser' n'est pas installé.")
    url = source["url"]
    parsed = feedparser.parse(url, agent=USER_AGENT)
    items = []
    for entry in parsed.entries[:30]:
        link = entry.get("link", "")
        title = entry.get("title", "(sans titre)")
        summary = entry.get("summary", "")[:400]
        date = entry.get("published", entry.get("updated", ""))
        items.append(
            {
                "uid": item_id(source["id"], entry.get("id", link or title)),
                "title": title,
                "summary": summary,
                "link": link,
                "date": date,
            }
        )
    return items


FETCHERS = {
    "nvd_cve": fetch_nvd_cve,
    "html_links": fetch_html_links,
    "github_releases": fetch_github_releases,
    "rss": fetch_rss,
}


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------

def build_email_body(new_items_by_source):
    lines_html = ["<h2>Veille quotidienne Adobe Commerce / Magento</h2>"]
    lines_html.append(
        f"<p>Généré le {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</p>"
    )
    for label, items in new_items_by_source.items():
        if not items:
            continue
        lines_html.append(f"<h3>{label} ({len(items)})</h3><ul>")
        for it in items:
            title = it["title"]
            link = it["link"]
            summary = it["summary"]
            if link:
                lines_html.append(f'<li><a href="{link}">{title}</a>')
            else:
                lines_html.append(f"<li>{title}")
            if summary:
                lines_html.append(f"<br><small>{summary}</small>")
            lines_html.append("</li>")
        lines_html.append("</ul>")
    return "\n".join(lines_html)


def send_email(subject, html_body):
    host = os.environ["SMTP_HOST"]
    port = int(os.environ.get("SMTP_PORT") or "587")
    user = os.environ["SMTP_USER"]
    password = os.environ["SMTP_PASS"]
    mail_from = os.environ.get("MAIL_FROM", user)
    mail_to = os.environ["MAIL_TO"].split(",")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = mail_from
    msg["To"] = ", ".join(mail_to)
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    with smtplib.SMTP(host, port, timeout=TIMEOUT) as server:
        server.starttls()
        server.login(user, password)
        server.sendmail(mail_from, mail_to, msg.as_string())


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    with open(SOURCES_FILE, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    state = load_state()
    new_items_by_source = {}
    errors = []

    for source in config["sources"]:
        fetcher = FETCHERS.get(source["type"])
        if not fetcher:
            errors.append(f"Type de source inconnu: {source['type']} ({source['id']})")
            continue

        try:
            items = fetcher(source)
        except Exception as exc:  # on continue même si une source échoue
            errors.append(f"Erreur source '{source['id']}': {exc}")
            continue

        seen_uids = set(state.get(source["id"], []))
        new_items = [it for it in items if it["uid"] not in seen_uids]

        if new_items:
            new_items_by_source[source["label"]] = new_items

        # Mémorise tout ce qui a été vu (limité aux 500 derniers pour éviter
        # une croissance infinie du fichier d'état)
        state[source["id"]] = list(seen_uids.union(it["uid"] for it in items))[-500:]

    save_state(state)

    # Historique cumulatif (et non plus "juste les nouveautés du jour") pour que
    # l'app React puisse le lire directement via l'URL brute GitHub, sans jamais
    # dépendre du fait qu'on ait ouvert l'app le jour précis où un item est sorti.
    history = []
    if os.path.exists(DIGEST_FILE):
        try:
            with open(DIGEST_FILE, "r", encoding="utf-8") as f:
                history = json.load(f)
        except (json.JSONDecodeError, OSError):
            history = []

    existing_keys = {(h.get("link") or h.get("title"), h.get("source")) for h in history}
    for label, items in new_items_by_source.items():
        for it in items:
            key = (it["link"] or it["title"], label)
            if key in existing_keys:
                continue
            history.append(
                {
                    "title": it["title"],
                    "summary": it["summary"],
                    "link": it["link"],
                    "date": it["date"] or datetime.now(timezone.utc).isoformat(),
                    "source": label,
                }
            )
            existing_keys.add(key)

    # Fenêtre glissante de 120 jours pour ne pas faire grossir le fichier indéfiniment.
    cutoff = datetime.now(timezone.utc) - timedelta(days=120)

    def _within_window(h):
        try:
            d = datetime.fromisoformat(h["date"].replace("Z", "+00:00"))
        except (ValueError, KeyError, TypeError, AttributeError):
            return True
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return d >= cutoff

    history = [h for h in history if _within_window(h)]
    history.sort(key=lambda h: h.get("date", ""), reverse=True)

    with open(DIGEST_FILE, "w", encoding="utf-8") as f:
        json.dump(history, f, ensure_ascii=False, indent=2)

    if errors:
        print("Avertissements :", file=sys.stderr)
        for e in errors:
            print(" - " + e, file=sys.stderr)

    total_new = sum(len(v) for v in new_items_by_source.values())
    if total_new == 0:
        print("Aucune nouveauté détectée.")
        return

    subject = f"[Veille Adobe Commerce/Magento] {total_new} nouveauté(s) détectée(s)"
    body = build_email_body(new_items_by_source)

    if os.environ.get("DRY_RUN") == "1":
        print(subject)
        print(body)
        return

    required_smtp_vars = ["SMTP_HOST", "SMTP_USER", "SMTP_PASS", "MAIL_TO"]
    missing = [v for v in required_smtp_vars if not os.environ.get(v)]
    if missing:
        print(
            "Email non envoyé (variables manquantes : "
            + ", ".join(missing)
            + "). Le digest JSON a bien été généré/mis à jour.",
            file=sys.stderr,
        )
        return

    try:
        send_email(subject, body)
        print(f"Email envoyé : {total_new} nouveauté(s).")
    except Exception as exc:
        # On ne fait jamais échouer le job pour un souci d'email : le digest
        # JSON (déjà écrit plus haut) doit être commité même si l'email plante.
        print(f"Échec de l'envoi d'email : {exc}", file=sys.stderr)


if __name__ == "__main__":
    main()
