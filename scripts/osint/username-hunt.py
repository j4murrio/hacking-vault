#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
username-hunt.py - Find where a username is registered across public sites.

Checks a handle against a curated list of social, developer and gaming sites and
reports the profiles that exist. Each site has an explicit detection rule (status
code and/or a marker string) so false positives stay low. Pure standard library.

Only public profile pages are requested - nothing is logged into or scraped past
the first response. Authorized / educational use only.

Examples:
    python3 username-hunt.py johndoe
    python3 username-hunt.py johndoe --found-only -o hits.txt
    python3 username-hunt.py johndoe -t 30 --timeout 8
"""

import argparse
import string
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

ALLOWED = set(string.ascii_letters + string.digits + "._-")

UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                     "(KHTML, like Gecko) Chrome/125.0 Safari/537.36"}

# (name, url_template, exists_codes, absent_marker)
# exists_codes: HTTP codes that mean "profile present".
# absent_marker: if this string is in the body, treat as NOT present (kills the
# soft-404 sites that return 200 for everything).
SITES = [
    ("GitHub",        "https://github.com/{}",               {200}, None),
    ("GitLab",        "https://gitlab.com/{}",               {200}, None),
    ("Twitter/X",     "https://x.com/{}",                    {200}, None),
    ("Instagram",     "https://www.instagram.com/{}/",       {200}, None),
    ("Reddit",        "https://www.reddit.com/user/{}",      {200}, "nobody on Reddit"),
    ("Twitch",        "https://www.twitch.tv/{}",            {200}, None),
    ("TikTok",        "https://www.tiktok.com/@{}",          {200}, None),
    ("YouTube",       "https://www.youtube.com/@{}",         {200}, None),
    ("Telegram",      "https://t.me/{}",                     {200}, "tgme_page_additional"),
    ("Keybase",       "https://keybase.io/{}",               {200}, None),
    ("Medium",        "https://medium.com/@{}",              {200}, None),
    ("Dev.to",        "https://dev.to/{}",                   {200}, None),
    ("StackOverflow", "https://stackoverflow.com/users/{}",  {200}, None),
    ("HackerNews",    "https://news.ycombinator.com/user?id={}", {200}, "No such user"),
    ("Pinterest",     "https://www.pinterest.com/{}/",       {200}, None),
    ("SoundCloud",    "https://soundcloud.com/{}",           {200}, None),
    ("Steam",         "https://steamcommunity.com/id/{}",    {200}, "The specified profile could not be found"),
    ("Gravatar",      "https://gravatar.com/{}",             {200}, None),
    ("Replit",        "https://replit.com/@{}",              {200}, None),
    ("PyPI",          "https://pypi.org/user/{}/",           {200}, None),
    ("npm",           "https://www.npmjs.com/~{}",           {200}, None),
    ("Docker Hub",    "https://hub.docker.com/u/{}",         {200}, None),
    ("Patreon",       "https://www.patreon.com/{}",          {200}, None),
    ("About.me",      "https://about.me/{}",                 {200}, None),
    ("Vimeo",         "https://vimeo.com/{}",                {200}, None),
    ("Spotify",       "https://open.spotify.com/user/{}",    {200}, None),
    ("Chess.com",     "https://www.chess.com/member/{}",     {200}, None),
    ("HackerOne",     "https://hackerone.com/{}",            {200}, None),
    ("Bitbucket",     "https://bitbucket.org/{}/",           {200}, None),
    ("Mastodon.social", "https://mastodon.social/@{}",       {200}, None),
]


def check(site, username, timeout=8):
    """Return (name, url, state) where state is 'found' | 'absent' | 'error'."""
    name, tmpl, codes, marker = site
    url = tmpl.format(username)
    req = urllib.request.Request(url, headers=UA, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            code = r.getcode()
            body = r.read(20000).decode("utf-8", "replace") if marker else ""
    except urllib.error.HTTPError as e:
        return name, url, "found" if e.code in codes else "absent"
    except Exception:
        return name, url, "error"
    if code in codes and (marker is None or marker not in body):
        return name, url, "found"
    return name, url, "absent"


def normalize_username(name):
    """Accept what people paste: trim spaces and a leading '@' (@johndoe)."""
    return name.strip().lstrip("@")


def valid_username(name):
    return bool(name) and all(c in ALLOWED for c in name)


def main():
    p = argparse.ArgumentParser(
        description="Find where a username is registered across public sites.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("username", help="the handle to search for")
    p.add_argument("--found-only", action="store_true",
                   help="print only the sites where the profile exists")
    p.add_argument("-o", "--output", help="write found profile URLs to a file")
    p.add_argument("-t", "--threads", type=int, default=20, help="concurrency (default 20)")
    p.add_argument("--timeout", type=float, default=8, help="per-site timeout s (default 8)")
    args = p.parse_args()

    username = normalize_username(args.username)
    if not valid_username(username):
        sys.exit("[-] Username may contain only ASCII letters, digits, '.', '_' and '-'.")

    print(f"[*] Hunting '{username}' across {len(SITES)} sites ...",
          file=sys.stderr)
    found, errors = [], 0
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = [pool.submit(check, s, username, args.timeout) for s in SITES]
        for fut in as_completed(futures):
            name, url, state = fut.result()
            if state == "found":
                found.append((name, url))
                print(f"  [+] {name:<16} {url}")
            elif state == "error":
                errors += 1
            elif not args.found_only:
                print(f"  [-] {name:<16} not found")

    print(f"\n[+] Found on {len(found)} site(s)"
          + (f", {errors} unreachable" if errors else ""), file=sys.stderr)
    if args.output and found:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write("\n".join(url for _, url in sorted(found)) + "\n")
        print(f"[+] Wrote {len(found)} URL(s) to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
