#!/usr/bin/env python3
"""
Sportzfy — Auto-updating playlist using Playwright (headless browser).

Cloudflare blocks direct HTTP requests to /api/upstream/playback/ after
the first call. Playwright runs a real browser that passes Cloudflare's
JavaScript challenge, allowing unlimited API calls.

Pipeline:
  1. Launch headless Chromium
  2. Navigate to live.sportzfy.life (passes Cloudflare challenge)
  3. Execute fetch() calls in page context for events + playback APIs
  4. Decrypt AES-GCM encrypted stream data
  5. Verify streams (HLS/DASH)
  6. Generate M3U playlists
"""
import base64
import json
import os
import sys
import time
import hashlib
import re
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from playwright.sync_api import sync_playwright
from Crypto.Cipher import AES
import requests

# Enable unbuffered output
sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', buffering=1)

# ============== CONSTANTS ==============
BASE_URL = "https://live.sportzfy.life"
GLOBAL_KEY_K = "ZESBtSlRTuF4Ac4k757OuasOWOA0W8LcqRn3SFgdInDoMyS8"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
OUTPUT_DIR = os.path.join(REPO_ROOT, "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)

BD_TZ = timezone(timedelta(hours=6))

# ============== DECRYPTION ==============
def decrypt_playback(enc_b64, key_k, bucket):
    buf = base64.b64decode(enc_b64)
    iv = buf[:12]
    ct_with_tag = buf[12:]
    key_input = f"{key_k}|lsp-v1|{bucket}".encode('utf-8')
    key = hashlib.sha256(key_input).digest()
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    pt = cipher.decrypt_and_verify(ct_with_tag[:-16], ct_with_tag[-16:])
    return json.loads(pt.decode('utf-8'))

# ============== EVENT STATUS ==============
def parse_event_time(starts_at):
    try:
        return datetime.fromisoformat(starts_at.replace('Z', '+00:00'))
    except Exception:
        return None

def get_event_status(ev, now):
    dt = parse_event_time(ev.get('starts_at', ''))
    if not dt:
        return '', '', False, False, False
    dt = dt.astimezone(BD_TZ)
    live_start = dt - timedelta(minutes=5)
    live_end = dt + timedelta(hours=4)
    if live_start <= now <= live_end:
        return 'LIVE', '\U0001F534', True, False, False
    elif dt > now:
        return f'UPCOMING {dt.strftime("%b %d %H:%M")}', '\u23F3', False, True, False
    else:
        return f'FINISHED {dt.strftime("%b %d")}', '\u2713', False, False, True

# ============== STREAM VERIFICATION ==============
USER_AGENTS = [
    "Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 Chrome/120 Mobile",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120",
]

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VERIFY_SESSION = requests.Session()
VERIFY_SESSION.verify = False

def verify_hls(url, timeout=10):
    try:
        r = VERIFY_SESSION.get(url, timeout=timeout, stream=True)
        body = r.text[:5000]
        if '#EXTM3U' not in body:
            return False, "not M3U8"
        if '#EXT-X-STREAM-INF' in body:
            return True, "OK (master)"
        return True, "OK (media)"
    except Exception as e:
        return False, str(e)[:50]

def verify_dash(url, timeout=10):
    try:
        r = VERIFY_SESSION.get(url, timeout=timeout, stream=True)
        body = r.text[:5000]
        if '<MPD' in body:
            return True, "OK (MPD)"
        return False, "not MPD"
    except Exception as e:
        return False, str(e)[:50]

def verify_stream(url):
    if not url or url.startswith('#'):
        return False, "empty"
    lower = url.lower().split('|')[0]
    if any(s in lower for s in ['error.m3u8', 'error_pro.com', 'default.url']):
        return False, "error placeholder"
    if lower.endswith('.m3u8') or '.m3u8?' in lower or '/index.m3u8' in lower:
        return verify_hls(url)
    elif lower.endswith('.mpd') or '.mpd?' in lower:
        return verify_dash(url)
    else:
        try:
            r = VERIFY_SESSION.head(url, timeout=8, allow_redirects=True)
            if 200 <= r.status_code < 400:
                return True, f"OK (HTTP {r.status_code})"
            return False, f"HTTP {r.status_code}"
        except Exception as e:
            return False, str(e)[:50]

def verify_streams_parallel(streams, max_workers=8):
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        future_to_stream = {ex.submit(verify_stream, s['stream_url']): s for s in streams if s.get('stream_url')}
        for future in as_completed(future_to_stream):
            stream = future_to_stream[future]
            try:
                ok, msg = future.result(timeout=15)
            except Exception as e:
                ok, msg = False, f"exception: {str(e)[:50]}"
            results.append((stream, ok, msg))
    return results

# ============== BROWSER-BASED FETCHING ==============
def fetch_via_browser(page, url, headers=None):
    """Execute a fetch() call inside the browser page context."""
    js = f"""
    (async () => {{
        try {{
            const resp = await fetch({json.dumps(url)}, {{
                headers: {json.dumps(headers or {})},
                credentials: 'same-origin'
            }});
            const text = await resp.text();
            return JSON.stringify({{status: resp.status, body: text}});
        }} catch(e) {{
            return JSON.stringify({{status: 0, body: e.message}});
        }}
    }})()
    """
    result = page.evaluate(js)
    data = json.loads(result)
    return data['status'], data['body']

def fetch_events_via_browser(page):
    """Fetch events list via browser."""
    print("[1/5] Fetching events list...", flush=True)
    status, body = fetch_via_browser(page, f"{BASE_URL}/api/upstream/events", {
        "Accept": "application/json",
    })
    if status != 200:
        print(f"  ! HTTP {status}", flush=True)
        return []
    data = json.loads(body)
    events = data.get('events', [])
    print(f"      ✓ Total events: {len(events)}", flush=True)
    events.sort(key=lambda e: parse_event_time(e.get('starts_at', '')) or datetime.max.replace(tzinfo=timezone.utc))
    return events

def fetch_event_streams_via_browser(page, ev):
    """Fetch and decrypt streams for a single event via browser."""
    parent = ev.get('parent', '')
    enc_parent = ev.get('enc_parent', '')
    if not parent or not enc_parent:
        return []

    watch_url = f"{BASE_URL}/watch/{enc_parent}"

    # Fetch watch page (needed to establish Referer context)
    try:
        page.goto(watch_url, wait_until='domcontentloaded', timeout=20000)
    except Exception:
        pass

    time.sleep(0.5)

    # Fetch playback data via browser fetch()
    playback_url = f"{BASE_URL}/api/upstream/playback/{parent}"
    status, body = fetch_via_browser(page, playback_url, {
        "Accept": "application/json",
        "X-Requested-With": "lsp",
        "X-LSP-Enc": "1",
        "Referer": watch_url,
    })

    if status != 200:
        return []

    try:
        pb_data = json.loads(body)
    except Exception:
        return []

    if not pb_data.get('enc'):
        return []

    bucket = pb_data.get('bucket', 0)

    # Decrypt with global key K
    try:
        decrypted = decrypt_playback(pb_data['enc'], GLOBAL_KEY_K, bucket)
        return decrypted.get('streams', [])
    except Exception as e:
        return []

# ============== M3U BUILDER ==============
def build_m3u(events, hls_only=False, status_filter=None, include_unverified=False):
    now = datetime.now(BD_TZ)
    lines = [
        '#EXTM3U',
        '# Sportzfy Auto-Updated Playlist',
        f'# Generated: {now.isoformat()}',
        f'# Mode: {"HLS-only (Televizo-friendly)" if hls_only else "All streams (HLS+DASH)"}',
        f'# Filter: {status_filter or "all"} | Unverified: {"included" if include_unverified else "excluded"}',
        '',
    ]

    total = 0
    for ev in events:
        status_label, status_emoji, is_live, is_upcoming, is_finished = get_event_status(ev, now)
        if status_filter == 'live' and not is_live: continue
        if status_filter == 'upcoming' and not is_upcoming: continue
        if status_filter == 'finished' and not is_finished: continue

        sport = ev.get('sport', 'Sports')
        league = ev.get('league', '')
        team_a = ev.get('team_a_name', '')
        team_b = ev.get('team_b_name', '')
        logo = ev.get('team_a_logo') or ev.get('league_icon', '')
        verified = ev.get('_verified', [])

        match_name = f"{team_a} vs {team_b}" if team_a or team_b else league or 'Event'
        group = f"{sport} | {match_name}"

        server_num = 0
        for i, (stream, ok, msg) in enumerate(verified):
            url = stream.get('stream_url') if isinstance(stream, dict) else stream
            if not url:
                continue
            base_url = url.split('|')[0].lower()
            if hls_only and not (base_url.endswith('.m3u8') or '.m3u8?' in base_url or '/index.m3u8' in base_url):
                continue
            if not ok and not include_unverified:
                continue
            server_num += 1
            label = stream.get('label', '') if isinstance(stream, dict) else f"Server {server_num}"
            verify_tag = '\u2713' if ok else '\u2717'
            name = f"{status_emoji} {verify_tag} Server {server_num} | {match_name} | {label}"
            lines.append(f'#EXTINF:-1 tvg-logo="{logo}" group-title="{group}",{name}')
            lines.append(url)
            lines.append('')
            total += 1

    lines.insert(5, f'# Total entries: {total}')
    return '\n'.join(lines)

# ============== MAIN ==============
def main():
    print("=" * 65, flush=True)
    print("Sportzfy — Auto-Update Playlist (Playwright browser-based)", flush=True)
    print("=" * 65, flush=True)
    start_time = time.time()

    try:
        with sync_playwright() as p:
            # Launch headless Chromium
            print("[0/5] Launching headless browser...", flush=True)
            browser = p.chromium.launch(
                headless=True,
                args=['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
            )
            context = browser.new_context(
                user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                viewport={'width': 1280, 'height': 720},
            )
            page = context.new_page()

            # Navigate to homepage first (passes Cloudflare challenge)
            print("      Navigating to homepage...", flush=True)
            page.goto(BASE_URL, wait_until='domcontentloaded', timeout=30000)
            time.sleep(2)

            # Fetch events
            events = fetch_events_via_browser(page)

            # Fetch streams for each event
            print(f"\n[2/5] Fetching streams for {len(events)} events...", flush=True)
            for i, ev in enumerate(events):
                print(f"  [{i+1}/{len(events)}] Fetching...", end=' ', flush=True)
                streams = fetch_event_streams_via_browser(page, ev)
                ev['_streams'] = streams
                if streams:
                    print(f"{ev.get('sport','?'):12} | {ev.get('team_a_name','?')[:15]:15} vs {ev.get('team_b_name','?')[:15]:15} | {len(streams)} streams", flush=True)
                else:
                    print("0 streams", flush=True)

            browser.close()

        # Verify streams in parallel
        print(f"\n[3/5] Verifying streams (parallel, 8 workers)...", flush=True)
        all_streams = []
        for ev in events:
            for s in ev.get('_streams', []):
                if isinstance(s, dict) and s.get('stream_url'):
                    all_streams.append(s)

        print(f"      Verifying {len(all_streams)} streams...", flush=True)
        verified = verify_streams_parallel(all_streams, max_workers=8)

        idx = 0
        for ev in events:
            ev_streams = ev.get('_streams', [])
            ev_verified = []
            for s in ev_streams:
                if idx < len(verified):
                    ev_verified.append(verified[idx])
                    idx += 1
                else:
                    ev_verified.append((s, False, "no result"))
            ev['_verified'] = ev_verified

        ok_count = sum(1 for _, ok, _ in verified if ok)
        fail_count = len(verified) - ok_count
        print(f"      ✓ Verified: {ok_count} OK, {fail_count} failed", flush=True)

        # Generate M3U playlists
        print(f"\n[4/5] Generating M3U playlists...", flush=True)

        variants = [
            ("sportzfy_hls_only.m3u", True, None, False),
            ("sportzfy_hls_all.m3u", True, None, True),
            ("sportzfy_master.m3u", False, None, False),
            ("sportzfy_live.m3u", True, 'live', False),
            ("sportzfy_live_all.m3u", True, 'live', True),
            ("sportzfy_upcoming.m3u", True, 'upcoming', False),
            ("sportzfy_upcoming_all.m3u", True, 'upcoming', True),
        ]
        for fname, hls, filt, incl_unv in variants:
            m = build_m3u(events, hls_only=hls, status_filter=filt, include_unverified=incl_unv)
            with open(os.path.join(OUTPUT_DIR, fname), 'w', encoding='utf-8') as f:
                f.write(m)

        # Save JSON
        with open(os.path.join(OUTPUT_DIR, "events.json"), 'w', encoding='utf-8') as f:
            json.dump(events, f, indent=2, ensure_ascii=False, default=str)

        # Save CSV
        csv_lines = ['sport,league,team_a,team_b,starts_at,label,stream_type,stream_url,verified,verify_message']
        for ev in events:
            for i, (stream, ok, msg) in enumerate(ev.get('_verified', [])):
                url = stream.get('stream_url') if isinstance(stream, dict) else stream
                label = stream.get('label', '') if isinstance(stream, dict) else f"Server {i+1}"
                stype = stream.get('stream_type', '') if isinstance(stream, dict) else ''
                csv_lines.append(f'"{ev.get("sport","")}","{ev.get("league","")}","{ev.get("team_a_name","")}","{ev.get("team_b_name","")}","{ev.get("starts_at","")}","{label}","{stype}","{url or ""}","{"OK" if ok else "FAIL"}","{msg}"')
        with open(os.path.join(OUTPUT_DIR, "sportzfy_streams.csv"), 'w', encoding='utf-8') as f:
            f.write('\n'.join(csv_lines))

        # Save status.json
        now = datetime.now(BD_TZ)
        live_count = sum(1 for e in events if get_event_status(e, now)[2])
        upcoming_count = sum(1 for e in events if get_event_status(e, now)[3])
        status = {
            "last_updated": now.isoformat(),
            "last_updated_unix": int(now.timestamp()),
            "source": BASE_URL,
            "stats": {
                "total_events": len(events),
                "live_events": live_count,
                "upcoming_events": upcoming_count,
                "total_streams": len(verified),
                "verified_ok": ok_count,
                "verified_failed": fail_count,
            },
            "verification_rate": f"{(ok_count / len(verified) * 100):.1f}%" if verified else "0%",
            "run_duration_seconds": round(time.time() - start_time, 1),
            "github_raw_base": "https://raw.githubusercontent.com/khadembd/sportzfy-playlist/main/output/",
        }
        with open(os.path.join(OUTPUT_DIR, "status.json"), 'w') as f:
            json.dump(status, f, indent=2)

        # Summary
        print(f"\n{'='*65}", flush=True)
        print(f"SUMMARY", flush=True)
        print(f"{'='*65}", flush=True)
        print(f"  Events:    {len(events)} total", flush=True)
        print(f"             🔴 Live: {live_count} | ⏰ Upcoming: {upcoming_count}", flush=True)
        print(f"  Streams:   {len(verified)} total | ✓ {ok_count} OK | ✗ {fail_count} failed", flush=True)
        print(f"  Verification rate: {(ok_count / len(verified) * 100):.1f}%" if verified else "  N/A", flush=True)
        print(f"  Run time:  {round(time.time() - start_time, 1)}s", flush=True)
        print(f"\n  Generated playlists:", flush=True)
        for fname in ['sportzfy_hls_only.m3u', 'sportzfy_hls_all.m3u', 'sportzfy_live.m3u', 'sportzfy_live_all.m3u', 'sportzfy_upcoming.m3u', 'sportzfy_upcoming_all.m3u', 'sportzfy_master.m3u', 'status.json']:
            fpath = os.path.join(OUTPUT_DIR, fname)
            if os.path.exists(fpath):
                print(f"    {fname}: {os.path.getsize(fpath)} bytes", flush=True)
        return 0

    except Exception as e:
        import traceback
        print(f"\n❌ FATAL ERROR: {e}", flush=True)
        traceback.print_exc()
        with open(os.path.join(OUTPUT_DIR, "status.json"), 'w') as f:
            json.dump({
                "last_updated": datetime.now(BD_TZ).isoformat(),
                "error": str(e),
                "traceback": traceback.format_exc(),
            }, f, indent=2)
        return 1

if __name__ == "__main__":
    sys.exit(main())
