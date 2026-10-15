#!/usr/bin/env bash
# Renders social preview images from design/og.html with headless Firefox.
# Needs: firefox, python3, ImageMagick, and `npm run dev` running on :8787 (for the tool list).
set -euo pipefail
cd "$(dirname "$0")/.."

DEV=${DEV:-http://127.0.0.1:8787}
PORT=8899
PROFILE=$(mktemp -d)
OUT="$PWD/public/og"
mkdir -p "$OUT"

python3 -m http.server "$PORT" --bind 127.0.0.1 >/dev/null 2>&1 &
SERVER=$!
trap 'kill $SERVER; rm -rf "$PROFILE"' EXIT
sleep 1

shot() { # url width height file
  firefox --headless --no-remote --profile "$PROFILE" --window-size="$2,$3" --screenshot "$4" "$1" >/dev/null 2>&1
  magick "$4" -strip -define png:compression-level=9 "$4"
  echo "  $4 ($(du -h "$4" | cut -f1))"
}

base="http://127.0.0.1:$PORT/design/og.html"
shot "$base" 1200 630 "$OUT/default.png"
shot "$base" 1280 640 "$PWD/design/github-social-preview.png"

curl -fsS "$DEV/api/tools" | python3 -c '
import json, sys, urllib.parse
for t in json.load(sys.stdin):
    q = urllib.parse.urlencode({"title": t["title"], "sub": t["description"], "icon": t["icon"]})
    print(t["slug"], q)
' | while read -r slug query; do
  shot "$base?$query" 1200 630 "$OUT/$slug.png"
done
