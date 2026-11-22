#!/usr/bin/env bash
set -euo pipefail

RELEASE="v1.0.0-rc.7"
ASSET="daikin_BRY88BBA15G.ota.bin.raw"
URL="https://github.com/phicomm-io/iotcloud-community-firmware/releases/download/${RELEASE}/${ASSET}"
EXPECTED_SIZE="1288544"
EXPECTED_SHA256="b588e0d33bffe93be509441d39a949f4427a930245bd8b43b13dbb27cca9ecff"
DEST="app/src/main/assets/g3/${ASSET}"
TMP="${DEST}.download"

mkdir -p "$(dirname "$DEST")"
rm -f "$TMP"
curl --fail --location --retry 4 --retry-delay 2 --connect-timeout 20 "$URL" -o "$TMP"
echo "${EXPECTED_SHA256}  ${TMP}" | sha256sum --check --status
test "$(wc -c < "$TMP" | tr -d ' ')" = "$EXPECTED_SIZE"

python3 - "$TMP" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1])
b=p.read_bytes()
assert len(b)==1288544, f"unexpected size: {len(b)}"
assert b[0]==0xE9 and 1<=b[1]<=16 and b[12:14]==b"\\0\\0", "not an ESP32 raw application"
assert b[32:36]==bytes.fromhex("3254cdab"), "missing upstream G3 application marker"
assert b[288:320]==b"BRY88BBA15G".ljust(32,b"\\0"), "wrong G3 model"
assert b[320:352]==b"PHICOMM-DAIKIN-1:full".ljust(32,b"\\0"), "wrong G3 full application variant"
PY

mv "$TMP" "$DEST"
echo "Verified and staged $DEST ($EXPECTED_SIZE bytes, SHA256 $EXPECTED_SHA256)"
