#!/usr/bin/env bash
set -euo pipefail

MNT="${1:-./mnt}"
ROOT="${2:-./tests}"

mkdir -p "$MNT"
echo "[*] mounting: $MNT  (root: $ROOT)"
./build/gentfs -f -d -o default_permissions -o attr_timeout=1,entry_timeout=1,negative_timeout=1 "$MNT" --root "$ROOT" &
FS_PID=$!

cleanup() {
  echo "[*] unmounting..."
  fusermount3 -u "$MNT" || true
  kill -- $FS_PID 2>/dev/null || true
}
trap cleanup EXIT

trap 'echo "[!] failed at line $LINENO"; exit 1' ERR

# Wait for mount to appear
mounted=0
for i in {1..30}; do
  if findmnt -T "$MNT" >/dev/null 2>&1; then 
    mounted=1
    break 
  fi
  sleep 0.1
done

if [[ "${mounted:-0}" -ne 1 ]]; then
  echo "[!] failed to mount at $MNT" >&2
  exit 1
fi

echo "[*] basic RW"
printf 'test\n' > "$MNT/hello.txt"
#printf 'more\n' >> "$MNT/hello.txt"
#printf 'test\nmore\n' | cmp -s - "$MNT/hello.txt"

#echo "[*] truncate"
#truncate -s 4 "$MNT/hello.txt"
#printf 'test' | cmp -s - "$MNT/hello.txt"

echo "[*] rename/unlink"
mv "$MNT/hello.txt" "$MNT/hello2.txt"
rm "$MNT/hello2.txt"
! test -e "$MNT/hello2.txt"

echo "[*] mkdir/rmdir"
mkdir "$MNT/dir1"
echo x > "$MNT/dir1/a"
rm "$MNT/dir1/a"
rmdir "$MNT/dir1"

echo "[*] symlink + readlink"
echo "payload" > "$ROOT/targetfile"
ln -s targetfile "$MNT/link"
[[ "$(readlink "$MNT/link")" == "targetfile" ]]
if cat "$MNT/link" >/dev/null 2>&1; then
  echo "[!] cat on symlink unexpectedly succeeded" >&2
  exit 1
fi
printf 'payload\n' | cmp -s - "$MNT/targetfile"

echo "[*] xattrs probe (may print ENODATA, OK)"
getfattr -n user.test "$MNT/link" 2>/dev/null || true

echo "[*] large offset read (if big file exists)"
BF=$(find "$MNT" -maxdepth 1 -type f -size +3G | head -n 1 || true)
if [[ -n "${BF}" ]]; then
  dd if="$BF" bs=4K skip=$(( (2<<30)/4096 + 1 )) count=1 status=none | wc -c
fi

echo "[*] PASS"
