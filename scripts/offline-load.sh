#!/usr/bin/env sh
set -eu

usage() {
  echo "usage: $0 resso-v<version>.tar.gz [release-sha256.txt]" >&2
  echo >&2
  echo "Verifies the archive against the checksum the release publishes, then" >&2
  echo "loads the image. Without a checksum file the load is refused, because" >&2
  echo "an archive that travelled to an offline network on removable media is" >&2
  echo "exactly the one worth checking. Pass --no-verify to load anyway." >&2
  exit 2
}

verify=yes
archive=""
checksum=""
for argument in "$@"; do
  case "$argument" in
    --no-verify) verify=no ;;
    -h|--help) usage ;;
    -*) echo "unknown option: $argument" >&2; usage ;;
    *)
      if [ -z "$archive" ]; then archive="$argument"
      elif [ -z "$checksum" ]; then checksum="$argument"
      else usage
      fi
      ;;
  esac
done
[ -n "$archive" ] || usage

if [ ! -f "$archive" ]; then
  echo "archive not found: $archive" >&2
  exit 2
fi

# sha256sum on Linux, shasum where coreutils is not what is installed.
digest_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    echo "neither sha256sum nor shasum is available; use --no-verify to skip" >&2
    exit 2
  fi
}

if [ "$verify" = yes ]; then
  # The release publishes release-sha256.txt beside the archive, so look there
  # before asking for it.
  if [ -z "$checksum" ]; then
    for candidate in "$(dirname "$archive")/release-sha256.txt" "${archive}.sha256"; do
      if [ -f "$candidate" ]; then checksum="$candidate"; break; fi
    done
  fi
  if [ -z "$checksum" ]; then
    echo "no checksum file found next to $archive" >&2
    echo "download release-sha256.txt from the same release, or pass --no-verify" >&2
    exit 2
  fi
  # The digest is compared directly rather than through `sha256sum -c`, which
  # matches on the file name recorded in the checksum file and fails confusingly
  # when the archive was renamed on its way here.
  expected="$(awk 'NR==1 {print $1}' "$checksum" | tr -d '\r')"
  if [ -z "$expected" ]; then
    echo "no digest found in $checksum" >&2
    exit 2
  fi
  actual="$(digest_of "$archive")"
  if [ "$expected" != "$actual" ]; then
    echo "checksum mismatch for $archive" >&2
    echo "  expected $expected (from $checksum)" >&2
    echo "  actual   $actual" >&2
    exit 1
  fi
  echo "checksum verified against $checksum"
fi

# A truncated archive is already caught by docker load, which errors partway
# through ingesting. Testing the archive first turns that into one clear line
# before anything is ingested at all, and it catches the case the checksum
# cannot: a file whose digest was recomputed after it was damaged.
gzip -t "$archive"
gzip -dc "$archive" | docker load
