#!/usr/bin/env sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 resso-v<version>.tar.gz" >&2
  exit 2
fi

archive="$1"
if [ ! -f "$archive" ]; then
  echo "archive not found: $archive" >&2
  exit 2
fi

gzip -dc "$archive" | docker load
