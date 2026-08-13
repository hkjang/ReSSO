#!/usr/bin/env sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 v<version>" >&2
  exit 2
fi

release_version="$1"
case "$release_version" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) echo "version must look like v0.1.0" >&2; exit 2 ;;
esac

commit="$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
build_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
archive="resso-${release_version}.tar.gz"

docker build --platform linux/amd64 \
  --build-arg "VERSION=${release_version}" \
  --build-arg "COMMIT=${commit}" \
  --build-arg "BUILD_TIME=${build_time}" \
  --tag "resso:${release_version}" .

docker image inspect "resso:${release_version}" >/dev/null
docker save "resso:${release_version}" | gzip -9 -n > "$archive"
echo "created ${archive} from resso:${release_version}"
