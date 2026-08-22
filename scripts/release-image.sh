#!/usr/bin/env sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 v<version>" >&2
  exit 2
fi

release_version="$1"
is_release_version() {
  numeric_version="${1#v}"
  [ "$numeric_version" != "$1" ] || return 1
  case "$numeric_version" in
    *[!0-9.]*|.*|*.|*..*) return 1 ;;
  esac
  previous_ifs="$IFS"
  IFS=.
  set -- $numeric_version
  IFS="$previous_ifs"
  [ "$#" -eq 3 ] && [ -n "$1" ] && [ -n "$2" ] && [ -n "$3" ]
}
if ! is_release_version "$release_version"; then
  echo "version must look like vX.Y.Z" >&2
  exit 2
fi

# The commit is baked into the binary and reported by /api/v1/meta, so it is
# how anyone holding the archive finds the source it was built from. Building
# from a modified tree would stamp a commit that does not describe the
# contents — a quiet lie in an artifact people verify by checksum and trust.
# Releases proper are built by CI from a clean checkout; this guard is for the
# same command run by hand, which the README documents.
if ! git diff --quiet HEAD 2>/dev/null || [ -n "$(git status --porcelain 2>/dev/null)" ]; then
  echo "refusing to build a release from a modified working tree" >&2
  echo "commit or stash your changes so the recorded commit describes the image" >&2
  exit 2
fi

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
