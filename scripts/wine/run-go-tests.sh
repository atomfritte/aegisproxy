#!/bin/sh
# Builds every control-plane test package for windows/amd64 and runs it under Wine, in its package
# directory (testdata). With --cluster the PostgreSQL cluster tests run against a postgres:17 container.
#   scripts/wine/run-go-tests.sh <work-dir> [--cluster]
set -eu
REPO=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
WORK=$(mkdir -p "$1" && CDPATH='' cd -- "$1" && pwd); shift
CLUSTER=${1:-}
IMAGE=aegis-test-wine:local
docker build -q -t "$IMAGE" "$REPO/scripts/wine" >/dev/null
mkdir -p "$WORK/bin" "$WORK/out"; rm -f "$WORK/bin/"*.exe "$WORK/bin/list"
for p in $(go -C "$REPO/control-plane" list -f '{{if .TestGoFiles}}{{.ImportPath}}{{end}}' ./...); do
  rel=${p#aegisproxy/control-plane}; rel=${rel#/}; n=$(basename "$p")
  GOOS=windows GOARCH=amd64 go -C "$REPO/control-plane" test -c -o "$WORK/bin/$n.test.exe" "./$rel"
  echo "$n $rel" >> "$WORK/bin/list"
done
NET=""; DSN=""
if [ "$CLUSTER" = "--cluster" ]; then
  docker network create aegis-wine-net >/dev/null 2>&1 || true
  docker rm -f aegis-wine-pg >/dev/null 2>&1 || true
  docker run -d --name aegis-wine-pg --network aegis-wine-net -e POSTGRES_PASSWORD=winepg -e POSTGRES_DB=aegis postgres:17-alpine >/dev/null
  until docker exec aegis-wine-pg pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done
  NET="--network aegis-wine-net"; DSN="postgres://postgres:winepg@aegis-wine-pg:5432/aegis?sslmode=disable"
fi
rc=0
while read -r n rel; do
  # shellcheck disable=SC2086
  docker run --rm $NET -e AEGIS_TEST_DATABASE_URL="$DSN" -v "$WORK/bin:/bin-win:ro" -v "$REPO:/src:ro" \
    -w "/src/control-plane/$rel" "$IMAGE" wine "/bin-win/$n.test.exe" -test.count=1 -test.timeout=800s -test.v \
    > "$WORK/out/$n.log" 2>&1 || rc=1
  printf '%-12s pass=%-3s fail=%-2s skip=%s\n' "$n" "$(grep -c '^--- PASS' "$WORK/out/$n.log")" \
    "$(grep -c '^--- FAIL' "$WORK/out/$n.log")" "$(grep -c '^--- SKIP' "$WORK/out/$n.log")"
  grep -E '^--- (FAIL|SKIP)' "$WORK/out/$n.log" | sed 's/^/    /' || true
done < "$WORK/bin/list"
if [ "$CLUSTER" = "--cluster" ]; then
  docker rm -f aegis-wine-pg >/dev/null; docker network rm aegis-wine-net >/dev/null
fi
exit $rc
