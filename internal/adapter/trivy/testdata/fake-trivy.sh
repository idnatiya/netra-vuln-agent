#!/bin/sh
# Fake Trivy for tests. Mode via FAKE_TRIVY_MODE: ok (default) | fail | hang.
if [ "$1" = "version" ]; then
	echo '{"Version":"0.99.0","VulnerabilityDB":{"Version":2}}'
	exit 0
fi
case "$FAKE_TRIVY_MODE" in
fail) echo "FATAL unable to initialize: boom" >&2; exit 1 ;;
hang) exec sleep 30 ;;
esac
out=""
while [ $# -gt 0 ]; do
	[ "$1" = "--output" ] && out="$2"
	shift
done
cp "$FAKE_TRIVY_FIXTURE" "$out"
