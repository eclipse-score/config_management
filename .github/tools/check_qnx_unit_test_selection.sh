#!/usr/bin/env bash
# *******************************************************************************
# Copyright (c) 2026 Contributors to the Eclipse Foundation
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
# *******************************************************************************

# QNX unit test selection check.
#
# build_qnx.yml runs every cc_test tagged `unit` (cc_unit_test / cc_gtest_unit_test add the tag) on QNX,
# minus the exclusions (-//...) listed in its bazel-test-target. This script keeps that selection reliable:
#   1. every cc_test in scope must carry the `unit` tag, otherwise it would silently never run on QNX,
#   2. every exclusion must still resolve to a `unit` test, otherwise it is stale and must be removed.
set -euo pipefail
cd "$(dirname "$0")/../.."

WORKFLOW=.github/workflows/build_qnx.yml
SCOPE='(//score/config_management/... + //tests/cpp/...) except //score/config_management/dependability/...'

status=0

untagged=$(bazel query "kind(cc_test, $SCOPE) except attr(tags, '\\bunit\\b', kind(cc_test, $SCOPE))" \
  --output=label | sort -u)
if [ -n "$untagged" ]; then
  echo "ERROR: cc_test targets without the 'unit' tag (they would never run on QNX):"
  echo "$untagged" | sed 's/^/  /'
  echo "Declare them with cc_unit_test / cc_gtest_unit_test or add tags = [\"unit\"]."
  status=1
fi

# Exclusions are the negative single-test patterns of the workflow (package wildcards are scope, not exclusions).
exclusions=$( (grep -oE -- '-//[^[:space:]]+:[^[:space:]]+' "$WORKFLOW" || true) | sed 's/^-//' | sort -u)
stale=""
for target in $exclusions; do
  found=$(bazel query "attr(tags, '\\bunit\\b', kind(cc_test, $target))" --output=label 2>/dev/null || true)
  [ -n "$found" ] || stale="$stale$target"$'\n'
done
if [ -n "$stale" ]; then
  echo "ERROR: exclusions in $WORKFLOW which are not (or no longer) 'unit' cc_tests - remove them:"
  printf '%s' "$stale" | sed 's/^/  /'
  status=1
fi

selected=$(bazel query "attr(tags, '\\bunit\\b', tests($SCOPE))" --output=label | sort -u | wc -l)
excluded=$(printf '%s\n' "$exclusions" | grep -c . || true)
echo "QNX unit tests: $((selected - excluded)) selected, $excluded excluded ($selected unit tests in total)."
[ "$status" -eq 0 ] && echo "QNX unit test selection is consistent."
exit "$status"
