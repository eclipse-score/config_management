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
import io
import json
import textwrap
import unittest
import urllib.error
from unittest import mock

from quality.dependency_compatibility_checker import resolve_config

MODULE = textwrap.dedent(
    """
    module(name = "root")
    bazel_dep(name = "score_baselibs", version = "0.2.19")
    bazel_dep(name = "score_logging", version = "0.2.8", dev_dependency = True)
    bazel_dep(name = "score_communication", version = "0.5.0")
    # bazel_dep(name = "score_lifecycle", version = "9.9.9")
    bazel_dep(name = "score_lifecycle", version = "0.10.1")

    git_override(
        module_name = "score_communication",
        commit = "abc123",
        remote = "https://example.com/communication.git",
    )
    single_version_override(
        module_name = "score_lifecycle",
        version = "0.7.0",
    )
    """
)

METADATA = {
    "score_baselibs": {
        "versions": ["0.2.18", "0.2.19", "0.2.20-rc1", "0.2.21"],
        "yanked_versions": {"0.2.21": "broken"},
    },
    "score_logging": {"versions": ["0.2.8", "0.2.9", "0.10.0"]},
    "score_lifecycle": {"versions": ["0.5.0", "0.6.0"]},
    "score_communication": {"versions": ["0.6.0"]},
}


def _fetch(url):
    for name, data in METADATA.items():
        if url.endswith(f"/modules/{name}/metadata.json"):
            return data
    return None


class LatestReleaseTest(unittest.TestCase):
    def test_skips_prereleases_and_yanked_versions(self):
        self.assertEqual(
            resolve_config.latest_release("score_baselibs", ("r",), _fetch), "0.2.19"
        )

    def test_compares_numerically(self):
        self.assertEqual(
            resolve_config.latest_release("score_logging", ("r",), _fetch), "0.10.0"
        )

    def test_falls_back_to_the_next_registry(self):
        calls = []

        def fetch(url):
            calls.append(url)
            return None if url.startswith("first") else METADATA["score_logging"]

        self.assertEqual(
            resolve_config.latest_release("score_logging", ("first", "second"), fetch),
            "0.10.0",
        )
        self.assertEqual(len(calls), 2)

    def test_unknown_module_is_an_error(self):
        with self.assertRaises(ValueError):
            resolve_config.latest_release("nope", ("r",), _fetch)


class CurrentVersionTest(unittest.TestCase):
    def test_declared_version(self):
        self.assertEqual(
            resolve_config.current_version(MODULE, "score_baselibs"), "0.2.19"
        )
        self.assertEqual(
            resolve_config.current_version(MODULE, "score_logging"), "0.2.8"
        )

    def test_git_override_is_pinned(self):
        self.assertEqual(
            resolve_config.current_version(MODULE, "score_communication"), "pinned"
        )

    def test_single_version_override_wins_over_bazel_dep(self):
        self.assertEqual(
            resolve_config.current_version(MODULE, "score_lifecycle"), "0.7.0"
        )

    def test_missing_module_is_an_error(self):
        with self.assertRaises(ValueError):
            resolve_config.current_version(MODULE, "score_unknown")


class FetchJsonTest(unittest.TestCase):
    def _response(self, data):
        return io.BytesIO(json.dumps(data).encode())

    def _http_error(self, code):
        return urllib.error.HTTPError("u", code, "msg", {}, None)

    @mock.patch.object(resolve_config.time, "sleep")
    @mock.patch.object(resolve_config.urllib.request, "urlopen")
    def test_retries_transient_errors(self, urlopen, _sleep):
        urlopen.side_effect = [
            urllib.error.URLError("down"),
            self._http_error(503),
            self._response({"versions": ["1.0.0"]}),
        ]
        self.assertEqual(resolve_config._fetch_json("u"), {"versions": ["1.0.0"]})
        self.assertEqual(urlopen.call_count, 3)

    @mock.patch.object(resolve_config.time, "sleep")
    @mock.patch.object(resolve_config.urllib.request, "urlopen")
    def test_gives_up_after_the_last_attempt(self, urlopen, _sleep):
        urlopen.side_effect = urllib.error.URLError("down")
        with self.assertRaises(urllib.error.URLError):
            resolve_config._fetch_json("u")
        self.assertEqual(urlopen.call_count, 3)

    @mock.patch.object(resolve_config.urllib.request, "urlopen")
    def test_not_found_is_none_and_not_retried(self, urlopen):
        urlopen.side_effect = self._http_error(404)
        self.assertIsNone(resolve_config._fetch_json("u"))
        self.assertEqual(urlopen.call_count, 1)

    @mock.patch.object(resolve_config.urllib.request, "urlopen")
    def test_client_errors_are_not_retried(self, urlopen):
        urlopen.side_effect = self._http_error(403)
        with self.assertRaises(urllib.error.HTTPError):
            resolve_config._fetch_json("u")
        self.assertEqual(urlopen.call_count, 1)


class ResolveTest(unittest.TestCase):
    def _resolve(self, deps, bazel_version="8.8.2"):
        raw = {"dependencies": deps}
        return resolve_config.resolve(
            raw, MODULE, ("r",), _fetch, bazel_version=bazel_version
        )["dependencies"]

    def test_current_is_kept_and_latest_is_resolved(self):
        deps = self._resolve(
            {
                "score_logging": {
                    "versions": [{"version": "current"}, {"version": "latest"}]
                }
            }
        )
        self.assertEqual(
            deps["score_logging"]["versions"],
            [
                {"version": "0.2.8", "keep": True},
                {"version": "0.10.0"},
            ],
        )

    def test_latest_equal_to_current_is_dropped(self):
        deps = self._resolve(
            {
                "score_baselibs": {
                    "versions": [
                        {"version": "current"},
                        {"version": "latest"},
                        {"version": "main", "branch": "main"},
                    ]
                }
            }
        )
        self.assertEqual(
            [v["version"] for v in deps["score_baselibs"]["versions"]],
            ["0.2.19", "main"],
        )

    def test_latest_older_than_current_is_dropped(self):
        deps = self._resolve(
            {
                "score_lifecycle": {
                    "versions": [{"version": "current"}, {"version": "latest"}]
                }
            }
        )
        self.assertEqual(
            [v["version"] for v in deps["score_lifecycle"]["versions"]], ["0.7.0"]
        )

    def test_latest_is_kept_when_current_is_pinned(self):
        deps = self._resolve(
            {
                "score_communication": {
                    "versions": [{"version": "current"}, {"version": "latest"}]
                }
            }
        )
        self.assertEqual(
            [v["version"] for v in deps["score_communication"]["versions"]],
            ["pinned", "0.6.0"],
        )

    def test_bazel_plain_version_is_left_alone(self):
        deps = self._resolve({"bazel": {"versions": [{"version": "8.8.2"}]}})
        self.assertEqual(deps["bazel"]["versions"], [{"version": "8.8.2"}])

    def test_bazel_current_is_bazelversion(self):
        deps = self._resolve(
            {"bazel": {"versions": [{"version": "current"}]}}, bazel_version="8.9.0"
        )
        self.assertEqual(deps["bazel"]["versions"], [{"version": "8.9.0"}])

    def test_bazel_current_needs_bazelversion(self):
        with self.assertRaises(ValueError):
            self._resolve(
                {"bazel": {"versions": [{"version": "current"}]}},
                bazel_version=None,
            )

    def test_bazel_latest_is_not_supported(self):
        with self.assertRaises(ValueError):
            self._resolve({"bazel": {"versions": [{"version": "latest"}]}})

    def test_current_cannot_carry_patches(self):
        with self.assertRaises(ValueError):
            self._resolve(
                {
                    "score_logging": {
                        "versions": [{"version": "current", "patches": ["//p:a"]}]
                    }
                }
            )


if __name__ == "__main__":
    unittest.main()
