#
# Copyright © 2026 Kirby Kuehl
#
# Licence: wxWindows Library Licence, Version 3.1
#
"""scripts/update-bindings.sh's fetching and caching, with a stand-in for curl."""
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "update-bindings.sh"
VERSION = "1.2.3"

# Logs each URL it is asked for, fails for one containing $FAKE_CURL_FAIL, and
# otherwise writes a devkit holding a frida-core.gir, or a GIR naming the URL.
FAKE_CURL = r'''import io, os, sys, tarfile
args = sys.argv[1:]
out = args[args.index("-o") + 1]
url = args[-1]
with open(os.environ["FAKE_CURL_LOG"], "a") as log:
    log.write(url + "\n")
fail = os.environ.get("FAKE_CURL_FAIL")
if fail and fail in url:
    with open(out, "w") as f:
        f.write("partial")
    sys.exit(22)
if url.endswith(".tar.xz"):
    data = ("<gir of %s/>" % url.rsplit("/", 1)[-1]).encode()
    with tarfile.open(out, "w:xz") as tar:
        info = tarfile.TarInfo("./frida-core.gir")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
else:
    with open(out, "w") as f:
        f.write("<gir from %s/>" % url)
'''


def _has_bash_and_tar() -> bool:
    return shutil.which("bash") is not None and shutil.which("tar") is not None


@unittest.skipUnless(_has_bash_and_tar(), "needs bash and tar")
class UpdateBindingsFetchTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        root = self.tmp / "repo"
        (root / "scripts").mkdir(parents=True)
        shutil.copy(SCRIPT, root / "scripts" / "update-bindings.sh")
        (root / "FRIDA_VERSION").write_text(VERSION + "\n")
        self.script = root / "scripts" / "update-bindings.sh"
        # The script is told which curl to run, rather than finding this one on PATH: Git
        # Bash puts its own directories, and so its own curl, before anything in PATH. And
        # it is a shell script that runs Python, as a `#!` line cannot hold a path with a
        # space in it. Forward slashes, as the shell reads a backslash as an escape.
        fake = self.tmp / "fake_curl.py"
        fake.write_text(FAKE_CURL)
        curl = self.tmp / "curl"
        with curl.open("w", newline="\n") as f:
            f.write(f'#!/bin/sh\nexec "{Path(sys.executable).as_posix()}" -I "{fake.as_posix()}" "$@"\n')
        curl.chmod(0o755)
        self.cache = self.tmp / "cache"
        self.log = self.tmp / "curl.log"
        self.env = dict(
            os.environ,
            CURL=curl.as_posix(),
            FRIDA_DEVKIT_CACHE=str(self.cache),
            FAKE_CURL_LOG=str(self.log),
        )

    def fetch(self, fail=None):
        env = dict(self.env)
        if fail is not None:
            env["FAKE_CURL_FAIL"] = fail
        result = subprocess.run(
            ["bash", str(self.script), "--fetch-only"], env=env, capture_output=True, text=True
        )
        urls = self.log.read_text().split() if self.log.exists() else []
        if self.log.exists():
            self.log.unlink()
        return result, urls

    def test_fetches_each_input_once_into_the_cache(self):
        result, urls = self.fetch()
        self.assertEqual(result.returncode, 0, result.stderr)
        releases = f"https://github.com/frida/frida/releases/download/{VERSION}"
        api = f"https://raw.githubusercontent.com/frida/frida-core/{VERSION}/src/api"
        self.assertEqual(urls, [
            f"{releases}/frida-core-devkit-{VERSION}-linux-x86_64.tar.xz",
            f"{releases}/frida-core-devkit-{VERSION}-windows-x86_64.tar.xz",
            f"{api}/GLib-2.0.gir",
            f"{api}/GObject-2.0.gir",
            f"{api}/Gio-2.0.gir",
        ])
        paths = result.stdout.split()
        self.assertEqual([Path(p).name for p in paths], [
            f"frida-core-{VERSION}-linux-x86_64.gir",
            f"frida-core-{VERSION}-windows-x86_64.gir",
            f"frida-core-{VERSION}-GLib-2.0.gir",
            f"frida-core-{VERSION}-GObject-2.0.gir",
            f"frida-core-{VERSION}-Gio-2.0.gir",
        ])
        self.assertTrue(all(Path(p).parent == self.cache for p in paths))
        self.assertEqual(Path(paths[1]).read_text(), f"<gir of frida-core-devkit-{VERSION}-windows-x86_64.tar.xz/>")
        self.assertEqual(Path(paths[3]).read_text(), f"<gir from {api}/GObject-2.0.gir/>")

        again, urls = self.fetch()
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertEqual(urls, [])
        self.assertEqual(again.stdout, result.stdout)

    def test_a_devkit_frida_build_cached_is_not_downloaded_again(self):
        self.cache.mkdir()
        devkit = self.cache / f"frida-core-devkit-{VERSION}-linux-x86_64.tar.xz"
        data = b"<cached/>"
        with tarfile.open(devkit, "w:xz") as tar:
            info = tarfile.TarInfo("frida-core.gir")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        result, urls = self.fetch()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(f"frida-core-devkit-{VERSION}-linux-x86_64.tar.xz", " ".join(urls))
        self.assertEqual(Path(result.stdout.split()[0]).read_bytes(), data)

    def test_a_failed_download_leaves_nothing_behind(self):
        result, _ = self.fetch(fail="Gio-2.0.gir")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("could not fetch", result.stderr)
        cached = sorted(p.name for p in self.cache.iterdir())
        self.assertNotIn(f"frida-core-{VERSION}-Gio-2.0.gir", cached)
        self.assertFalse([name for name in cached if name.endswith(".part")])
        self.assertIn(f"frida-core-{VERSION}-GLib-2.0.gir", cached)

        retry, urls = self.fetch()
        self.assertEqual(retry.returncode, 0, retry.stderr)
        self.assertEqual([u.rsplit("/", 1)[-1] for u in urls], ["Gio-2.0.gir"])

    def test_an_unknown_option_is_refused(self):
        result = subprocess.run(["bash", str(self.script), "--frobnicate"], env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("usage:", result.stderr)


if __name__ == "__main__":
    unittest.main()
