"""Stand-in for nmap in tests: writes a fixture XML to the -oA prefix and prints progress.

Fixture choice: ``-p-`` -> allports.xml, ``-sU`` -> udp.xml, otherwise services.xml, all read
from $FAKE_NMAP_FIXTURES. Exit code from $FAKE_NMAP_EXIT (default 0).
"""

import os
import shutil
import sys
from pathlib import Path


def main() -> int:
    args = sys.argv[1:]
    fixtures = Path(os.environ["FAKE_NMAP_FIXTURES"])
    if "-p-" in args:
        name = "allports.xml"
    elif "-sU" in args:
        name = "udp.xml"
    else:
        name = "services.xml"
    prefix = Path(args[args.index("-oA") + 1])
    print("Starting Nmap 7.95 ( https://nmap.org )", flush=True)
    print("Connect Scan Timing: About 50.00% done; ETC: 10:00 (0:00:05 remaining)", flush=True)
    print("Discovered open port 22/tcp on 10.129.231.15", flush=True)
    print("warning: fake nmap", file=sys.stderr, flush=True)
    source = fixtures / name
    if source.exists():
        shutil.copy(source, prefix.with_name(prefix.name + ".xml"))
    return int(os.environ.get("FAKE_NMAP_EXIT", "0"))


if __name__ == "__main__":
    sys.exit(main())
