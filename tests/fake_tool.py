"""Stand-in for any manifest tool in tests: copies $FAKE_TOOL_FIXTURE to the output file named
in its argv (a ``raw/...`` path, also inside ``--opt=raw/...``), prints a line, and exits with
$FAKE_TOOL_EXIT (default 0). $FAKE_TOOL_STDOUT (a file) is printed too, e.g. a config file the
"tool" dumped."""

import os
import re
import shutil
import sys
from pathlib import Path

_OUT = re.compile(r"(?:^|=)(raw/\S+\.(?:json|txt))$")


def main() -> int:
    fixture = os.environ.get("FAKE_TOOL_FIXTURE")
    for arg in sys.argv[1:]:
        match = _OUT.search(arg)
        if match and fixture:
            target = Path(match.group(1))
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(fixture, target)
            break
    print("fake tool ran", flush=True)
    stdout = os.environ.get("FAKE_TOOL_STDOUT")
    if stdout:
        print(Path(stdout).read_text(encoding="utf-8"), flush=True)
    return int(os.environ.get("FAKE_TOOL_EXIT", "0"))


if __name__ == "__main__":
    sys.exit(main())
