from __future__ import annotations

import hashlib
import sys
from pathlib import Path


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: checksums.py <file> [<file> ...]", file=sys.stderr)
        return 2
    for item in argv[1:]:
        path = Path(item)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        print(f"{digest}  {path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
