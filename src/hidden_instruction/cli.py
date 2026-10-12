"""Command line entry for the hidden-instruction detector."""

from __future__ import annotations

import argparse
import json
import sys

from hidden_instruction.detect import detect


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="规范化不可见文本后，检测其中藏着的指令。命中时整段不能作为工具参数。",
    )
    parser.add_argument("path", nargs="?", help="待检测文件；用 - 读取标准输入")
    parser.add_argument("--text", help="直接检测这段文本")
    args = parser.parse_args(argv)

    if args.text is not None:
        raw = args.text
    elif args.path and args.path != "-":
        with open(args.path, encoding="utf-8") as handle:
            raw = handle.read()
    else:
        raw = sys.stdin.read()

    result = detect(raw)
    json.dump(result.to_dict(), sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    return 0 if result.tool_parameter_allowed else 1


if __name__ == "__main__":
    raise SystemExit(main())
