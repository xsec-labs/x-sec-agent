#!/usr/bin/env python3
"""从 config/vulnerability-skills.yaml 生成给模型读的路由索引 references/routing-index.md。

    python3 scripts/build_routing_index.py          重新生成索引
    python3 scripts/build_routing_index.py --check  只检查，索引与 yaml 不一致时退出码为 1

yaml 是唯一来源，索引是它的投影：一行一个 Skill，写“信号 → Skill id”。只收 enabled 且已注册的条目
（status 为 not_installed 或 enabled=false 的只能进建议状态，不该出现在派发用的索引里）。
依赖 PyYAML（只在维护这个仓库时需要，运行 Skill 本身不需要）。
"""
from __future__ import annotations

import argparse
import posixpath
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
REGISTRY_REL = "config/vulnerability-skills.yaml"
INDEX_REL = "references/routing-index.md"

HEADER = """# 漏洞 Skill 路由索引

由 `python3 scripts/build_routing_index.py` 从 `config/vulnerability-skills.yaml` 生成，不要手改。
一行一个 Skill，观察到任一信号即可考虑派发；多个同时命中按本表顺序（`priority` 从高到低）。
信号只是候选条件，派发前还要看该条目的 `requires_environment`、`requires_artifacts`、`blocked_when`。
格式：`信号 / 信号 → Skill id [阶段] 目录名`；路径是 `skills/<目录名>`，目录名与 id 或 `xsec-<id>` 相同时省略。

"""

POST_HEADER = """
收尾处理器（不在启动阶段默认运行）：
"""


def _by_priority(entries: list[dict]) -> list[dict]:
    # 稳定排序：yaml 里条目的书写顺序不影响结果。
    return sorted(entries or [], key=lambda e: -int(e.get("priority") or 0))


def _line(entry: dict) -> str | None:
    if not entry.get("enabled") or entry.get("status") == "not_installed":
        return None
    eid, path = entry.get("id") or "", entry.get("path") or ""
    if not eid or not path:
        raise ValueError(f"条目缺 id 或 path：{entry!r}")
    activation = entry.get("activation") or {}
    signals = activation.get("any_signals") or []
    if not signals:
        raise ValueError(f"{eid} 没有 activation.any_signals，生成不出索引行")
    if posixpath.dirname(path) != "skills":
        raise ValueError(f"{eid} 的 path {path!r} 不在 skills/ 下")
    directory = posixpath.basename(path)
    line = "- " + " / ".join(signals) + " → " + eid
    if activation.get("phase"):
        line += " [" + activation["phase"] + "]"
    if directory not in (eid, "xsec-" + eid):
        line += " " + directory
    return line + "\n"


def render(registry_yaml: str) -> str:
    reg = yaml.safe_load(registry_yaml) or {}
    out = [HEADER]
    count = 0
    for entry in _by_priority(reg.get("vulnerability_skills")):
        line = _line(entry)
        if line:
            out.append(line)
            count += 1
    if count == 0:
        raise ValueError(f"{REGISTRY_REL} 里没有可用的 vulnerability_skills 条目")
    post = [ln for ln in map(_line, _by_priority(reg.get("post_processors"))) if ln]
    if post:
        out.append(POST_HEADER)
        out.extend(post)
    return "".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--skill", type=Path, default=ROOT, help="Skill 目录（默认本仓库根）")
    parser.add_argument("--check", action="store_true", help="只检查索引是否与 yaml 一致")
    args = parser.parse_args(argv)
    want = render((args.skill / REGISTRY_REL).read_text(encoding="utf-8"))
    target = args.skill / INDEX_REL
    if args.check:
        if not target.exists() or target.read_text(encoding="utf-8") != want:
            print(f"{INDEX_REL} 与 {REGISTRY_REL} 不一致，运行 python3 scripts/build_routing_index.py 重新生成", file=sys.stderr)
            return 1
        return 0
    target.write_bytes(want.encode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
