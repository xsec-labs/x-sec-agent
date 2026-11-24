"""路由索引生成器的测试：python3 -m unittest discover -s scripts -p 'test_*.py'"""
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_routing_index as gen  # noqa: E402
import yaml  # noqa: E402

ROOT = gen.ROOT


class RoutingIndexTest(unittest.TestCase):
    def test_committed_index_is_current(self):
        want = gen.render((ROOT / gen.REGISTRY_REL).read_text(encoding="utf-8"))
        got = (ROOT / gen.INDEX_REL).read_text(encoding="utf-8")
        self.assertEqual(got, want, "routing-index.md 与 yaml 不一致：运行 python3 scripts/build_routing_index.py")

    def test_index_covers_every_enabled_skill_and_points_at_real_dirs(self):
        reg = yaml.safe_load((ROOT / gen.REGISTRY_REL).read_text(encoding="utf-8"))
        index = (ROOT / gen.INDEX_REL).read_text(encoding="utf-8")
        for entry in reg["vulnerability_skills"] + (reg.get("post_processors") or []):
            if not entry.get("enabled") or entry.get("status") == "not_installed":
                continue
            lines = [ln for ln in index.splitlines() if " → " in ln]
            ids = {ln.split(" → ", 1)[1].split(" ", 1)[0] for ln in lines}
            self.assertIn(entry["id"], ids, entry["id"])
            self.assertTrue((ROOT / entry["path"]).is_dir(), f'{entry["id"]} 的目录 {entry["path"]} 不存在')

    def test_render_skips_unavailable_entries(self):
        src = """
vulnerability_skills:
  - {id: a, path: skills/a, status: registered, enabled: true, priority: 1, activation: {phase: p, any_signals: [s1, s2]}}
  - {id: b, path: skills/b, status: not_installed, enabled: true, priority: 1, activation: {any_signals: [s3]}}
  - {id: c, path: skills/c, status: registered, enabled: false, priority: 1, activation: {any_signals: [s4]}}
"""
        out = gen.render(src)
        self.assertIn("- s1 / s2 → a [p]\n", out)
        self.assertNotIn("→ b", out)
        self.assertNotIn("→ c", out)

    def test_render_rejects_broken_entries(self):
        for bad in (
            "vulnerability_skills:\n  - {id: a, path: skills/a, enabled: true, activation: {any_signals: []}}\n",
            "vulnerability_skills:\n  - {id: a, path: other/a, enabled: true, activation: {any_signals: [s]}}\n",
            "vulnerability_skills:\n  - {id: '', path: skills/a, enabled: true, activation: {any_signals: [s]}}\n",
            "vulnerability_skills: []\n",
        ):
            with self.assertRaises(ValueError, msg=bad):
                gen.render(bad)

    def test_render_orders_by_priority_not_by_writing_order(self):
        src = """
vulnerability_skills:
  - {id: low, path: skills/low, enabled: true, priority: 1, activation: {any_signals: [x]}}
  - {id: high, path: skills/high, enabled: true, priority: 9, activation: {any_signals: [y]}}
"""
        out = gen.render(src)
        self.assertLess(out.index("→ high"), out.index("→ low"))

    def test_directory_name_shown_only_when_it_differs(self):
        src = """
vulnerability_skills:
  - {id: a, path: skills/xsec-a, enabled: true, activation: {any_signals: [s]}}
  - {id: b, path: skills/other, enabled: true, activation: {any_signals: [t]}}
"""
        out = gen.render(src)
        self.assertIn("- s → a\n", out)
        self.assertIn("- t → b other\n", out)


class DocLinksTest(unittest.TestCase):
    """SKILL.md / AGENT.md / README.md 里指向 references/、config/、scripts/ 的链接都要解析到真实文件。"""

    PATTERN = re.compile(r"(?:\]\(|`)((?:references|config|scripts)/[A-Za-z0-9_./-]+?\.[A-Za-z0-9]+)(?:\)|`)")

    def test_doc_links_resolve(self):
        missing = []
        for doc in ("SKILL.md", "AGENT.md", "README.md"):
            text = (ROOT / doc).read_text(encoding="utf-8")
            for target in sorted(set(self.PATTERN.findall(text))):
                if not (ROOT / target).is_file():
                    missing.append(f"{doc} -> {target}")
        self.assertEqual(missing, [], "文档里的链接指向不存在的文件")


if __name__ == "__main__":
    unittest.main()
