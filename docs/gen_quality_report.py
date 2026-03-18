# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Generate the quality report page for MkDocs."""

from pathlib import Path

import mkdocs_gen_files
from mkdocs_terok.quality_report import QualityReportConfig, generate_quality_report

ROOT = Path(__file__).parent.parent
config = QualityReportConfig(
    root=ROOT,
    src_dir=ROOT / "src" / "terok_dbus",
    codecov_repo="terok-ai/terok-dbus",
    codecov_treemap_path=ROOT / "docs" / "assets" / "coverage_treemap.svg",
    file_level_loc=True,
)
result = generate_quality_report(config)
with mkdocs_gen_files.open("quality_report.md", "w") as f:
    f.write(result.markdown)
for path, content in result.companion_files.items():
    with mkdocs_gen_files.open(f"quality_report/{path}", "w") as f:
        f.write(content)
