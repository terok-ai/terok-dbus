# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Copy shared brand CSS into the docs build."""

import mkdocs_gen_files
from mkdocs_terok import brand_css_path

with mkdocs_gen_files.open("stylesheets/extra.css", "w") as f:
    f.write(brand_css_path().read_text())
