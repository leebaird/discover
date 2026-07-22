# Discover agent notes

Conventions agreed with the operator for Discover development. **Read and follow this file.** When we discuss and agree on a durable rule (layout, install order, Update UX, host-scan gating, etc.), **add or update it here** in the same change set when practical—do not leave it only in chat history.

## Report UI layout (CSS)

When designing or tweaking **report page layouts** (especially Audit and other `modern.css` tables/containers):

- Prefer **`px`** for widths, min/max-widths, padding, and gaps you are dialing in with the operator.
- **Do not use `rem` for layout sizing.** Bootstrap sets `html { font-size: 10px }`, so `1rem = 10px` (not 16px). That made earlier “rem” floors look far too narrow.
- `%` / `width: 1%` + `nowrap` is fine for shrink-to-content columns; once a column needs a **fixed** size, use **px**.
- Bust `modern.css?v=…` on the affected page after CSS changes and deploy to the live engagement report when applicable.

## `misc/update.sh` tool install order

Tool install/update blocks in **`misc/update.sh` must stay in case-insensitive alphabetical order** by tool/display name (e.g. DomainPasswordSpray → droopescan → Egress-Assess → … → WhatWeb → Windows Exploit Suggester → **wpscan** → xdotool).

- Do **not** group by feature (e.g. “CMS tools together”). Place new tools where the alphabet says, not next to a related tool.
- Comments already mark some blocks this way (e.g. CISA KEV after chromium, before curl); follow that convention.
- Same idea for README Update bullet lists when they mirror install order.
