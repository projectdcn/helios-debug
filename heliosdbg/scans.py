"""Which saved check of a rack to use: the newest one that read links (and, for the whole-rack views, the newest of the
whole rack). A check that read nothing - every switch off the network, g02-g17 3 Nov - or one of three trays is no
picture of the rack: as 'the latest' it blanked the map, emptied the cabling export and the GPU picker."""
from __future__ import annotations

import json
from pathlib import Path


def partial(d: dict) -> bool:
    sc = d.get("scope") or {}
    return bool(sc.get("switches") or sc.get("trays"))


def newest(rack_dir: Path, full: bool = False, need: str | None = None,
           links: bool = True) -> tuple[dict, Path] | tuple[None, None]:
    """(link_check.json as a dict, its folder) of the newest check with links (any check with links=False) - and of
    the whole rack when full; need: a file that folder must have (raw/trays.json.gz)."""
    for f in sorted(Path(rack_dir).glob("scan-*/link_check.json"), reverse=True)[:100]:
        if need and not (f.parent / need).is_file():
            continue
        try:
            d = json.loads(f.read_text())
        except (OSError, ValueError):
            continue
        if (d.get("links") or not links) and not (full and partial(d)):
            return d, f.parent
    return None, None
