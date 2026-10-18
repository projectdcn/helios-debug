"""Rack: the switch / compute tray drivers built from an inventory (SSH only, no AFM client)."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Iterable, TypeVar

from .compute import ComputeTray
from .inventory import Inventory
from .sonic import DEFAULT_FABRIC_PORT_RE, SonicSwitch
from .transport import make_transport

T = TypeVar("T")
R = TypeVar("R")


class Rack:
    def __init__(self, inv: Inventory):
        self.inv = inv
        fabric_re = inv.th("switch.fabric_port_re") or DEFAULT_FABRIC_PORT_RE
        excl = inv.th("switch.exclude_ports") or []
        self.switches = {
            h.name: SonicSwitch(h, make_transport(h, inv.transport), fabric_port_re=fabric_re, exclude_ports=excl)
            for h in inv.switches
        }
        self.computes = {h.name: ComputeTray(h, make_transport(h, inv.transport)) for h in inv.computes}

    def close(self) -> None:
        for node in [*self.switches.values(), *self.computes.values()]:
            node.close()


def fan_out(fn: Callable[[T], R], items: Iterable[T], workers: int | None = None
            ) -> list[tuple[T, R | None, BaseException | None]]:
    """Run ``fn`` over items in parallel; returns (item, result, exception) in input order."""
    items = list(items)
    if not items:
        return []
    with ThreadPoolExecutor(max_workers=workers or min(32, len(items))) as ex:
        futs = [ex.submit(fn, it) for it in items]
        out = []
        for it, f in zip(items, futs):
            try:
                out.append((it, f.result(), None))
            except Exception as e:  # noqa: BLE001 - reported per item by the caller
                out.append((it, None, e))
        return out
