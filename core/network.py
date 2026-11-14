"""SYSTEMA Processes — сетевые соединения процесса, по требованию.

Системный `net_connections()` для всех процессов на каждый тик — дорогая и
не нужная операция. Соединения запрашиваются только для процесса, открытого
в панели деталей, и только когда пользователь смотрит вкладку «Сеть».
"""

from __future__ import annotations

from typing import List

import psutil

from .models import NetConnection

_PROTO = {1: "TCP", 2: "UDP"}   # psutil.SOCK_STREAM=1 / SOCK_DGRAM=2


def connections_for(pid: int) -> List[NetConnection]:
    try:
        p = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return []

    conns = None
    for attr in ("net_connections", "connections"):   # psutil переименовал метод в 6.0
        fn = getattr(p, attr, None)
        if fn is None:
            continue
        try:
            conns = fn(kind="inet")
            break
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            return []
        except TypeError:
            continue
    if conns is None:
        return []

    out: List[NetConnection] = []
    for c in conns:
        laddr = c.laddr.ip if c.laddr else ""
        lport = c.laddr.port if c.laddr else 0
        raddr = c.raddr.ip if c.raddr else ""
        rport = c.raddr.port if c.raddr else 0
        proto = _PROTO.get(int(c.type), str(c.type))
        out.append(NetConnection(proto, laddr, lport, raddr, rport, c.status))
    return out
