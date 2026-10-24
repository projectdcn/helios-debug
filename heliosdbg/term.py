"""Interactive shells on the rack's switch / compute trays for the debug UI's terminal (Access to the rack tab).

A session is a real login shell with a pseudo-terminal, opened the way the read-only tools reach the node:
  * SSH (paramiko, the inventory user and key) - with transport.jump via: tunnel the jump host only forwards;
  * transport.jump via: exec - `ssh -tt <user>@<node>` run on the jump host, whose own ssh config / key do the last hop;
  * the node the UI runs on (local) - a shell under a local pseudo-terminal.
The page polls the output (``read``: waits up to ``wait`` s for new bytes) and posts keystrokes (``write``). What is
typed is never stored or logged; only open / close (node, time, how) is appended to ``results/term/sessions.log``.
At most MAX_SESSIONS at once; a session nobody reads for IDLE_S is closed.
"""
from __future__ import annotations

import os
import secrets
import shlex
import threading
import time
from pathlib import Path

from .transport import SshTransport, _jump_client, is_local

MAX_SESSIONS = 6
IDLE_S = 30 * 60
KEEP_BYTES = 2_000_000           # output kept per session for the page (older output is dropped)


class TermError(RuntimeError):
    pass


class Session:
    def __init__(self, node_name: str, how: str, cols: int, rows: int):
        self.id = secrets.token_hex(8)
        self.node, self.how = node_name, how
        self.cols, self.rows = cols, rows
        self.buf = bytearray()
        self.base = 0                # absolute offset of buf[0]
        self.cv = threading.Condition()
        self.closed: str | None = None
        self.opened = time.time()
        self.last = time.time()
        self._chan = None            # paramiko channel
        self._fd = None              # local pty master
        self._proc = None
        self._client = None          # our own SSH client (closed with the session)
        self._pump = None            # the reader thread (local shells: joined before the pty is closed)

    # -- output --------------------------------------------------------------------------------------------------
    def _append(self, data: bytes) -> None:
        with self.cv:
            self.buf += data
            if len(self.buf) > KEEP_BYTES:
                cut = len(self.buf) - KEEP_BYTES
                del self.buf[:cut]
                self.base += cut
            self.cv.notify_all()

    def _ended(self, why: str) -> None:
        with self.cv:
            if self.closed is None:
                self.closed = why
            self.cv.notify_all()

    def read(self, since: int, wait: float = 15.0) -> dict:
        self.last = time.time()
        end = time.monotonic() + wait
        with self.cv:
            while self.base + len(self.buf) <= since and self.closed is None:
                left = end - time.monotonic()
                if left <= 0:
                    break
                self.cv.wait(left)
            start = max(since, self.base)
            data = bytes(self.buf[start - self.base:])
            return {"data": data, "next": self.base + len(self.buf), "closed": self.closed,
                    "dropped": since < self.base}

    # -- input -----------------------------------------------------------------------------------------------------
    def write(self, data: bytes) -> None:
        if self.closed:
            raise TermError(f"session closed: {self.closed}")
        self.last = time.time()
        if self._chan is not None:
            self._chan.sendall(data)
        elif self._fd is not None:
            os.write(self._fd, data)

    def resize(self, cols: int, rows: int) -> None:
        self.cols, self.rows = cols, rows
        if self._chan is not None:
            self._chan.resize_pty(width=cols, height=rows)
        elif self._fd is not None:
            import fcntl
            import struct
            import termios
            fcntl.ioctl(self._fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))

    def close(self, why: str = "closed") -> None:
        self._ended(why)
        for f in (lambda: self._chan and self._chan.close(), lambda: self._client and self._client.close()):
            try:
                f()
            except Exception:  # noqa: BLE001 - closing, best effort
                pass
        if self._proc is not None:
            # local shell: end it first so the reader thread sees EOF, then close the pty (closing a pty master while
            # a thread is blocked reading it hangs on macOS)
            try:
                os.killpg(self._proc.pid, 15)
            except (OSError, ProcessLookupError):
                pass
            try:
                self._proc.wait(timeout=3)
            except Exception:  # noqa: BLE001
                try:
                    os.killpg(self._proc.pid, 9)
                except (OSError, ProcessLookupError):
                    pass
            if self._pump is not None:
                self._pump.join(timeout=3)
            if self._fd is not None:
                try:
                    os.close(self._fd)
                except OSError:
                    pass
        self._fd = None

    # -- openers -----------------------------------------------------------------------------------------------------
    def _pump_chan(self) -> None:
        try:
            while True:
                d = self._chan.recv(65536)
                if not d:
                    break
                self._append(d)
        except Exception as e:  # noqa: BLE001
            self._ended(f"connection lost: {type(e).__name__}")
            return
        self._ended("the shell ended")

    def _pump_fd(self) -> None:
        try:
            while True:
                d = os.read(self._fd, 65536)
                if not d:
                    break
                self._append(d)
        except OSError:
            pass
        self._ended("the shell ended")


def open_session(host, transport_cfg: dict, cols: int = 120, rows: int = 32, connect_timeout: float = 20) -> Session:
    """A login shell on ``host`` (an inventory Host) with a cols x rows pseudo-terminal."""
    cols, rows = max(20, min(int(cols), 500)), max(5, min(int(rows), 200))
    jump = (transport_cfg or {}).get("jump")
    if is_local(host):
        return _open_local(host, cols, rows)
    if jump and jump.get("via") == "exec":
        s = Session(host.name, "through the jump host (ssh -tt)", cols, rows)
        client = _jump_client(jump, max(connect_timeout, 60))
        chan = client.get_transport().open_session(timeout=connect_timeout)
        chan.get_pty(term="xterm-256color", width=cols, height=rows)
        target = f"{host.user}@{host.host}" if host.user else host.host
        chan.exec_command(f"ssh -tt -o ConnectTimeout={int(connect_timeout)} -p {host.port} {shlex.quote(target)}")
        s._chan = chan                      # the shared jump connection stays open for the other tools
    else:
        s = Session(host.name, "SSH" + (" through the jump host" if jump else ""), cols, rows)
        t = SshTransport(host, connect_timeout=connect_timeout, jump=jump)
        client = t._connect()               # our own connection: closed with the session
        chan = client.get_transport().open_session(timeout=connect_timeout)
        chan.get_pty(term="xterm-256color", width=cols, height=rows)
        chan.invoke_shell()
        s._chan, s._client = chan, client
    threading.Thread(target=s._pump_chan, daemon=True, name=f"term-{host.name}").start()
    return s


def _open_local(host, cols: int, rows: int) -> Session:
    import pty
    import subprocess
    s = Session(host.name, "on this machine", cols, rows)
    master, slave = pty.openpty()
    shell = os.environ.get("SHELL") or "/bin/bash"
    s._proc = subprocess.Popen([shell, "-l"], stdin=slave, stdout=slave, stderr=slave, start_new_session=True,
                               env=dict(os.environ, TERM="xterm-256color"), close_fds=True)
    os.close(slave)
    s._fd = master
    s.resize(cols, rows)
    s._pump = threading.Thread(target=s._pump_fd, daemon=True, name=f"term-{host.name}")
    s._pump.start()
    return s


class Terminals:
    """The UI's open sessions (thread-safe)."""

    def __init__(self, log_dir: Path | None = None):
        self.lock = threading.Lock()
        self.sessions: dict[str, Session] = {}
        self.log_path = (log_dir / "sessions.log") if log_dir else None
        threading.Thread(target=self._reaper, daemon=True, name="term-reaper").start()

    def _log(self, s: Session, what: str) -> None:
        if not self.log_path:
            return
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a") as fh:
                fh.write(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} {what} {s.node} ({s.how}) id={s.id}\n")
        except OSError:
            pass

    def open(self, host, transport_cfg: dict, cols: int, rows: int) -> Session:
        with self.lock:
            live = [x for x in self.sessions.values() if not x.closed]
            if len(live) >= MAX_SESSIONS:
                raise TermError(f"{MAX_SESSIONS} terminals are open already - close one first")
        try:
            s = open_session(host, transport_cfg, cols, rows)
        except Exception as e:  # noqa: BLE001 - shown in the page
            raise TermError(f"could not open a shell on {host.name}: {type(e).__name__}: {str(e)[:200]}") from None
        with self.lock:
            self.sessions[s.id] = s
        self._log(s, "open")
        return s

    def get(self, sid: str) -> Session:
        with self.lock:
            s = self.sessions.get(sid or "")
        if not s:
            raise TermError("no such terminal (closed, or the UI restarted)")
        return s

    def close(self, sid: str, why: str = "closed in the page") -> None:
        s = self.get(sid)
        s.close(why)
        self._log(s, f"close ({why})")
        with self.lock:
            self.sessions.pop(sid, None)

    def list(self) -> list[dict]:
        with self.lock:
            return [{"id": s.id, "node": s.node, "how": s.how, "opened": s.opened, "closed": s.closed}
                    for s in self.sessions.values()]

    def _reaper(self) -> None:
        while True:
            time.sleep(30)
            now = time.time()
            with self.lock:
                stale = [s for s in self.sessions.values()            # a closed one stays readable 2 min (why it ended)
                         if (s.closed and now - s.last > 120) or now - s.last > IDLE_S]
            for s in stale:
                why = s.closed or f"idle for {IDLE_S // 60} min"
                s.close(why)
                self._log(s, f"close ({why})")
                with self.lock:
                    self.sessions.pop(s.id, None)
