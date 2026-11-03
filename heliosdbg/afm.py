"""Minimal read-only AFM REST client (standard library only) for the link check's AFM view.

Login: ``POST /v1/login`` {"username", "password", "tenant"} -> ``sid`` session cookie (+ ``Grpc-Metadata-Csrf-Token``
header, sent back). Only GETs follow. The password comes from the environment variable the inventory names
(``afm.auth.password_env``, default HELIOS_AFM_PASSWORD) and is never logged, printed or written anywhere.

Inventory (same block as helios-tests):
    afm:
      url: https://10.0.80.52
      verify_tls: false          # self-signed controller certificate
      auth: {username: admin, password_env: HELIOS_AFM_PASSWORD, tenant: default}
"""
from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request
from http.cookiejar import CookieJar

CLUSTER = "/configs/cluster/v1"


class AfmUnavailable(Exception):
    """The AFM view cannot be read (no url / password, login refused, unreachable) - the scan goes on without it."""


class Afm:
    def __init__(self, cfg: dict, timeout: float = 30):
        cfg = cfg or {}
        self.base = str(cfg.get("url") or "").rstrip("/")
        if not self.base:
            raise AfmUnavailable("no afm.url in the inventory")
        auth = cfg.get("auth") or {}
        self.env = auth.get("password_env") or "HELIOS_AFM_PASSWORD"
        # 'password' is given in memory by the UI for one run (never from a file: the inventory refuses one); else env
        self._password = auth.get("password") or os.environ.get(self.env)
        if not self._password:
            raise AfmUnavailable(f"AFM password not set: export {self.env} in this shell to add the AFM view")
        self.username = str(auth.get("username") or "admin")
        self.tenant = str(auth.get("tenant") or "default")
        self.timeout = timeout
        ctx = ssl.create_default_context()
        if cfg.get("verify_tls", False) is False:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self.jar = CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx),
                                              urllib.request.HTTPCookieProcessor(self.jar))
        self.headers = {"Content-Type": "application/json", "Accept": "application/json"}
        self._login()

    def _req(self, method: str, path: str, body: dict | None = None):
        data = json.dumps(body).encode() if body is not None else None
        r = urllib.request.Request(self.base + path, data=data, method=method, headers=self.headers)
        return self.op.open(r, timeout=self.timeout)

    def _login(self) -> None:
        try:
            r = self._req("POST", "/v1/login", {"username": self.username, "password": self._password,
                                                "tenant": self.tenant})
        except urllib.error.HTTPError as e:
            raise AfmUnavailable(f"AFM login refused (HTTP {e.code}) - check {self.env}") from None
        except Exception as e:  # noqa: BLE001 - unreachable / TLS
            raise AfmUnavailable(f"AFM not reachable at {self.base}: {type(e).__name__}: {str(e)[:120]}") from None
        finally:
            self._password = None          # not kept after the login
        csrf = r.headers.get("Grpc-Metadata-Csrf-Token")
        if csrf:
            self.headers["Grpc-Metadata-Csrf-Token"] = csrf

    def get(self, path: str) -> dict:
        with self._req("GET", path) as r:
            return json.loads(r.read() or b"{}")

    def computes(self) -> list[dict]:
        return self.get(f"{CLUSTER}/computenodes").get("items") or []
