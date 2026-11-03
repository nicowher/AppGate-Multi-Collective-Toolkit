"""Controller CA pin. Production only. Lab mode does not call this.

The current CA PEM is an unauthenticated GET, so it is fetched before login.
The fingerprint confirm is the anti-MITM step. Later calls use verify=<pem>.
The next CA is staged after login so a planned rotation does not break the pin.
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import sys
import threading

import requests

from config import (
    API_TIMEOUT,
    APPGATE_API_VERSION,
    YES_ANSWERS,
)
from core.utils import REPO_ROOT

CA_PEM_PATH = "/certificate-authority/ca-pem"
CA_NEXT_PATH = "/certificate-authority/ca-next"


class CaPinError(RuntimeError):
    """Operator rejected the CA, or a stored pin did not match."""


def _store_dir() -> str:
    path = os.path.join(REPO_ROOT, "certs")
    os.makedirs(path, exist_ok=True)
    return path


def _safe_host(host: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", host)[:80] or "controller"


def _pem_path(host: str) -> str:
    return os.path.join(_store_dir(), f"{_safe_host(host)}.pem")


def _fp_path(host: str) -> str:
    return _pem_path(host) + ".fp"


def _read_fps(host: str) -> set:
    path = _fp_path(host)
    if not os.path.isfile(path):
        return set()
    with open(path, encoding="utf-8") as fh:
        return {line.strip().lower() for line in fh if line.strip()}


def _append_fp(host: str, fingerprint: str) -> None:
    fp = fingerprint.strip().lower()
    if not fp or fp in _read_fps(host):
        return
    with open(_fp_path(host), "a", encoding="utf-8") as fh:
        fh.write(fp + "\n")


def pem_from_payload(payload: dict) -> str:
    """CaConfig.certificate is PEM text or base64 DER/PEM."""
    raw = str(payload.get("certificate") or "").strip()
    if not raw:
        raise CaPinError("CA response had no certificate")
    if "BEGIN CERTIFICATE" in raw:
        return raw if raw.endswith("\n") else raw + "\n"
    try:
        blob = base64.b64decode(raw)
    except (ValueError, TypeError) as exc:
        raise CaPinError(f"CA certificate was not valid base64: {exc}") from exc
    if blob.startswith(b"-----BEGIN"):
        text = blob.decode("utf-8")
        return text if text.endswith("\n") else text + "\n"
    b64 = base64.b64encode(blob).decode("ascii")
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"


def fingerprint_of_pem(pem: str) -> str:
    """SHA-256 of the certificate DER. Do not trust the JSON fingerprint field."""
    body = pem
    if "BEGIN CERTIFICATE" in pem:
        lines = [
            line.strip()
            for line in pem.splitlines()
            if line.strip() and "BEGIN CERTIFICATE" not in line and "END CERTIFICATE" not in line
        ]
        der = base64.b64decode("".join(lines))
    else:
        der = pem.encode("utf-8")
    return hashlib.sha256(der).hexdigest()


def fingerprint_from_payload(payload: dict, pem: str) -> str:
    """Use the computed fingerprint. Reject a JSON fingerprint that does not match."""
    computed = fingerprint_of_pem(pem)
    claimed = str(payload.get("fingerprint") or "").replace(":", "").strip().lower()
    if claimed and claimed != computed:
        raise CaPinError(
            "CA JSON fingerprint does not match the certificate bytes. Refusing to pin."
        )
    return computed


def _accept_header() -> dict:
    return {"Accept": f"application/vnd.appgate.peer-v{APPGATE_API_VERSION}+json"}


def _fetch_ca(base_url: str, path: str, *, verify, headers: dict) -> requests.Response:
    return requests.get(
        f"{base_url}{path}",
        headers=headers,
        verify=verify,
        timeout=API_TIMEOUT,
    )


def _confirm(host: str, fingerprint: str) -> None:
    """Out-of-band confirm. The GET itself is not the trust anchor."""
    if threading.current_thread() is not threading.main_thread():
        raise CaPinError("CA fingerprint confirm must run on the main thread")
    print(f"      Controller CA SHA-256 for {host}:", file=sys.stderr)
    print(f"      {fingerprint}", file=sys.stderr)
    ans = input("      Trust this CA? [y/N]: ").strip().lower()
    if ans not in YES_ANSWERS:
        raise CaPinError(
            f"CA for {host} was not trusted. No credentials were sent."
        )


def _save_pem(host: str, pem: str, fingerprint: str) -> str:
    path = _pem_path(host)
    existing = ""
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as fh:
            existing = fh.read()
    if pem not in existing:
        with open(path, "a", encoding="utf-8") as fh:
            if existing and not existing.endswith("\n"):
                fh.write("\n")
            fh.write(pem)
    _append_fp(host, fingerprint)
    return path


def ensure_ca_pin(host: str, base_url: str) -> str:
    """Fetch the current CA before login. Return the PEM path for verify=."""
    stored = _read_fps(host)
    verify = _pem_path(host) if stored and os.path.isfile(_pem_path(host)) else False
    try:
        response = _fetch_ca(base_url, CA_PEM_PATH, verify=verify, headers=_accept_header())
    except requests.exceptions.SSLError as exc:
        raise CaPinError(
            f"Controller certificate for {host} did not match the pinned CA."
        ) from exc
    if response.status_code != 200:
        raise CaPinError(
            f"CA fetch for {host} failed (HTTP {response.status_code})."
        )
    try:
        payload = response.json()
    except ValueError as exc:
        raise CaPinError(f"CA fetch for {host} returned non-JSON") from exc
    if not isinstance(payload, dict):
        raise CaPinError(f"CA fetch for {host} was not an object")
    pem = pem_from_payload(payload)
    fingerprint = fingerprint_from_payload(payload, pem)
    if not fingerprint:
        raise CaPinError(f"CA response for {host} had no fingerprint")
    if stored:
        if fingerprint not in stored:
            raise CaPinError(
                f"CA fingerprint for {host} changed ({fingerprint}). "
                "Refusing to send credentials."
            )
    else:
        _confirm(host, fingerprint)
    return _save_pem(host, pem, fingerprint)


def stage_next_ca(host: str, base_url: str, headers: dict, verify) -> None:
    """After login, add the next CA to the pin bundle if the Controller has one."""
    try:
        response = _fetch_ca(base_url, CA_NEXT_PATH, verify=verify, headers=headers)
    except requests.exceptions.RequestException as exc:
        print(f"      Could not read next CA for {host}: {exc}", file=sys.stderr)
        return
    if response.status_code == 404:
        return
    if response.status_code != 200:
        return
    try:
        payload = response.json()
    except ValueError:
        return
    if not isinstance(payload, dict) or not payload.get("certificate"):
        return
    try:
        pem = pem_from_payload(payload)
        fingerprint = fingerprint_from_payload(payload, pem)
    except CaPinError as exc:
        print(f"      Next CA for {host} was not staged: {exc}", file=sys.stderr)
        return
    if not fingerprint or fingerprint in _read_fps(host):
        return
    _save_pem(host, pem, fingerprint)
    print(f"      Staged next CA for {host}: {fingerprint}", file=sys.stderr)
