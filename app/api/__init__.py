"""Shared AppGate admin API.

``AppGateClient`` is HTTP login + GET/PUT. SNMP/NTP/allowSources are mixins
(``api/snmp.py``, ``api/ntp.py``, ``api/allow_sources.py``). Inventory shape is
``core/inventory.py``. Shared login/exclude is ``core/run.py``. One client per
collective (own bearer token).
"""
from .appgate import AppGateClient, AppliancePutError

__all__ = ["AppGateClient", "AppliancePutError"]
