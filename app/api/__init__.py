"""Shared AppGate admin API.

HTTP only (login, GET/PUT appliances, NTP). Target/exclude helpers are in
``core/inventory.py``. One client instance per collective (own bearer token)
so site A's token is never sent to site B.
"""
from .appgate import AppGateClient, AppliancePutError

__all__ = ["AppGateClient", "AppliancePutError"]
