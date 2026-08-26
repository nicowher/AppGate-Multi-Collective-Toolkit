"""Shared AppGate admin API.

HTTP only (login, GET/PUT appliances). Target/exclude helpers are in
``core/inventory.py``. One client instance per collective (own bearer token).
"""
from .appgate import AppGateClient

__all__ = ["AppGateClient"]
