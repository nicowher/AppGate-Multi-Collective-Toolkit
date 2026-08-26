"""Shared SSH for appliance work.

SSHSession is the reusable connect / sudo / run layer (password then
keyboard-interactive). SNMPEngineFetcher adds step 4 engine-ID read and
step 7 persistent USM purge. Future ACAS tools should use SSHSession.
"""
from .client import SSHSession
from .engine import SNMPEngineFetcher

__all__ = ["SSHSession", "SNMPEngineFetcher"]
