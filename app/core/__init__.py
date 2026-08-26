"""Shared helpers that are not API, SSH, or a menu tool.

  inventory     Target model, health labels, exclude table (not an API client)
  prompts       Controller / credential prompts used by more than one tool
  snmp_hashgen  RFC 3414 localization (step 5)
  snmp_validate Walk backends (step 8 / menu 3)
  utils         credentials.json, host checks, vendor pip, report writer
"""
