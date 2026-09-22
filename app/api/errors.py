"""API errors shared by AppGateClient mixins."""


class AppliancePutError(RuntimeError):
    """GET/PUT guard or Controller rejected the appliance document (E08)."""
