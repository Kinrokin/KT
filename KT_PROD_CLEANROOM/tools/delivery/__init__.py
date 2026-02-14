"""Delivery pack generation tools (client-safe bundles).

These tools are strictly *derivation* utilities:
- They do not modify evidence packs in place.
- They copy + redact selected surfaces for client delivery.
- They run a fail-closed secret scan on the final delivery directory.
"""

