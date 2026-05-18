# Security Review Packet

Security posture for bounded pilot review:

- External attestation remains pending.
- No secrets should be included in pilot evidence bundles.
- Generated receipts must preserve claim ceiling and source bindings.
- FP0/local runtime and contained subagent work remain non-authoritative unless separately promoted.
- Any credential leakage, prompt injection, tool injection, or authority drift routes to blocker or forensic review.
