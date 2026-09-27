"""Shared decorators for the Sentinel codebase."""


def no_audit_log(func):
    """Marker: audit_fix will not inject logging into this function.

    This decorator does nothing at runtime. It signals to the audit_fix tool
    that logging should NOT be auto-injected into this function, even if it
    would otherwise qualify under the skip rules.

    Use for edge cases the skip rules don't cover — high-frequency endpoints,
    functions where logging was deliberately removed, etc.
    """
    func._no_audit_log = True
    return func
