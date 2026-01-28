def run(target, ip, context):
    """
    Example plugin that demonstrates plugin structure.
    """
    return {
        "plugin": "example_plugin",
        "message": f"Plugin executed for {target} ({ip})",
        "note": "Replace this with real logic"
    }
