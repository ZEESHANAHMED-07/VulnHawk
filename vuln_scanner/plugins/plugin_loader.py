import importlib
import os


def load_plugins():
    plugins = []
    base_path = os.path.dirname(__file__)

    for file in os.listdir(base_path):
        if file.endswith(".py") and not file.startswith("_") and file != "plugin_loader.py":
            module_name = f"plugins.{file[:-3]}"
            module = importlib.import_module(module_name)

            if hasattr(module, "run"):
                plugins.append(module)

    return plugins
