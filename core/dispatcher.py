import importlib

from core.registry import MODULES


def dispatch_command(command, target):
    module_path = MODULES.get(command)

    if not module_path:
        print(f"[!] Unknown command: {command}")
        return

    module = importlib.import_module(module_path)

    print(f"[+] Dispatching to: {module_path}")

    module.run(target)
