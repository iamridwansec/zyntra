from importlib import import_module

from core.registry import MODULES
from core.lifecycle import run_assessment


def dispatch_command(command, target, ports=None):
    module_path = MODULES.get(command)

    if not module_path:
        print(f"[!] Unknown command: {command}")
        return

    module = import_module(module_path)

    print(f"[+] Dispatching to: {module_path}")

    return run_assessment(
        command,
        module,
        target,
        ports=ports
    )
