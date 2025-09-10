import os
import sys


def choose_interface() -> str:
    """
    Choisit une interface réseau :
    - IDS_INTERFACE (env) si définie,
    - sinon 1ʳᵉ interface disponible,
    - prompt interactif UNIQUEMENT si stdin est un TTY (pas en tests).
    """
    # 1) variable d'environnement prioritaire
    forced = os.environ.get("IDS_INTERFACE")
    try:
        from scapy.all import get_if_list  # type: ignore
        interfaces = get_if_list() or []
    except Exception:
        interfaces = []

    if not interfaces:
        return forced or "lo"

    # Si une interface est forcée et existe, on la prend
    if forced and forced in interfaces:
        return forced

    # En environnement non interactif (pytest/CI), on évite input()
    non_interactive = (not sys.stdin.isatty()) or ("PYTEST_CURRENT_TEST" in os.environ)
    default_iface = forced or interfaces[0]

    if non_interactive:
        return default_iface

    # Mode interactif
    print("Interfaces disponibles :")
    for i, iface in enumerate(interfaces):
        print(f"  [{i}] {iface}")

    choice = input(f"Sélectionnez une interface (Entrée = {default_iface}) : ").strip()

    if choice.isdigit():
        idx = int(choice)
        if 0 <= idx < len(interfaces):
            return interfaces[idx]

    if choice in interfaces:
        return choice

    return default_iface
