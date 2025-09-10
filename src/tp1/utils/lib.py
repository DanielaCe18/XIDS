import os
import sys
from typing import Optional


def choose_interface(interactive: Optional[bool] = None) -> str:
    """
    Sélection d'interface :
    - IDS_INTERFACE (env) prioritaire si définie et présente
    - Sinon 1ʳᵉ interface disponible
    - Interaction utilisateur uniquement si 'interactive=True' OU si interactive=None
      ET qu'on est dans un TTY (et pas sous pytest/CI).
    """
    # Détecte si on est en mode interactif
    if interactive is None:
        interactive = sys.stdin.isatty() and ("PYTEST_CURRENT_TEST" not in os.environ)

    forced = os.environ.get("IDS_INTERFACE")

    try:
        from scapy.all import get_if_list  # type: ignore
        interfaces = get_if_list() or []
    except Exception:
        interfaces = []

    if not interfaces:
        return forced or "lo"

    if forced and forced in interfaces:
        return forced

    default_iface = forced or interfaces[0]

    if not interactive:
        # Pas d'input() en tests/CI -> on retourne directement
        return default_iface

    # Affichage et saisie seulement en mode interactif
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
