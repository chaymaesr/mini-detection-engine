"""
convert_events.py
------------------
Convertit le dataset reel ssh_bruteforce.json (format LabSZ, champs
event_type / pas de id / pas de detail) vers le format attendu par
le moteur de detection (champs type / id / detail).

Usage:
    python convert_events.py ssh_bruteforce.json ssh_bruteforce_converted.json
"""

import json
import sys


def convert(input_path: str, output_path: str) -> None:
    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError("Le fichier source doit contenir un tableau JSON.")

    converted = []
    for i, e in enumerate(data, start=1):
        event_type = e.get("event_type", "unknown")
        user = e.get("user", "unknown")
        source_ip = e.get("source_ip", "N/A")
        process = e.get("process", "")
        port = e.get("port")

        # Construit un champ "detail" textuel lisible, exploite par les
        # operateurs contains / regex des regles (R003, R005, R009, R010).
        if event_type == "auth_failure":
            detail = f"ssh login failed for user {user} from {source_ip}"
            if port is not None:
                detail += f" port {port}"
        elif event_type == "invalid_user":
            detail = f"invalid user {user} attempted from {source_ip}"
        else:
            detail = f"{event_type} for user {user} from {source_ip}"

        converted.append({
            "id": f"EVT-{i:04d}",
            "timestamp": e.get("timestamp", ""),
            "type": event_type,        # event_type -> type
            "user": user,
            "process": process,
            "detail": detail,          # champ synthetique ajoute
            "source_ip": source_ip,
            "port": port,
        })

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(converted, f, indent=2, ensure_ascii=False)

    print(f"[convert] {len(converted)} evenement(s) convertis -> {output_path}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python convert_events.py <entree.json> <sortie.json>")
        sys.exit(1)
    convert(sys.argv[1], sys.argv[2])
