"""
alert_generator.py
------------------
Transforme les correspondances (event + rule) en alertes
structurées, lisibles et justifiées.
"""

import json
import os
from datetime import datetime


# Icônes console selon la sévérité
SEVERITY_ICONS = {
    "high":   "🔴",
    "medium": "🟡",
    "low":    "🟢",
}

# Couleurs ANSI pour le terminal
COLORS = {
    "high":   "\033[91m",   # rouge
    "medium": "\033[93m",   # jaune
    "low":    "\033[92m",   # vert
    "reset":  "\033[0m",
    "bold":   "\033[1m",
    "dim":    "\033[2m",
}


class AlertGenerator:
    """
    Génère des alertes lisibles à partir des correspondances
    produites par RuleEngine.
    """

    def __init__(self, matches: list):
        self.matches = matches
        self.alerts = []

    def generate(self) -> list:
        """
        Construit la liste d'alertes structurées.
        """
        self.alerts = []

        for i, match in enumerate(self.matches, start=1):
            event = match["event"]
            rule = match["rule"]
            cond = rule["condition"]

            # Justification textuelle lisible
            justification = self._build_justification(event, rule)

            alert = {
                "alert_id":      f"ALT-{i:04d}",
                "generated_at":  datetime.now().isoformat(),
                "severity":      rule["severity"],
                "rule_id":       rule["id"],
                "rule_name":     rule["name"],
                "description":   rule.get("description", ""),
                "tags":          rule.get("tags", []),
                "justification": justification,
                "matched_event": {
                    "event_id":  event.get("id", "N/A"),
                    "timestamp": event.get("timestamp", "N/A"),
                    "type":      event.get("type", "N/A"),
                    "user":      event.get("user", "N/A"),
                    "process":   event.get("process", "N/A"),
                    "detail":    event.get("detail", "N/A"),
                    "source_ip": event.get("source_ip", "N/A"),
                },
            }
            self.alerts.append(alert)

        return self.alerts

    def _build_justification(self, event: dict, rule: dict) -> str:
        """
        Génère un texte explicatif clair indiquant pourquoi
        la règle a été déclenchée sur cet événement.
        """
        cond = rule["condition"]
        field = cond["field"]
        operator = cond["operator"]
        value = cond["value"]
        actual = event.get(field, "N/A")

        op_phrases = {
            "equals":       f"le champ '{field}' est exactement '{value}'",
            "not_equals":   f"le champ '{field}' est différent de '{value}'",
            "contains":     f"le champ '{field}' contient '{value}'",
            "regex":        f"le champ '{field}' correspond au pattern '{value}'",
            "greater_than": f"le champ '{field}' ({actual}) est supérieur à {value}",
        }

        phrase = op_phrases.get(operator, f"condition '{operator}' vérifiée")
        return (
            f"Règle '{rule['id']} — {rule['name']}' déclenchée car {phrase}. "
            f"Valeur observée : '{actual}'. "
            f"Événement : [{event.get('timestamp', '')}] {event.get('type', '')} "
            f"par utilisateur '{event.get('user', '')}'."
        )

    def print_alerts(self):
        """
        Affiche les alertes dans le terminal avec couleurs et formatage.
        """
        if not self.alerts:
            print("\n[AlertGenerator] Aucune alerte déclenchée.\n")
            return

        print(f"\n{'='*60}")
        print(f"  RAPPORT D'ALERTES — {len(self.alerts)} alerte(s) générée(s)")
        print(f"{'='*60}\n")

        # Trier par sévérité : high → medium → low
        order = {"high": 0, "medium": 1, "low": 2}
        sorted_alerts = sorted(self.alerts, key=lambda a: order[a["severity"]])

        for alert in sorted_alerts:
            sev = alert["severity"]
            icon = SEVERITY_ICONS.get(sev, "")
            color = COLORS.get(sev, "")
            reset = COLORS["reset"]
            bold = COLORS["bold"]
            dim = COLORS["dim"]

            print(f"{color}{bold}[{alert['alert_id']}] {icon} {sev.upper()} — {alert['rule_name']}{reset}")
            print(f"  {dim}Règle       :{reset} {alert['rule_id']}")
            print(f"  {dim}Événement   :{reset} {alert['matched_event']['event_id']} "
                  f"@ {alert['matched_event']['timestamp']}")
            print(f"  {dim}Type        :{reset} {alert['matched_event']['type']}")
            print(f"  {dim}Utilisateur :{reset} {alert['matched_event']['user']}")
            print(f"  {dim}Détail      :{reset} {alert['matched_event']['detail']}")
            print(f"  {dim}Justif.     :{reset} {alert['justification']}")
            if alert["tags"]:
                print(f"  {dim}Tags        :{reset} {', '.join(alert['tags'])}")
            print()

    def save(self, output_dir: str = "alerts") -> str:
        """
        Sauvegarde les alertes dans un fichier JSON horodaté.
        Retourne le chemin du fichier créé.
        """
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(output_dir, f"alerts_{timestamp}.json")

        output = {
            "generated_at": datetime.now().isoformat(),
            "total_alerts": len(self.alerts),
            "summary": {
                "high":   sum(1 for a in self.alerts if a["severity"] == "high"),
                "medium": sum(1 for a in self.alerts if a["severity"] == "medium"),
                "low":    sum(1 for a in self.alerts if a["severity"] == "low"),
            },
            "alerts": self.alerts,
        }

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, ensure_ascii=False)

        print(f"[AlertGenerator] Alertes sauvegardées → {filename}")
        return filename

    def get_summary(self) -> dict:
        return {
            "total":  len(self.alerts),
            "high":   sum(1 for a in self.alerts if a["severity"] == "high"),
            "medium": sum(1 for a in self.alerts if a["severity"] == "medium"),
            "low":    sum(1 for a in self.alerts if a["severity"] == "low"),
        }
