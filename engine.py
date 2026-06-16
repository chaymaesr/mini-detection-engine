"""
engine.py
---------
Moteur d'évaluation : applique les règles sur chaque événement
et retourne la liste des correspondances (matches).
"""

import re


class EvaluationError(Exception):
    """Exception levée si l'évaluation d'une règle échoue."""
    pass


class RuleEngine:
    """
    Évalue une liste d'événements contre une liste de règles.
    Retourne les paires (événement, règle) qui correspondent.
    """

    def __init__(self, rules: list):
        self.rules = rules
        self.stats = {
            "events_processed": 0,
            "rules_evaluated": 0,
            "matches_found": 0,
        }

    def run(self, events: list) -> list:
        """
        Parcourt tous les événements et évalue chaque règle.

        Retourne une liste de dict { "event": ..., "rule": ... }
        """
        matches = []

        for event in events:
            self.stats["events_processed"] += 1

            for rule in self.rules:
                self.stats["rules_evaluated"] += 1

                try:
                    matched = self._evaluate(event, rule)
                except EvaluationError as e:
                    print(f"[RuleEngine] ERREUR évaluation règle {rule['id']} : {e}")
                    continue

                if matched:
                    self.stats["matches_found"] += 1
                    matches.append({
                        "event": event,
                        "rule": rule,
                    })

        print(
            f"[RuleEngine] Analyse terminée — "
            f"{self.stats['events_processed']} événement(s), "
            f"{self.stats['rules_evaluated']} évaluation(s), "
            f"{self.stats['matches_found']} correspondance(s)"
        )
        return matches

    def _evaluate(self, event: dict, rule: dict) -> bool:
        """
        Évalue une règle sur un événement.
        Retourne True si la condition est satisfaite.
        """
        cond = rule["condition"]
        field = cond["field"]
        operator = cond["operator"]
        target = cond["value"]

        # Récupérer la valeur du champ dans l'événement
        raw_value = event.get(field, "")
        field_value = str(raw_value) if raw_value is not None else ""

        # --- Opérateurs ---

        if operator == "equals":
            return field_value.lower() == target.lower()

        elif operator == "not_equals":
            return field_value.lower() != target.lower()

        elif operator == "contains":
            return target.lower() in field_value.lower()

        elif operator == "regex":
            try:
                return bool(re.search(target, field_value, re.IGNORECASE))
            except re.error as e:
                raise EvaluationError(f"Expression regex invalide '{target}' : {e}")

        elif operator == "greater_than":
            try:
                return float(field_value) > float(target)
            except ValueError:
                raise EvaluationError(
                    f"Impossible de comparer '{field_value}' > '{target}' "
                    f"(valeurs non numériques)"
                )

        else:
            raise EvaluationError(f"Opérateur inconnu : '{operator}'")

    def get_stats(self) -> dict:
        return self.stats
