"""
rule_loader.py
--------------
Charge et valide les règles de détection depuis un fichier JSON.
"""

import json
import os


# Champs obligatoires dans chaque règle
REQUIRED_FIELDS = ["id", "name", "condition", "severity"]

# Opérateurs acceptés
VALID_OPERATORS = ["equals", "contains", "regex", "not_equals", "greater_than"]

# Champs d'événement acceptés
VALID_FIELDS = ["type", "user", "detail", "source_ip", "process"]

# Niveaux de sévérité acceptés
VALID_SEVERITIES = ["low", "medium", "high"]


class RuleLoaderError(Exception):
    """Exception levée si une règle est mal formée."""
    pass


class RuleLoader:
    """
    Charge les règles depuis un fichier JSON et valide leur structure.
    """

    def __init__(self, rules_path: str):
        if not os.path.exists(rules_path):
            raise FileNotFoundError(f"Fichier de règles introuvable : {rules_path}")
        self.rules_path = rules_path
        self.rules = []

    def load(self) -> list:
        """
        Lit le fichier JSON et retourne la liste des règles validées.
        """
        with open(self.rules_path, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError as e:
                raise RuleLoaderError(f"JSON invalide dans {self.rules_path} : {e}")

        if not isinstance(data, list):
            raise RuleLoaderError("Le fichier de règles doit contenir un tableau JSON.")

        validated = []
        for i, rule in enumerate(data):
            self._validate_rule(rule, index=i)
            validated.append(rule)

        self.rules = validated
        print(f"[RuleLoader] {len(self.rules)} règle(s) chargée(s) depuis '{self.rules_path}'")
        return self.rules

    def _validate_rule(self, rule: dict, index: int):
        """
        Vérifie qu'une règle possède tous les champs requis et des valeurs valides.
        """
        # Vérifier les champs obligatoires
        for field in REQUIRED_FIELDS:
            if field not in rule:
                raise RuleLoaderError(
                    f"Règle #{index} : champ obligatoire manquant → '{field}'"
                )

        # Vérifier la sévérité
        if rule["severity"] not in VALID_SEVERITIES:
            raise RuleLoaderError(
                f"Règle '{rule.get('id', index)}' : sévérité invalide → '{rule['severity']}'. "
                f"Valeurs acceptées : {VALID_SEVERITIES}"
            )

        # Vérifier la condition
        cond = rule["condition"]
        if not isinstance(cond, dict):
            raise RuleLoaderError(
                f"Règle '{rule['id']}' : 'condition' doit être un objet JSON."
            )

        for sub in ["field", "operator", "value"]:
            if sub not in cond:
                raise RuleLoaderError(
                    f"Règle '{rule['id']}' : champ manquant dans condition → '{sub}'"
                )

        if cond["operator"] not in VALID_OPERATORS:
            raise RuleLoaderError(
                f"Règle '{rule['id']}' : opérateur invalide → '{cond['operator']}'. "
                f"Opérateurs acceptés : {VALID_OPERATORS}"
            )

        if cond["field"] not in VALID_FIELDS:
            raise RuleLoaderError(
                f"Règle '{rule['id']}' : champ d'événement invalide → '{cond['field']}'. "
                f"Champs acceptés : {VALID_FIELDS}"
            )

    def get_rules(self) -> list:
        return self.rules
