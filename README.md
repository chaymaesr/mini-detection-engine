# Mini Moteur de Détection Basé sur des Règles

**Module** : Operating Systems and Application Security  
**Objectif** : Concevoir un moteur capable d'appliquer des règles de détection à un jeu d'événements système, puis de produire des alertes compréhensibles et justifiées.

---

## Structure du projet

```
detection_engine/
├── engine/                  # Code source du moteur
│   ├── rule_loader.py       # Chargement et validation des règles
│   ├── engine.py            # Évaluateur de règles
│   └── alert_generator.py   # Générateur d'alertes
├── rules/
│   ├── rules_schema.json    # Schéma JSON des règles (référence)
│   └── rules.json           # Règles de détection actives
├── events/
│   ├── event_schema.json    # Schéma JSON des événements (référence)
│   ├── ssh_bruteforce.json  # Scénario 1 : brute-force SSH
│   ├── privesc.json         # Scénario 2 : élévation de privilèges
│   ├── dns_exfil.json       # Scénario 3 : exfiltration DNS
│   └── recon.json           # Scénario 4 : scan réseau
├── alerts/                  # Alertes générées (output)
├── tests/                   # Tests unitaires pytest
├── docs/                    # Documentation & rapport
├── main.py                  # Point d'entrée principal
└── requirements.txt         # Dépendances Python
```

---

## Format des règles

Chaque règle est un objet JSON avec les champs suivants :

| Champ         | Type     | Obligatoire | Description                                      |
|---------------|----------|-------------|--------------------------------------------------|
| `id`          | string   | oui         | Identifiant unique (ex: `R001`)                  |
| `name`        | string   | oui         | Nom lisible de la règle                          |
| `description` | string   | non         | Explication de ce que détecte la règle           |
| `condition`   | object   | oui         | Condition d'activation (voir ci-dessous)         |
| `severity`    | string   | oui         | Niveau : `low`, `medium`, `high`                 |
| `tags`        | array    | non         | Catégories (ex: MITRE ATT&CK)                    |

### Opérateurs supportés dans `condition`

| Opérateur      | Description                                    | Exemple                          |
|----------------|------------------------------------------------|----------------------------------|
| `equals`       | Correspondance exacte                          | `"value": "root"`                |
| `contains`     | Sous-chaîne présente                           | `"value": "sudo"`                |
| `regex`        | Expression régulière                           | `"value": "/etc/(passwd|shadow)"`|
| `not_equals`   | Différent de la valeur                         | `"value": "system"`              |
| `greater_than` | Valeur numérique supérieure                    | `"value": "1000"`                |

### Exemple de règle

```json
{
  "id": "R001",
  "name": "Échec d'authentification SSH",
  "description": "Détecte un échec SSH, possible brute-force",
  "condition": {
    "field": "type",
    "operator": "equals",
    "value": "auth_failure"
  },
  "severity": "medium",
  "tags": ["brute-force", "T1110"]
}
```

---

## Format des événements

Chaque événement système est un objet JSON :

| Champ        | Type     | Obligatoire | Description                                    |
|--------------|----------|-------------|------------------------------------------------|
| `id`         | string   | oui         | Identifiant unique de l'événement              |
| `timestamp`  | string   | oui         | Horodatage ISO 8601                            |
| `type`       | string   | oui         | Catégorie de l'événement (voir liste ci-dessous)|
| `user`       | string   | oui         | Utilisateur système                            |
| `process`    | string   | non         | Processus impliqué                             |
| `detail`     | string   | oui         | Description détaillée de l'action             |
| `source_ip`  | string   | non         | Adresse IP source                              |
| `pid`        | integer  | non         | PID du processus                               |

### Types d'événements supportés

`auth_failure` · `auth_success` · `process_exec` · `suid_exec` · `file_write` · `file_read` · `dns_query` · `net_connect` · `port_scan` · `service_enum` · `privilege_change`

---

## Installation

```bash
pip install -r requirements.txt
```

## Utilisation

```bash
python main.py --rules rules/rules.json --events events/ssh_bruteforce.json
```

Options disponibles :
- `--rules`   : chemin vers le fichier de règles (défaut : `rules/rules.json`)
- `--events`  : chemin vers le fichier d'événements
- `--output`  : répertoire de sortie des alertes (défaut : `alerts/`)
- `--verbose` : afficher le détail de chaque évaluation

---

## Scénarios de test

| Scénario | Fichier               | Attaque simulée               | Alertes attendues |
|----------|-----------------------|-------------------------------|-------------------|
| 1        | `ssh_bruteforce.json` | Brute-force SSH + login root  | HIGH + MEDIUM     |
| 2        | `privesc.json`        | sudo, SUID, /etc/passwd       | HIGH              |
| 3        | `dns_exfil.json`      | Requêtes DNS + transfert      | HIGH + MEDIUM     |
| 4        | `recon.json`          | Port scan + banner grabbing   | MEDIUM + LOW      |

---

## Auteur

Projet académique — Module OS & Application Security
