"""
test_engine.py
--------------
Tests unitaires du mini moteur de detection.
Lancement : pytest test_engine.py -v
"""

import pytest
import json
import os
import sys
import importlib.util

# -------------------------------------------------------
# Chargement des modules depuis le meme dossier
# -------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def _load(name, filename):
    path = os.path.join(BASE_DIR, filename)
    spec = importlib.util.spec_from_file_location(name, path)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

rl_mod  = _load("rule_loader",     "rule_loader.py")
eng_mod = _load("engine_core",     "engine.py")
ag_mod  = _load("alert_generator", "alert_generator.py")

RuleLoader      = rl_mod.RuleLoader
RuleLoaderError = rl_mod.RuleLoaderError
RuleEngine      = eng_mod.RuleEngine
AlertGenerator  = ag_mod.AlertGenerator


# ================================================================
# FIXTURES
# ================================================================

@pytest.fixture
def sample_rules():
    return [
        {"id":"R001","name":"Test equals","description":"d","condition":{"field":"type","operator":"equals","value":"auth_failure"},"severity":"medium","tags":[]},
        {"id":"R002","name":"Test contains","description":"d","condition":{"field":"detail","operator":"contains","value":"sudo"},"severity":"high","tags":[]},
        {"id":"R003","name":"Test regex","description":"d","condition":{"field":"detail","operator":"regex","value":"/etc/(passwd|shadow)"},"severity":"high","tags":[]},
        {"id":"R004","name":"Test not_equals","description":"d","condition":{"field":"user","operator":"not_equals","value":"system"},"severity":"low","tags":[]},
    ]

@pytest.fixture
def sample_events():
    return [
        {"id":"EVT-001","timestamp":"2024-11-15T08:00:00Z","type":"auth_failure","user":"root","process":"sshd","detail":"ssh login failed","source_ip":"10.0.0.1"},
        {"id":"EVT-002","timestamp":"2024-11-15T08:01:00Z","type":"process_exec","user":"www-data","process":"bash","detail":"sudo su - root","source_ip":"N/A"},
        {"id":"EVT-003","timestamp":"2024-11-15T08:02:00Z","type":"file_write","user":"www-data","process":"bash","detail":"ecriture /etc/passwd","source_ip":"N/A"},
        {"id":"EVT-004","timestamp":"2024-11-15T08:03:00Z","type":"auth_success","user":"alice","process":"sshd","detail":"login normal","source_ip":"10.0.0.5"},
    ]

@pytest.fixture
def rules_file(tmp_path, sample_rules):
    f = tmp_path / "rules.json"
    f.write_text(json.dumps(sample_rules), encoding="utf-8")
    return str(f)


# ================================================================
# TESTS RuleLoader
# ================================================================

class TestRuleLoader:

    def test_charge_regles_valides(self, rules_file, sample_rules):
        loader = RuleLoader(rules_file)
        rules = loader.load()
        assert len(rules) == len(sample_rules)

    def test_fichier_introuvable(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            RuleLoader(str(tmp_path / "inexistant.json"))

    def test_json_invalide(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("{ ceci n'est pas du JSON", encoding="utf-8")
        loader = RuleLoader(str(f))
        with pytest.raises(RuleLoaderError):
            loader.load()

    def test_tableau_requis(self, tmp_path):
        f = tmp_path / "obj.json"
        f.write_text('{"id":"R001"}', encoding="utf-8")
        loader = RuleLoader(str(f))
        with pytest.raises(RuleLoaderError):
            loader.load()

    def test_champ_id_manquant(self, tmp_path):
        bad = [{"name":"Sans ID","condition":{"field":"type","operator":"equals","value":"x"},"severity":"low"}]
        f = tmp_path / "bad.json"
        f.write_text(json.dumps(bad), encoding="utf-8")
        loader = RuleLoader(str(f))
        with pytest.raises(RuleLoaderError):
            loader.load()

    def test_severite_invalide(self, tmp_path):
        bad = [{"id":"R001","name":"T","condition":{"field":"type","operator":"equals","value":"x"},"severity":"critique"}]
        f = tmp_path / "bad.json"
        f.write_text(json.dumps(bad), encoding="utf-8")
        loader = RuleLoader(str(f))
        with pytest.raises(RuleLoaderError):
            loader.load()

    def test_operateur_invalide(self, tmp_path):
        bad = [{"id":"R001","name":"T","condition":{"field":"type","operator":"like","value":"x"},"severity":"low"}]
        f = tmp_path / "bad.json"
        f.write_text(json.dumps(bad), encoding="utf-8")
        loader = RuleLoader(str(f))
        with pytest.raises(RuleLoaderError):
            loader.load()

    def test_fichier_vide(self, tmp_path):
        f = tmp_path / "empty.json"
        f.write_text("[]", encoding="utf-8")
        loader = RuleLoader(str(f))
        rules = loader.load()
        assert rules == []


# ================================================================
# TESTS RuleEngine — operateurs
# ================================================================

class TestRuleEngineOperateurs:

    def test_equals_match(self):
        r = [{"id":"R1","name":"T","condition":{"field":"type","operator":"equals","value":"auth_failure"},"severity":"medium","tags":[]}]
        e = [{"id":"E1","timestamp":"T","type":"auth_failure","user":"root","detail":"x"}]
        assert len(RuleEngine(r).run(e)) == 1

    def test_equals_no_match(self):
        r = [{"id":"R1","name":"T","condition":{"field":"type","operator":"equals","value":"auth_failure"},"severity":"medium","tags":[]}]
        e = [{"id":"E1","timestamp":"T","type":"auth_success","user":"alice","detail":"x"}]
        assert len(RuleEngine(r).run(e)) == 0

    def test_contains_match(self):
        r = [{"id":"R1","name":"T","condition":{"field":"detail","operator":"contains","value":"sudo"},"severity":"high","tags":[]}]
        e = [{"id":"E1","timestamp":"T","type":"process_exec","user":"www-data","detail":"sudo su - root"}]
        assert len(RuleEngine(r).run(e)) == 1

    def test_contains_insensible_casse(self):
        r = [{"id":"R1","name":"T","condition":{"field":"detail","operator":"contains","value":"SUDO"},"severity":"high","tags":[]}]
        e = [{"id":"E1","timestamp":"T","type":"process_exec","user":"u","detail":"sudo su"}]
        assert len(RuleEngine(r).run(e)) == 1

    def test_regex_match(self):
        r = [{"id":"R1","name":"T","condition":{"field":"detail","operator":"regex","value":"/etc/(passwd|shadow)"},"severity":"high","tags":[]}]
        e = [{"id":"E1","timestamp":"T","type":"file_write","user":"u","detail":"ecriture /etc/passwd"}]
        assert len(RuleEngine(r).run(e)) == 1

    def test_regex_no_match(self):
        r = [{"id":"R1","name":"T","condition":{"field":"detail","operator":"regex","value":"/etc/(passwd|shadow)"},"severity":"high","tags":[]}]
        e = [{"id":"E1","timestamp":"T","type":"file_write","user":"u","detail":"ecriture /tmp/test"}]
        assert len(RuleEngine(r).run(e)) == 0

    def test_not_equals_match(self):
        r = [{"id":"R1","name":"T","condition":{"field":"user","operator":"not_equals","value":"system"},"severity":"low","tags":[]}]
        e = [{"id":"E1","timestamp":"T","type":"process_exec","user":"root","detail":"x"}]
        assert len(RuleEngine(r).run(e)) == 1

    def test_champ_absent(self):
        r = [{"id":"R1","name":"T","condition":{"field":"source_ip","operator":"equals","value":"10.0.0.1"},"severity":"low","tags":[]}]
        e = [{"id":"E1","timestamp":"T","type":"process_exec","user":"root","detail":"x"}]
        assert len(RuleEngine(r).run(e)) == 0

    def test_aucun_evenement(self, sample_rules):
        assert len(RuleEngine(sample_rules).run([])) == 0

    def test_aucune_regle(self, sample_events):
        assert len(RuleEngine([]).run(sample_events)) == 0


# ================================================================
# TESTS RuleEngine — scenarios
# ================================================================

class TestRuleEngineScenarios:

    def test_scenario_brute_force(self, sample_rules, sample_events):
        matches = RuleEngine(sample_rules).run(sample_events)
        rule_ids = [m["rule"]["id"] for m in matches]
        assert "R001" in rule_ids

    def test_scenario_privesc(self, sample_rules, sample_events):
        matches = RuleEngine(sample_rules).run(sample_events)
        rule_ids = [m["rule"]["id"] for m in matches]
        assert "R002" in rule_ids
        assert "R003" in rule_ids

    def test_faux_positif_alice(self, sample_rules, sample_events):
        matches = RuleEngine(sample_rules).run(sample_events)
        for m in matches:
            if m["event"]["id"] == "EVT-004":
                assert m["rule"]["id"] != "R001"

    def test_stats_correctes(self, sample_rules, sample_events):
        engine = RuleEngine(sample_rules)
        engine.run(sample_events)
        stats = engine.get_stats()
        assert stats["events_processed"] == len(sample_events)
        assert stats["rules_evaluated"] == len(sample_rules) * len(sample_events)


# ================================================================
# TESTS AlertGenerator
# ================================================================

class TestAlertGenerator:

    def test_autant_alertes_que_matches(self, sample_rules, sample_events):
        matches = RuleEngine(sample_rules).run(sample_events)
        alerts = AlertGenerator(matches).generate()
        assert len(alerts) == len(matches)

    def test_champs_requis(self, sample_rules, sample_events):
        matches = RuleEngine(sample_rules).run(sample_events)
        alerts = AlertGenerator(matches).generate()
        for a in alerts:
            assert "alert_id"      in a
            assert "severity"      in a
            assert "rule_id"       in a
            assert "rule_name"     in a
            assert "justification" in a
            assert "matched_event" in a

    def test_severite_valide(self, sample_rules, sample_events):
        matches = RuleEngine(sample_rules).run(sample_events)
        alerts = AlertGenerator(matches).generate()
        for a in alerts:
            assert a["severity"] in ["low","medium","high"]

    def test_justification_non_vide(self, sample_rules, sample_events):
        matches = RuleEngine(sample_rules).run(sample_events)
        alerts = AlertGenerator(matches).generate()
        for a in alerts:
            assert len(a["justification"]) > 10

    def test_resume_correct(self, sample_rules, sample_events):
        matches = RuleEngine(sample_rules).run(sample_events)
        gen = AlertGenerator(matches)
        gen.generate()
        s = gen.get_summary()
        assert s["total"] == s["high"] + s["medium"] + s["low"]

    def test_sauvegarde_json(self, tmp_path, sample_rules, sample_events):
        matches = RuleEngine(sample_rules).run(sample_events)
        gen = AlertGenerator(matches)
        gen.generate()
        path = gen.save(output_dir=str(tmp_path))
        assert os.path.exists(path)
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        assert "alerts" in data
        assert data["total_alerts"] == len(matches)

    def test_aucun_match(self):
        gen = AlertGenerator([])
        alerts = gen.generate()
        assert alerts == []
        assert gen.get_summary()["total"] == 0
