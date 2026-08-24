from pathlib import Path

from seventytwo.engine.context import load_context
from seventytwo.policy import load_policy
from seventytwo.rehearsal import load_scenario

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "seventytwo" / "data"


def test_bundled_policy_and_context_match_repository_defaults():
    source_policy = load_policy(ROOT / "policy" / "containment-authority.yaml")
    bundled_policy = load_policy(DATA / "default-containment-authority.yaml")
    assert bundled_policy.model_dump(mode="json") == source_policy.model_dump(mode="json")

    source_context = load_context(ROOT / "policy" / "business-context.yaml")
    bundled_context = load_context(DATA / "default-business-context.yaml")
    assert bundled_context.model_dump(mode="json") == source_context.model_dump(mode="json")


def test_bundled_scenarios_match_repository_defaults():
    for source_path in sorted((ROOT / "scenarios").glob("*.yaml")):
        bundled_path = DATA / "scenarios" / source_path.name
        assert bundled_path.is_file()
        assert load_scenario(bundled_path) == load_scenario(source_path)
