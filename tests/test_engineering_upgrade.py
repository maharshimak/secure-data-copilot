import pytest

from data_copilot.planner import DeterministicPlanner


@pytest.mark.parametrize("question", ["delete orders", "drop customers", "pragma orders", ""])
def test_mutation_intent_is_rejected_before_planning(question):
    with pytest.raises(ValueError):
        DeterministicPlanner().plan(question, [])
