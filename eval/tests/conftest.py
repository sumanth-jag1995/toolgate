import pytest
from mock_enterprise.canary import CANARY
from toolgate_eval.sink import CANARY_FIELDS, CanaryMatcher


@pytest.fixture
def matcher() -> CanaryMatcher:
    return CanaryMatcher({k: CANARY[k] for k in CANARY_FIELDS})
