from posture.finding import Finding, Severity, sort_findings


def _finding(check_id="A", resource_id="r", rule_key="k", severity=Severity.HIGH):
    return Finding(
        check_id=check_id,
        resource_id=resource_id,
        rule_key=rule_key,
        severity=severity,
        title="title",
        evidence="evidence",
    )


def test_to_dict_has_exact_keys():
    result = _finding().to_dict()
    assert result == {
        "check_id": "A",
        "resource_id": "r",
        "rule_key": "k",
        "severity": "HIGH",
        "title": "title",
        "evidence": "evidence",
    }


def test_sort_orders_high_severity_first():
    low = _finding(check_id="A", severity=Severity.LOW)
    high = _finding(check_id="Z", severity=Severity.HIGH)
    assert sort_findings([low, high]) == [high, low]


def test_sort_breaks_severity_ties_on_stable_keys():
    second = _finding(check_id="A", resource_id="b")
    first = _finding(check_id="A", resource_id="a")
    assert sort_findings([second, first]) == [first, second]


def test_sort_is_independent_of_input_order():
    items = [
        _finding(check_id="B", resource_id="b", severity=Severity.MEDIUM),
        _finding(check_id="A", resource_id="a", severity=Severity.HIGH),
        _finding(check_id="C", resource_id="c", severity=Severity.LOW),
    ]
    assert sort_findings(items) == sort_findings(list(reversed(items)))
