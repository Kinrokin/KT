from scripts.check_pr_review_completion import check_review_completion


def test_v4_review_completion_without_pr_is_pending():
    receipt = check_review_completion(None)
    assert receipt["status"] == "PENDING_PR_REVIEW_COMPLETION"
    assert receipt["required_merge_gate"] == "zero unresolved review threads"
