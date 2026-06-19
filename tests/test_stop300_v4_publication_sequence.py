import zipfile
from pathlib import Path


def test_v4_publication_non_circular_sequence():
    with zipfile.ZipFile(Path("packets/ktstop300_v4.zip")) as zf:
        runner = zf.read("runtime/KT_CANONICAL_RUNNER.py").decode("utf-8-sig")
        publisher = zf.read("runtime/hf_publisher.py").decode("utf-8-sig")
    assert "CORE_RESULT_SUMMARY.json" in runner
    assert "FINAL_RUN_DISPOSITION.json" in runner
    assert "publish_final_assessment" in runner
    assert "PASS_HF_FINAL_ASSESSMENT_UPLOADED" in publisher
