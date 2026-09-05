from pathlib import Path


def test_roadmap_documents_completed_and_remaining_phases() -> None:
    roadmap = Path(__file__).resolve().parents[1] / "docs" / "roadmap.md"
    content = roadmap.read_text(encoding="utf-8")

    assert "Phase 0" in content
    assert "Phase 1" in content
    assert "Phase 10" in content
    assert "Remaining gaps" in content


def test_open_source_gap_doc_exists() -> None:
    gaps = Path(__file__).resolve().parents[1] / "docs" / "open-source-tooling-gaps.md"
    content = gaps.read_text(encoding="utf-8")

    assert "Semgrep" in content
    assert "Redis" in content
