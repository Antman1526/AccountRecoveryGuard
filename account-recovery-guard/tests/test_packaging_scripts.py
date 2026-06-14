from pathlib import Path


def test_macos_dmg_build_retries_transient_hdiutil_failures():
    script = (Path(__file__).parents[1] / "scripts" / "build_macos_dmg.sh").read_text(encoding="utf-8")

    assert "create_dmg_with_retries()" in script
    assert "for attempt in 1 2 3" in script
    assert "hdiutil create" in script
    assert "retrying after cleanup" in script
