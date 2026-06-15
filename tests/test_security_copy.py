from pathlib import Path


def test_security_doc_names_hibp_scope_not_generic_breach_intelligence():
    security = (Path(__file__).parents[1] / "SECURITY.md").read_text(encoding="utf-8")

    assert "Exposure checks use authorized mailbox evidence, optional paid HIBP email-breach lookup, and k-anonymous HIBP password checks." in security
    assert "reputable breach intelligence" not in security
