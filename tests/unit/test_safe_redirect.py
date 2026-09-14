from crudauth import safe_redirect_path


def test_safe_redirect_path_acceptance_cases() -> None:
    assert safe_redirect_path("https://evil.example") == "/"
    assert safe_redirect_path("//evil.example") == "/"
    assert safe_redirect_path("/\\evil.example") == "/"
    assert safe_redirect_path("/foo\\bar") == "/"
    assert safe_redirect_path("/foo\nbar") == "/"
    assert safe_redirect_path("") == "/"
    assert safe_redirect_path(None) == "/"
    assert safe_redirect_path("/account?next=%2Fhome") == "/account?next=%2Fhome"


def test_safe_redirect_path_uses_custom_default() -> None:
    assert safe_redirect_path("https://evil.example", default="/home") == "/home"
