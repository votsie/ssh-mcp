import pytest

from conftest import TRICKY_PASSWORDS
from ssh_mcp import envfile

ADVERSARIAL = [
    *TRICKY_PASSWORDS,
    "it's a #trap",
    "trailing space ",
    " leading space",
    "#starts-with-hash",
    "has=equals=signs",
    'double"quote',
    "back\\slash",
    "both'\"quotes",
    "юникод и пробелы",
    "",
    "'''",
    "a'\\''b",  # уже похоже на POSIX-экранирование — не должно распаковаться дважды
]


@pytest.mark.parametrize("value", ADVERSARIAL)
def test_round_trip(value: str) -> None:
    text = envfile.render([("SSHM_X_PASSWORD", value)])
    parsed, _ = envfile.parse(text)
    assert parsed["SSHM_X_PASSWORD"] == value


def test_hash_in_bare_value_is_not_a_comment() -> None:
    """Решётка — законный символ пароля, обрезать по ней значение нельзя."""
    parsed, _ = envfile.parse("SSHM_X_PASSWORD=aXc#,,Q_31ZmT9\n")
    assert parsed["SSHM_X_PASSWORD"] == "aXc#,,Q_31ZmT9"


def test_full_line_comment_is_kept_aside() -> None:
    parsed, other = envfile.parse("# коммент\n\nSSHM_A_HOST='1.2.3.4'\n")
    assert parsed == {"SSHM_A_HOST": "1.2.3.4"}
    assert "# коммент" in other


def test_double_quoted_values_are_read() -> None:
    parsed, _ = envfile.parse('SSHM_A_LABEL="RU1 - BGD"\nSSHM_A_X="a\\nb"\n')
    assert parsed["SSHM_A_LABEL"] == "RU1 - BGD"
    assert parsed["SSHM_A_X"] == "a\nb"


def test_quote_uses_posix_escaping() -> None:
    assert envfile.quote("it's") == "'it'\\''s'"
