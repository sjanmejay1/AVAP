from app.core.config import Settings


def test_cors_allowed_origins_default_is_local_frontend_dev_origin():
    """The out-of-the-box default must allow the standard local Next.js dev
    server without requiring any .env changes, while still being an explicit
    allowlist rather than a wildcard.
    """
    settings = Settings(_env_file=None)
    assert settings.cors_allowed_origins_list == ["http://localhost:3000"]


def test_cors_allowed_origins_list_parses_multiple_comma_separated_origins():
    settings = Settings(
        _env_file=None,
        cors_allowed_origins="https://app.example.com,https://staging.example.com",
    )
    assert settings.cors_allowed_origins_list == [
        "https://app.example.com",
        "https://staging.example.com",
    ]


def test_cors_allowed_origins_list_strips_whitespace_around_entries():
    settings = Settings(
        _env_file=None,
        cors_allowed_origins=" https://app.example.com , https://staging.example.com ",
    )
    assert settings.cors_allowed_origins_list == [
        "https://app.example.com",
        "https://staging.example.com",
    ]


def test_cors_allowed_origins_list_drops_blank_entries_from_trailing_comma():
    settings = Settings(_env_file=None, cors_allowed_origins="https://app.example.com,")
    assert settings.cors_allowed_origins_list == ["https://app.example.com"]


def test_cors_allowed_origins_list_empty_string_yields_empty_list():
    """An operator who blanks out the setting gets a deny-all allowlist
    (CORSMiddleware with allow_origins=[]), never an accidental wildcard.
    """
    settings = Settings(_env_file=None, cors_allowed_origins="")
    assert settings.cors_allowed_origins_list == []


def test_effective_database_url_pins_the_psycopg2_driver():
    """SQLAlchemy 2.1 defaults a bare ``postgresql://`` URL to psycopg v3,
    which is not installed; the driver must be named explicitly.
    """
    settings = Settings(
        _env_file=None,
        database_url=None,
        postgres_user="u",
        postgres_password="p",
        postgres_host="db",
        postgres_port=5432,
        postgres_db="avap",
    )
    assert settings.effective_database_url == "postgresql+psycopg2://u:p@db:5432/avap"
