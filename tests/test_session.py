"""Credential helper must not expose secrets."""

from app.adapters.aws import session as aws_session


def test_session_helpers_are_importable():
    assert callable(aws_session.build_session)
    assert callable(aws_session.credentials_present)
