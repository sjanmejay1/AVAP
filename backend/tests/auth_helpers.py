"""Shared identity for tests: the user that owns test data and that the
`client` fixture is authenticated as."""

import uuid

TEST_USER_ID = uuid.UUID("00000000-0000-4000-8000-000000000001")
TEST_USER_EMAIL = "owner@example.test"
OTHER_USER_ID = uuid.UUID("00000000-0000-4000-8000-000000000002")
