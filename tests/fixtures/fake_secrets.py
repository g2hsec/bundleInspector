"""Synthetic secret-like constants for public test fixtures.

These values are intentionally assembled from multiple fragments so the source
tree does not contain provider-looking credentials in a contiguous form.
Runtime tests still receive the exact secret-like strings they need.
"""

FAKE_AWS_ACCESS_KEY = "AKIA" "IOSFODNN7EXAMPLE"
FAKE_GITHUB_PAT = "gh" "p_" "abcdefghijklmnopqrstuvwxyz1234567890"
FAKE_STRIPE_LIVE = "sk" "_live_" "abcdefghijklmnopqrstuvwxyz123456"
FAKE_STRIPE_LIVE_SHORT = "sk" "_live_" "abcdefghijklmnopqrstuvwxyz"
FAKE_STRIPE_LIVE_ALT = "sk" "_live_" "abc123xyz789secretkey"
FAKE_STRIPE_TEST_SHORT = "sk" "_test_" "abcdefghijklmnopqrstuvwxyz"
FAKE_MASK_VALUE_LONG = "sk" "_live_" "1234567890abcdef"
FAKE_MASK_VALUE_SHORT = "sk" "_live_" "1234567890"
FAKE_MAILGUN_API_KEY = "key-" "1234567890abcdef" "1234567890abcdef"
FAKE_MAILGUN_PRIVATE_KEY = (
    "1234567890abcdef" "1234567890abcdef"
    "-"
    "12345678"
    "-"
    "12345678"
)
