"""Unit tests for the checksum and range validators."""

import pytest

from pii_scan.validators import (
    is_valid_credit_card,
    is_valid_ipv4,
    is_valid_ipv6,
    is_valid_mac,
    is_valid_ssn,
    validate,
)


@pytest.mark.parametrize(
    "number",
    [
        "4539185296307417",  # Visa
        "4539-1852-9630-7417",
        "4929 1852 9630 7415",
        "371418529630746",  # Amex
        "5425185296307411",  # Mastercard 5-series
        "2223185296307412",  # Mastercard 2-series
        "6011185296307419",  # Discover
        "30561852963078",  # Diners Club
        "3528185296307412",  # JCB
        "4716185296305",  # 13-digit Visa
    ],
)
def test_luhn_valid_cards_accepted(number):
    assert is_valid_credit_card(number)


@pytest.mark.parametrize(
    "number",
    [
        "4539185296307418",  # bad check digit
        "4539-1852-9630-7410",
        "2000185296307411",  # Luhn-valid but unissued prefix
        "1234567890123456",
        "453918529630741",  # wrong length for the check digit
        "4539 1852 9630 741",  # 15 digits, Visa prefix, Luhn-invalid
        "abcd",
        "",
    ],
)
def test_invalid_cards_rejected(number):
    assert not is_valid_credit_card(number)


@pytest.mark.parametrize("ssn", ["521-44-7890", "521 44 7890", "472301234"])
def test_valid_ssns_accepted(ssn):
    assert is_valid_ssn(ssn)


@pytest.mark.parametrize(
    "ssn",
    [
        "000-12-3456",
        "666-12-3456",
        "900-12-3456",
        "999-12-3456",
        "123-00-6789",
        "123-45-0000",
        "12345678",
        "1234567890",
        "abc-de-fghi",
    ],
)
def test_invalid_ssns_rejected(ssn):
    assert not is_valid_ssn(ssn)


@pytest.mark.parametrize("ip", ["45.33.12.7", "185.199.108.153", "91.198.174.192"])
def test_public_ipv4_accepted(ip):
    assert is_valid_ipv4(ip)


@pytest.mark.parametrize(
    "ip",
    [
        "10.0.0.5",
        "192.168.1.1",
        "172.16.0.1",
        "127.0.0.1",
        "169.254.10.10",
        "224.0.0.251",
        "192.0.2.1",
        "198.51.100.9",
        "203.0.113.9",
        "0.0.0.0",
        "255.255.255.255",
        "100.64.0.1",
        "1.2.3.4",
        "8.8.8.8",
        "300.1.1.1",
        "01.02.03.04",
    ],
)
def test_non_public_or_placeholder_ipv4_rejected(ip):
    assert not is_valid_ipv4(ip)


def test_public_ipv6_accepted():
    assert is_valid_ipv6("2a00:1450:4009:81f::200e")
    assert is_valid_ipv6("2001:4860:4860:0:0:0:0:8888")


@pytest.mark.parametrize(
    "ip", ["::1", "::", "fe80::1", "fd00::1", "2001:db8::1", "ff02::1", "12:30:45"]
)
def test_non_public_or_non_ipv6_rejected(ip):
    assert not is_valid_ipv6(ip)


def test_mac_placeholders_rejected():
    assert is_valid_mac("3c:22:fb:5a:91:0d")
    assert is_valid_mac("3C-22-FB-5A-91-0D")
    assert not is_valid_mac("00:00:00:00:00:00")
    assert not is_valid_mac("FF-FF-FF-FF-FF-FF")


def test_validate_dispatch_defaults_to_true_for_unvalidated_rules():
    assert validate("aws-access-key-id", "anything")
    assert not validate("credit-card", "4539185296307418")
