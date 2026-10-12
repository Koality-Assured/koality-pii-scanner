import ipaddress


def is_valid_credit_card(cc: str) -> bool:
    # Remove separators
    cc = cc.replace("-", "").replace(" ", "")
    if not cc.isdigit():
        return False
    if len(cc) < 13 or len(cc) > 19:
        return False

    # IIN check

    valid_iin = False
    if cc.startswith("4"):
        valid_iin = True
    elif 51 <= int(cc[:2]) <= 55:
        valid_iin = True
    elif cc[:2] in ("34", "37"):
        valid_iin = True
    elif 300 <= int(cc[:3]) <= 305 or cc[:2] in ("36", "38"):
        valid_iin = True
    elif cc.startswith("6011") or 650000 <= int(cc[:6].ljust(6, "0")) <= 659999:  # 65xx
        valid_iin = True

    if not valid_iin:
        return False

    # Luhn check
    total = 0
    reverse_digits = cc[::-1]
    for i, char in enumerate(reverse_digits):
        digit = int(char)
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def is_valid_ssn(ssn: str) -> bool:
    ssn = ssn.replace("-", "").replace(" ", "")
    if len(ssn) != 9 or not ssn.isdigit():
        return False

    area = int(ssn[0:3])
    group = int(ssn[3:5])
    serial = int(ssn[5:9])

    if area == 0 or area == 666 or (900 <= area <= 999):
        return False
    if group == 0:
        return False
    if serial == 0:
        return False

    return True


def is_valid_ipv4(ip: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
        # exclude private, loopback, link-local, multicast, documentation
        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
        ):
            return False
        # documentation: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
        # IP prefix checks are easier with ip_network, but we can just check string prefixes
        if (
            ip.startswith("192.0.2.")
            or ip.startswith("198.51.100.")
            or ip.startswith("203.0.113.")
        ):
            return False
        # Ignore common version number lookalikes like 1.2.3.4 (actually 1.x is valid but often versions)
        if ip in (
            "1.2.3.4",
            "1.0.0.0",
            "0.0.0.0",
            "255.255.255.255",
            "8.8.8.8",
            "1.1.1.1",
        ):
            # Actually 8.8.8.8 and 1.1.1.1 are public DNS. Let's not hardcode exclude them, unless it's a version.
            if ip in ("1.2.3.4", "0.0.0.0", "255.255.255.255"):
                return False
        return True
    except ValueError:
        return False


def is_valid_ipv6(ip: str) -> bool:
    try:
        addr = ipaddress.IPv6Address(ip)
        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
        ):
            return False
        return True
    except ValueError:
        return False


def is_valid_mac(mac: str) -> bool:
    # exclude common dummy MACs like 00:00:00:00:00:00 or ff:ff:ff:ff:ff:ff
    clean_mac = mac.lower().replace("-", ":")
    if clean_mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "01:23:45:67:89:ab"):
        return False
    return True


VALIDATORS = {
    "credit-card": is_valid_credit_card,
    "ssn-us": is_valid_ssn,
    "ipv4": is_valid_ipv4,
    "ipv6": is_valid_ipv6,
    "mac-address": is_valid_mac,
}


def validate(rule_id: str, match: str) -> bool:
    validator = VALIDATORS.get(rule_id)
    if validator:
        return validator(match)
    return True
