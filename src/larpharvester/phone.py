from __future__ import annotations

from typing import Any

import phonenumbers
from phonenumbers import carrier, geocoder, timezone

TYPE_NAMES = {
    -1: "unknown",
    0: "fixed_line",
    1: "mobile",
    2: "fixed_line_or_mobile",
    3: "toll_free",
    4: "premium_rate",
    5: "shared_cost",
    6: "voip",
    7: "personal_number",
    8: "pager",
    9: "uan",
    10: "voicemail",
}


def lookup(number: str, region: str | None = None) -> dict[str, Any] | None:
    try:
        parsed = phonenumbers.parse(number, region)
    except phonenumbers.NumberParseException:
        return None
    if not phonenumbers.is_valid_number(parsed):
        return None
    return {
        "input": number,
        "e164": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
        "national": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
        "international": phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
        ),
        "country_code": parsed.country_code,
        "national_number": parsed.national_number,
        "region": geocoder.description_for_number(parsed, "en") or None,
        "carrier": carrier.name_for_number(parsed, "en") or None,
        "timezones": list(timezone.time_zones_for_number(parsed)),
        "type": TYPE_NAMES.get(phonenumbers.number_type(parsed), "unknown"),
        "possible": phonenumbers.is_possible_number(parsed),
    }
