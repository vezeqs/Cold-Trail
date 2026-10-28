from __future__ import annotations

from .utils import dedupe

LEET = str.maketrans({"o": "0", "i": "1", "e": "3", "a": "4", "s": "5", "t": "7"})


def variants(username: str) -> list[str]:
    """Generate plausible handle variants for enumeration."""
    base = username.strip().lstrip("@")
    if len(base) < 3:
        return []
    out = [base]
    out.extend(
        [
            f"{base}_",
            f"_{base}",
            f"{base}1",
            f"{base}123",
            f"{base}official",
            f"{base}_official",
            f"real{base}",
            f"{base}hq",
            f"{base}dev",
            f"{base}io",
            f"{base}.dev",
            f"{base}_dev",
            f"the{base}",
            f"{base}x",
            f"{base}_x",
        ]
    )
    out.append(base.translate(LEET))
    out.append(base.replace("_", "."))
    out.append(base.replace("_", "-"))
    out.append(base.replace(".", "_"))
    out.append(base.replace("-", "_"))
    return [value for value in dedupe(out) if len(value) >= 3]


def email_variants(email: str) -> list[str]:
    """Canonical aliases for Gmail/Proton-style addresses."""
    email = email.strip().casefold()
    if "@" not in email:
        return [email]
    local, domain = email.rsplit("@", 1)
    out = [email]
    if domain in ("gmail.com", "googlemail.com"):
        bare = local.split("+", 1)[0].replace(".", "")
        out.extend([f"{bare}@gmail.com", f"{bare}@googlemail.com", f"{local}@gmail.com"])
    elif domain in ("proton.me", "protonmail.com", "pm.me"):
        bare = local.split("+", 1)[0]
        out.extend([f"{bare}@proton.me", f"{bare}@protonmail.com", f"{bare}@pm.me"])
    return dedupe([value for value in out if value])
