from __future__ import annotations

# Import submodules for their @app.command / @case_app.command /
# @source_app.command registrations. Order matters only for --help grouping.
from . import (  # noqa: F401, E402
    breach,
    cases,
    collect,
    company,
    evidence,
    integrations,
    interfaces,
    menu,
    ops,
    osint,
    output,
    query,
    websearch,
)
from ._app import app, run_cli

main = run_cli

__all__ = ["app", "main"]
