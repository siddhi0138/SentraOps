from typing import Callable

from app.parsers import cloudtrail, firewall, generic, syslog, webserver, windows

PARSERS: dict[str, Callable] = {
    "windows": windows.parse,
    "syslog": syslog.parse,
    "webserver": webserver.parse,
    "firewall": firewall.parse,
    "cloudtrail": cloudtrail.parse,
    "generic": generic.parse,
}


def get_parser(source_type: str) -> Callable:
    try:
        return PARSERS[source_type]
    except KeyError:
        raise ValueError(f"Unknown source_type '{source_type}'. Supported: {sorted(PARSERS)}")
