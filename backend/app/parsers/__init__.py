from typing import Callable

from app.parsers import cloudtrail, firewall, generic, syslog, webserver, windows

PARSERS: dict[str, Callable] = {
    "windows": windows.parse,
    "syslog": syslog.parse,
    "webserver": webserver.parse,
    "firewall": firewall.parse,
    "cloudtrail": cloudtrail.parse,
    "generic": generic.parse,
    # BAS (app/bas.py) already emits normalized events in exactly generic's
    # shape - a distinct source_type key (not reusing "generic" itself)
    # just so ingested events are visibly tagged as real-technique-execution
    # output rather than an arbitrary generic upload.
    "bas": generic.parse,
}


def get_parser(source_type: str) -> Callable:
    try:
        return PARSERS[source_type]
    except KeyError:
        raise ValueError(f"Unknown source_type '{source_type}'. Supported: {sorted(PARSERS)}")
