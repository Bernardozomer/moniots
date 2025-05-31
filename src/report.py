import json
from dataclasses import asdict
from typing import TYPE_CHECKING

from jinja2 import Environment, FileSystemLoader

import models

if TYPE_CHECKING:
    from datetime import datetime as dt

TEMPLATE_DIR = "./templates"
REPORT_TEMPLATE = f"{TEMPLATE_DIR}/report.html.j2"


class MoniotsJSONEnconder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, models.Severity):
            return o.label
        return super().default(o)


def generate_json_report(results: dict[models.Device, list[models.Alert]]) -> str:
    """Generate a JSON report from the test results."""
    results_ = _results_to_dicts(results)
    return json.dumps(results_, indent=2, cls=MoniotsJSONEnconder)


def generate_html_report(
    results: dict[models.Device, list[models.Alert]], network: str, now: "dt"
) -> str:
    """Generate an HTML report from the test results."""
    env = Environment(loader=FileSystemLoader("."), extensions=["jinja2.ext.do"])
    env.globals["AlertSource"] = models.AlertSource
    tmpl = env.get_template(REPORT_TEMPLATE)
    results_ = _results_to_dicts(results)
    formatted_now = now.strftime("%Y-%m-%d %H:%M:%S")
    return tmpl.render(results=results_, network=network, now=formatted_now)


def _results_to_dicts(results: dict[models.Device, list[models.Alert]]) -> list[dict]:
    """Convert the results to a list of dictionaries for easier serialization."""
    return [
        {"device": asdict(d), "alerts": [asdict(a) for a in alerts]}
        for d, alerts in results.items()
    ]
