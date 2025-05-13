from dataclasses import asdict
from datetime import datetime
import json

from jinja2 import Environment, FileSystemLoader


TEMPLATE_DIR = "./templates"
REPORT_TEMPLATE = f"{TEMPLATE_DIR}/report.html.j2"


def generate_json_report(results):
    """Generate a JSON report from the scan results."""
    results_dicts = [
        {**asdict(device), "findings": [asdict(f) for f in findings]}
        for device, findings in results.items()
    ]

    return json.dumps(results_dicts, indent=2)


def generate_html_report(results):
    """Generate an HTML report from the scan results using Jinja2 templates."""
    env = Environment(loader=FileSystemLoader("."), extensions=["jinja2.ext.do"])
    tmpl = env.get_template(REPORT_TEMPLATE)
    return tmpl.render(
        devices=results, now=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
