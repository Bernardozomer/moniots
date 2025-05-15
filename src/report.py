import json
from dataclasses import asdict
from datetime import datetime

from jinja2 import Environment, FileSystemLoader


TEMPLATE_DIR = "./templates"
REPORT_TEMPLATE = f"{TEMPLATE_DIR}/report.html.j2"


def generate_json_report(results):
    ser_res = serialize_results(results)
    return json.dumps(ser_res, indent=2)


def generate_html_report(results):
    """Generate an HTML report from the scan results using Jinja2 templates."""
    env = Environment(loader=FileSystemLoader("."), extensions=["jinja2.ext.do"])
    tmpl = env.get_template(REPORT_TEMPLATE)
    ser_res = serialize_results(results)
    return tmpl.render(
        devices=ser_res, now=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )


def serialize_results(results):
    ser_res = []

    for device, sections in results.items():
        entry = asdict(device)

        entry["findings"] = {
            "credentials": [asdict(f) for f in sections["credentials"]],
            "zap_findings": [asdict(z) for z in sections["zap_alerts"]],
        }

        ser_res.append(entry)

    return ser_res
