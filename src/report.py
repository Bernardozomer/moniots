import json
from dataclasses import asdict
from datetime import datetime

from jinja2 import Environment, FileSystemLoader


TEMPLATE_DIR = "./templates"
REPORT_TEMPLATE = f"{TEMPLATE_DIR}/report.html.j2"


def generate_json_report(results):
    results = results_to_dict(results)
    return json.dumps(results, indent=2)


def generate_html_report(results, network, now):
    env = Environment(loader=FileSystemLoader("."), extensions=["jinja2.ext.do"])
    tmpl = env.get_template(REPORT_TEMPLATE)
    results = results_to_dict(results)
    formatted_now = now.strftime("%Y-%m-%d %H:%M:%S")
    return tmpl.render(results=results, network=network, now=formatted_now)


def results_to_dict(results):
    return [
        {"device": asdict(d), "alerts": [asdict(a) for a in alerts]}
        for d, alerts in results.items()
    ]
