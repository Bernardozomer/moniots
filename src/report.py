import json
from dataclasses import asdict
from datetime import datetime

from jinja2 import Environment, FileSystemLoader


TEMPLATE_DIR = "./templates"
REPORT_TEMPLATE = f"{TEMPLATE_DIR}/report.html.j2"


def generate_json_report(results):
    ser_res = serialize_results(results)
    return json.dumps(ser_res, indent=2)


def generate_html_report(results, network, now):
    env = Environment(loader=FileSystemLoader("."), extensions=["jinja2.ext.do"])
    tmpl = env.get_template(REPORT_TEMPLATE)
    devices = serialize_results(results)
    formatted_now = now.strftime("%Y-%m-%d %H:%M:%S")
    return tmpl.render(devices=devices, network=network, now=formatted_now)


def serialize_results(results):
    ser = []

    for device, sections in results.items():
        entry = asdict(device)  # all the Device fields
        entry["credentials"] = [asdict(f) for f in sections["credentials"]]
        entry["zap_alerts"] = [asdict(z) for z in sections["zap_alerts"]]
        ser.append(entry)
    return ser
