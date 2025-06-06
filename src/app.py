import argparse
import os
import threading
import traceback
import uuid
from datetime import datetime as dt

from flask import Flask, render_template, request, jsonify, url_for, send_from_directory
from moniots_scanner import models as moniots_models_module
from moniots_scanner import report as moniots_report_module
from moniots_scanner.main import orchestrate_scan

# Flask application setup.
app = Flask(
    __name__,
    static_folder=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "static"
    ),
    template_folder=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "templates"
    ),
)

# TODO: change for production.
app.config["SECRET_KEY"] = os.environ.get(
    "FLASK_SECRET_KEY", "dev_secret_key_for_moniots_ui"
)

# In-memory storage for scan status and results.
# TODO: consider a database or a more robust caching solution.
scans_db = {}

# HTML reports directory path.
REPORTS_DIR_BASE_NAME = "reports"
# Avoid type errors by ensuring the static folder is set correctly.
assert app.static_folder is not None
REPORTS_DIR_PATH = os.path.join(app.static_folder, REPORTS_DIR_BASE_NAME)

if not os.path.exists(REPORTS_DIR_PATH):
    try:
        os.makedirs(REPORTS_DIR_PATH)
        print(f"Created reports directory: {REPORTS_DIR_PATH}")
    except OSError as e:
        print(f"Could not create reports directory {REPORTS_DIR_PATH}: {e}")
        exit(1)


# Flask routes.
@app.route("/")
def index_route():
    """Serves the main page: form for new scan & list of past/ongoing scans."""
    severity_choices = [s.label.lower() for s in moniots_models_module.Severity]

    # Sort scans by start time (most recent first) for display
    sorted_scans_list = sorted(
        scans_db.items(),
        key=lambda item: item[1].get("start_time", "1970-01-01 00:00:00"),
        reverse=True,
    )

    return render_template(
        "index.html.j2", severity_choices=severity_choices, scans_list=sorted_scans_list
    )


@app.route("/scan", methods=["POST"])
def start_scan_route():
    """Receives scan parameters and starts the scan in a new thread."""
    network_range = request.form.get("network_range", "").strip()
    severity_label = request.form.get("severity", "").strip()
    local_zap_proxy = request.form.get("local_zap_proxy", "").strip()
    zap_api_key = request.form.get("zap_api_key", "").strip()
    nvd_api_key = request.form.get("nvd_api_key", "").strip()

    if not network_range or not local_zap_proxy or not zap_api_key or not nvd_api_key:
        return jsonify({"error": "Missing parameters"}), 400
    if not severity_label:
        severity_label = moniots_models_module.Severity.MEDIUM.label.lower()

    scan_id = str(uuid.uuid4())

    scans_db[scan_id] = {
        "status": "queued",
        "network": network_range,
        "severity": severity_label,
        "start_time": dt.now().strftime("%Y-%m-%d %H:%M:%S"),
        "report_html_filename": None,
        "error_message": None,
    }

    print(f"Queued scan {scan_id} for {network_range}")

    scan_thread = threading.Thread(
        target=run_moniots,
        args=(
            scan_id,
            network_range,
            severity_label,
            nvd_api_key,
            zap_api_key,
            local_zap_proxy,
        ),
    )

    # Allows main app to exit even if threads are running.
    scan_thread.daemon = True
    scan_thread.start()

    return jsonify({"message": "Scan queued successfully.", "scan_id": scan_id})


@app.route("/status/<scan_id>", methods=["GET"])
def scan_status_route(scan_id):
    """Returns the status and basic info of a given scan."""
    scan_info = scans_db.get(scan_id)
    if not scan_info:
        return jsonify({"error": "Scan ID not found."}), 404

    response_data = {
        "scan_id": scan_id,
        "status": scan_info["status"],
        "network": scan_info.get("network"),
        "severity": scan_info.get("severity"),
        "start_time": scan_info.get("start_time"),
        "error_message": scan_info.get("error_message"),
    }

    if scan_info.get("report_html_filename"):
        # URL for the static HTML report.
        response_data["report_html_url"] = url_for(
            # Endpoint for the static folder.
            "static",
            filename=f'{REPORTS_DIR_BASE_NAME}/{scan_info["report_html_filename"]}',
        )
    return jsonify(response_data)


@app.route("/report/<scan_id>")
def view_html_report_route(scan_id):
    """Serves the static HTML report file for a completed scan."""
    scan_info = scans_db.get(scan_id)
    if not scan_info:
        return "Scan ID not found.", 404

    if scan_info["status"] == "error":
        return (
            f"Scan failed: {scan_info.get('error_message', 'Unknown error')}. No report available.",
            500,
        )

    report_filename = scan_info.get("report_html_filename")
    if not report_filename or scan_info["status"] != "complete":
        return (
            "HTML report is not yet available or scan is not complete. Please check status or try again later.",
            404,
        )

    # Serve the file from the 'static/reports' directory
    # Avoid type errors by ensuring the static folder is set correctly.
    assert app.static_folder is not None
    directory_to_serve_from = os.path.join(app.static_folder, REPORTS_DIR_BASE_NAME)

    print(
        f"Attempting to serve report: Directory='{directory_to_serve_from}', Filename='{report_filename}'"
    )

    try:
        return send_from_directory(directory_to_serve_from, report_filename)
    except FileNotFoundError:
        print(
            f"File not found for report: {os.path.join(directory_to_serve_from, report_filename)}"
        )
        return (
            "Report file not found on server. This could be due to an error during report generation or a file system issue.",
            404,
        )


def run_moniots(
    scan_id, network_range, severity_label, nvd_api_key, zap_api_key, local_zap_proxy
):
    """Runs the Moniots scan and updates the scans_db. Intended to be run in a separate thread.
    Generates an HTML report for later serving of the web app.
    """
    print(f"[{scan_id}] Background scan thread started")
    scans_db[scan_id]["status"] = "running"

    try:
        # Create an 'args' object similar to what argparse would produce.
        mock_args = argparse.Namespace()
        mock_args.network = network_range
        mock_args.severity = severity_label
        mock_args.nvd_api_key = nvd_api_key if nvd_api_key else None
        mock_args.zap_api_key = zap_api_key if zap_api_key else None
        mock_args.local_zap_proxy = local_zap_proxy if local_zap_proxy else None
        mock_args.json_out = None
        mock_args.html_out = None

        # Run Moniots.
        print(f"[{scan_id}] Calling Moniots with args: {vars(mock_args)}")
        results_from_scanner = orchestrate_scan(mock_args)
        print(f"[{scan_id}] Scan completed. Generating HTML report...")

        # Generate and save HTML report.
        # Check if directory exists and is a directory.
        if not os.path.isdir(REPORTS_DIR_PATH):
            print(
                f"[{scan_id}] ERROR: Reports directory {REPORTS_DIR_PATH} is not accessible. Cannot save HTML report."
            )

            scans_db[scan_id]["error_message"] = (
                scans_db[scan_id].get("error_message", "")
                + "; Reports directory missing"
            ).strip("; ")
        else:
            html_report_content = moniots_report_module.generate_html_report(
                results_from_scanner,
                network_range,
                dt.now(),
            )

            report_filename = f"moniots_report_{scan_id}.html"
            report_filepath = os.path.join(REPORTS_DIR_PATH, report_filename)

            try:
                with open(report_filepath, "w", encoding="utf-8") as fp:
                    fp.write(html_report_content)

                scans_db[scan_id]["report_html_filename"] = report_filename
                print(f"[{scan_id}] HTML report saved to: {report_filepath}")
            except IOError as e:
                print(f"[{scan_id}] Error saving HTML report {report_filepath}: {e}")

                scans_db[scan_id]["error_message"] = (
                    scans_db[scan_id].get("error_message", "")
                    + f"; Failed to save HTML report: {e}"
                ).strip("; ")

        scans_db[scan_id]["status"] = "complete"
        print(f"[{scan_id}] Scan processing complete.")

    except Exception as e:
        print(f"[{scan_id}] EXCEPTION during scan execution: {str(e)}")
        traceback.print_exc()
        scans_db[scan_id]["status"] = "error"
        scans_db[scan_id]["error_message"] = str(e)


if __name__ == "__main__":
    print(f"Flask Application Root Path: {os.path.abspath(os.path.dirname(__file__))}")
    print(f"Flask Static Folder (resolved): {os.path.abspath(app.static_folder)}")
    print(
        f"Reports will be saved in and served from: {os.path.abspath(REPORTS_DIR_PATH)}"
    )
    template_folder_path = (
        app.template_folder if app.template_folder is not None else ""
    )
    print(f"Flask Template Folder (resolved): {os.path.abspath(template_folder_path)}")

    app.run(debug=True, host="0.0.0.0", port=5001, use_reloader=False)
