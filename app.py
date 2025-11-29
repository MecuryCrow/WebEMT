import os
import json
import base64
import time
from flask import Flask, render_template, send_file, request, send_from_directory
from modules.capture_controller import CaptureController
from modules.event_listener import EventListener
from modules.reconstructor import Reconstructor

app = Flask(
    __name__,
    template_folder="templates",
    static_folder="static"
)

# Global controller + listener
controller = CaptureController()
listener = EventListener(controller)


# HOME PAGE
@app.route("/")
def home():
    status = {
        "mitm_running": controller.mitm_proc is not None,
        "dumpcap_running": controller.dumpcap_proc is not None,
        "alert_active": controller.alert_active,
        "alert_timestamp": controller.alert_timestamp,
        "future_capture_end": controller.future_capture_end
    }
    return render_template("homepage.html", status=status)


# URL LIST PAGE
@app.route("/urls")
def urls_page():
    output_dir = os.path.join("data", "output", "web")
    if not os.path.isdir(output_dir):
        return render_template("urls.html", urls=None)

    json_files = sorted(
        [f for f in os.listdir(output_dir) if f.endswith(".json")],
        reverse=True
    )

    if not json_files:
        return render_template("urls.html", urls=None)

    latest = json_files[0]
    with open(os.path.join(output_dir, latest), "r", encoding="utf-8") as f:
        flows = json.load(f)

    # Identify reconstructible URLs (those with a response body)
    reconstructible_urls = set()
    for flow in flows:
        if flow.get("url") and flow.get("resp_body_b64"):
            reconstructible_urls.add(flow["url"])

    all_urls = set(flow.get("url") for flow in flows if "url" in flow)
    
    # Sort: Reconstructible first (False < True), then alphabetical
    sorted_urls = sorted(all_urls, key=lambda u: (u not in reconstructible_urls, u))

    # Calculate reconstructed paths and check file existence
    reconstructor = Reconstructor("dummy.json", outputdir=os.path.join("data", "reconstructed"))
    
    reconstructed_urls = []
    non_reconstructed_urls = []
    
    for u in sorted_urls:
        flow = next((f for f in flows if f.get("url") == u), None)
        mime_type = flow.get("mime_type", "") if flow else ""
        
        # Calculate local path
        local_path = reconstructor.create_local_path(u, mime_type)
        
        # Check if file actually exists
        file_exists = local_path.exists() if local_path else False
        
        try:
            rel_path = local_path.relative_to(reconstructor.outputdir)
            link = f"/reconstructed/{rel_path}".replace("\\", "/")
        except ValueError:
            link = "#"

        url_item = {
            "original": u,
            "link": link,
            "mime_type": mime_type
        }
        
        if file_exists:
            reconstructed_urls.append(url_item)
        else:
            non_reconstructed_urls.append(url_item)

    return render_template(
        "urls.html",
        reconstructed_urls=reconstructed_urls,
        non_reconstructed_urls=non_reconstructed_urls
    )


# SERVE RECONSTRUCTED FILES
@app.route("/reconstructed/<path:filename>")
def serve_reconstructed(filename):
    reconstructed_dir = os.path.join(os.getcwd(), "data", "reconstructed")
    return send_from_directory(reconstructed_dir, filename)





# DOWNLOAD LATEST PCAP
@app.route("/download/pcap")
def download_pcap():
    output_dir = os.path.join("data", "output", "pcap")

    pcap_files = sorted(
        [
            f for f in os.listdir(output_dir)
            if f.endswith(".pcap") or f.endswith(".pcapng")
        ],
        reverse=True
    )

    if not pcap_files:
        return "No PCAP files found."

    latest = os.path.join(output_dir, pcap_files[0])
    return send_file(latest, as_attachment=True)


# MAIN ENTRY POINT
if __name__ == "__main__":
    print("[+] Starting CaptureController...")
    controller.start_all()

    print("[+] Starting EventListener...")
    listener.start()

    # Critical: disable reloader (otherwise app runs twice)
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        use_reloader=False
    )
