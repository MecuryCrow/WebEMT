import os
import json
import base64
import time
import mimetypes
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
    # Get page parameter for pagination
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Items per page for non-reconstructed URLs
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
    
    def is_real_webpage(url, mime_type):
        """
        Filter out non-webpage HTML content like ads, APIs, and iframes.
        Returns True only for actual user-facing web pages.
        """
        if 'html' not in mime_type.lower():
            return False
        
        url_lower = url.lower()
        
        # Exclude ad and tracking domains
        ad_domains = [
            'doubleclick', 'googlesyndication', 'googleadservices',
            'ads.', 'adservice', 'safeframe', 'bbloader', 'trustedframe',
            'advertising', 'googletagmanager', 'googletagservices'
        ]
        if any(domain in url_lower for domain in ad_domains):
            return False
        
        # Exclude API endpoints
        api_keywords = [
            '/api/', '/suggest', '/autocomplete', '/complete/search',
            '/xhr/', '/ajax/', '/graphql', '/rpc/', '/webapi/',
            'clients6.youtube.com'  # YouTube suggestion API
        ]
        if any(keyword in url_lower for keyword in api_keywords):
            return False
        
        # Exclude tracking and analytics
        tracking_keywords = [
            '/tracking/', '/analytics/', '/beacon/', '/pixel/',
            '/logstreamz', '/jserror', '/cspreport', '/gen_204'
        ]
        if any(keyword in url_lower for keyword in tracking_keywords):
            return False
        
        # Exclude embedded iframes and widgets
        iframe_keywords = [
            '/iframe/', '/embed/', '/widget/', '/frame/',
            'syncframe', 'hovercard'
        ]
        if any(keyword in url_lower for keyword in iframe_keywords):
            return False
        
        return True
    
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
            # Only show real web pages, not ads/APIs/iframes
            if is_real_webpage(u, mime_type):
                reconstructed_urls.append(url_item)
        else:
            non_reconstructed_urls.append(url_item)

    # Pagination for non-reconstructed URLs
    total_non_reconstructed = len(non_reconstructed_urls)
    total_pages = (total_non_reconstructed + per_page - 1) // per_page  # Ceiling division
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    paginated_non_reconstructed = non_reconstructed_urls[start_idx:end_idx]

    return render_template(
        "urls.html",
        reconstructed_urls=reconstructed_urls,
        non_reconstructed_urls=paginated_non_reconstructed,
        current_page=page,
        total_pages=total_pages,
        total_non_reconstructed=total_non_reconstructed
    )


# SERVE RECONSTRUCTED FILES
@app.route("/reconstructed/<path:filename>")
def serve_reconstructed(filename):
    reconstructed_dir = os.path.join(os.getcwd(), "data", "reconstructed")
    
    # Detect MIME type
    mime_type, _ = mimetypes.guess_type(filename)
    if mime_type is None:
        # Default to HTML for files without extension
        if not '.' in os.path.basename(filename):
            mime_type = 'text/html'
        else:
            mime_type = 'application/octet-stream'
    
    return send_from_directory(reconstructed_dir, filename, mimetype=mime_type)





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
