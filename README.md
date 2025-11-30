# Web Replay

Web Replay is a tool designed to capture, analyze, and replay web traffic. It combines a Flask-based web interface with powerful background capture capabilities using `mitmproxy` and `dumpcap` (Wireshark).

## Features

-   **Web Interface**: A user-friendly dashboard to view capture status and browse reconstructed web pages
-   **Traffic Capture**:
    -   **MITM Capture**: Uses `mitmproxy` to intercept and log HTTP/HTTPS flows, including headers and bodies
    -   **PCAP Capture**: Uses `dumpcap` for continuous rotating packet capture
-   **Event Monitoring**: Listens for specific Windows Event Log entries to trigger automatic data preservation
-   **Web Page Reconstruction**: Automatically reconstructs web pages from captured JSON data with full decompression support (gzip, Brotli, deflate)
-   **Intelligent Filtering**: Displays only user-facing web pages, filtering out ads, APIs, tracking pixels, and technical HTML responses
-   **Pagination**: Efficiently browse through large numbers of captured URLs with paginated views

## Prerequisites

-   **Python 3.x**
-   **Wireshark**: Ensure `dumpcap` is in your system PATH
-   **Windows OS**: Required for `pywin32` event log monitoring

## Installation

1.  Clone the repository or download the source code
2.  Install the required Python dependencies:

    ```bash
    pip install -r requirements.txt
    ```

## Usage

1.  Start the application:

    ```bash
    python app.py
    ```

    This will launch:
    -   The Flask web server on `http://127.0.0.1:5000`
    -   `mitmdump` on port 8080 (listening for proxy traffic)
    -   `dumpcap` for background packet capture
    -   The Windows Event Log listener

2.  **Configure Proxy**: Set your browser or system proxy to `127.0.0.1:8080` to start capturing traffic

3.  **Install CA Certificate**:
    -   With the proxy configured, visit [http://mitm.it](http://mitm.it) in your browser
    -   Click the icon for your operating system (Windows) to download the certificate
    -   Install the certificate into your **Trusted Root Certification Authorities** store to intercept HTTPS traffic without warnings

4.  **Access the Dashboard**: Open `http://127.0.0.1:5000` in your browser to see the system status

5.  **View Reconstructed Pages**: Navigate to the `/urls` page (or click "View Captured URLs" on the homepage)
    -   **✓ Reconstructed Pages**: Shows only actual user-facing web pages (excludes ads, APIs, tracking, iframes)
    -   **⊗ Non-Reconstructed URLs**: All other captured traffic (paginated, 10 items per page)
    -   **[CACHED]** tag indicates pages that were served from browser cache (304 status)

6.  **Manual Reconstruction**: Trigger reconstruction for the latest capture by clicking "Reconstruct Latest Capture" on the homepage

## Decompression Support

The reconstructor now supports:
- **Brotli (br)**: Modern compression used by sites like YouTube, Google
- **Gzip**: Traditional HTTP compression
- **Deflate**: Alternative HTTP compression

## Caching Behavior

Web pages served from browser cache (304 Not Modified) appear in the index with a `[CACHED]` tag but cannot be reconstructed since no content was captured. To capture these pages:
- Clear your browser cache before capturing
- Use incognito/private browsing mode

## Project Structure

-   `app.py`: Main Flask application entry point
-   `modules/`: Contains core logic
    -   `capture_controller.py`: Manages `mitmdump` and `dumpcap` processes
    -   `event_listener.py`: Monitors Windows Event Logs
    -   `mitm_addon.py`: `mitmproxy` script for logging HTTP flows
    -   `reconstructor.py`: Logic for reconstructing web pages from captured data
-   `templates/`: HTML templates for the web interface
-   `static/`: Static assets (CSS, JS)
-   `data/`: Directory where captured data is stored
    -   `output/`: JSON flows and PCAP files
    -   `reconstructed/`: Reconstructed static web pages
    -   `pcap_rotating/`: Temporary rotating PCAP buffer

## Recent Improvements

- ✅ Fixed garbled text issue with Brotli/deflate compressed pages
- ✅ Intelligent webpage filtering (excludes ads, APIs, iframes, tracking)
- ✅ Pagination for non-reconstructed URLs (10 per page)
- ✅ Cached page indicator for 304 responses
- ✅ URL truncation with ellipsis for better table display
- ✅ Red color coding for non-reconstructed URLs section