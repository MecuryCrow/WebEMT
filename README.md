# WebEMT

WebEMT is a tool designed to capture, analyze, and replay web traffic. It combines a Flask-based web interface with powerful background capture capabilities using `mitmproxy` and `dumpcap` (Wireshark).

## Features

-   **Web Interface**: A user-friendly dashboard to view capture status and browse captured URLs.
-   **Traffic Capture**:
    -   **MITM Capture**: Uses `mitmproxy` to intercept and log HTTP/HTTPS flows, including headers and bodies.
    -   **PCAP Capture**: Uses `dumpcap` for continuous rotating packet capture.
-   **Event Monitoring**: Listens for specific Windows Event Log entries (e.g., Symantec AntiVirus alerts) to trigger automatic data preservation.
-   **Automatic Reconstruction**: Automatically reconstructs web pages from captured JSON data upon alert trigger, allowing for offline viewing.

## Prerequisites

-   **Python 3.x**
-   **Wireshark**: Ensure `dumpcap` is in your system PATH.
-   **Windows OS**: Required for `pywin32` event log monitoring.

## Installation

1.  Clone the repository or download the source code.
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

2.  **Configure Proxy**: Set your browser or system proxy to `127.0.0.1:8080` to start capturing traffic.

3.  **Install CA Certificate**:
    -   With the proxy configured, visit [http://mitm.it](http://mitm.it) in your browser.
    -   Click the icon for your operating system (Windows) to download the certificate.
    -   Install the certificate into your **Trusted Root Certification Authorities** store to intercept HTTPS traffic without warnings.

4.  **Access the Dashboard**: Open `http://127.0.0.1:5000` in your browser to see the system status.

5.  **View Captured URLs**: Navigate to the `/urls` page (or click "View Captured URLs" on the homepage).
    -   This page now lists links to the **reconstructed offline versions** of the captured pages.
    -   Clicking a link will open the static HTML file with working images and styles (if reconstruction was successful).

6.  **Manual Reconstruction**: You can also trigger reconstruction for the latest capture manually by clicking "Reconstruct Latest Capture" on the homepage.

## Project Structure

-   `app.py`: Main Flask application entry point.
-   `modules/`: Contains core logic.
    -   `capture_controller.py`: Manages `mitmdump` and `dumpcap` processes.
    -   `event_listener.py`: Monitors Windows Event Logs.
    -   `mitm_addon.py`: `mitmproxy` script for logging HTTP flows.
    -   `reconstructor.py`: Logic for reconstructing web pages from captured data.
-   `templates/`: HTML templates for the web interface.
-   `static/`: Static assets (CSS, JS).
-   `data/`: Directory where captured data is stored.
    -   `output/`: JSON flows and PCAP files.
    -   `pcap_rotating/`: Temporary rotating PCAP buffer.