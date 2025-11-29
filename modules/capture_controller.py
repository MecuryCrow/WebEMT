import subprocess
import threading
import json
import time
from collections import deque
import os
import signal
import glob
import shutil
import sys
from modules.reconstructor import Reconstructor


class CaptureController:
    def __init__(self, buffer_minutes=20):

        # Output folders
        self.output_root = os.path.join(os.getcwd(), "data", "output")
        self.output_web = os.path.join(self.output_root, "web")
        self.output_pcap = os.path.join(self.output_root, "pcap")

        os.makedirs(self.output_web, exist_ok=True)
        os.makedirs(self.output_pcap, exist_ok=True)

        # HTTP FLOW BUFFER
        self.buffer = deque(maxlen=buffer_minutes * 2000)
        self.new_flows = deque()

        # MITM logging
        self.mitm_proc = None
        self.reader_thread = None

        # Rotating PCAP temp directory (internal storage)
        self.pcap_dir = os.path.join(os.getcwd(), "data", "pcap_rotating")
        os.makedirs(self.pcap_dir, exist_ok=True)

        self.dumpcap_proc = None

        # Path to mitm addon
        self.addon_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "mitm_addon.py"
        )

        # Alert state
        self.alert_active = False
        self.alert_timestamp = None
        self.future_capture_end = None

    # Start MITMDUMP (always-on)
    def start_mitmdump(self):

        # Prevent duplicate processes
        if self.mitm_proc and self.mitm_proc.poll() is None:
            print("[!] mitmdump already running.")
            return

        cmd = [
            "mitmdump",
            "-s", self.addon_path,
            "--listen-host", "127.0.0.1",
            "--listen-port", "8080",
            "--ssl-insecure",
            "--set", "console_eventlog_verbosity=info",
            "--set", "termlog_verbosity=info",
            "--set", "flow_detail=2"
        ]

        print("[+] Launching mitmdump...")

        try:
            # Critical: force unbuffered output
            self.mitm_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,      # merge output
                text=True,
                bufsize=1,                     # line-buffer
                env={**os.environ, "PYTHONUNBUFFERED": "1"}
            )
        except FileNotFoundError:
            print("[ERROR] mitmdump not found in PATH!")
            sys.exit(1)

        # Reader thread (non-blocking)
        self.reader_thread = threading.Thread(
            target=self._reader_loop,
            daemon=True
        )
        self.reader_thread.start()

        print("[+] mitmdump running on 127.0.0.1:8080")

    def stop_mitmdump(self):
        if not self.mitm_proc:
            return

        print("[+] Stopping mitmdump...")
        try:
            self.mitm_proc.send_signal(signal.SIGTERM)
        except:
            pass

        try:
            self.mitm_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.mitm_proc.kill()

        self.mitm_proc = None

    # MITMDUMP stdout reader
    def _reader_loop(self):
        print("[+] mitmdump reader started.")
        for line in self.mitm_proc.stdout:
            line = line.strip()
            if not line:
                continue

            # Debugging (optional):
            # print("[mitmdump RAW]", line)

            try:
                obj = json.loads(line)
                obj["timestamp"] = time.time()
                self.buffer.append(obj)
                self.new_flows.append(obj)
            except json.JSONDecodeError:
                # mitmdump logs or errors — ignore non-JSON lines
                continue

        print("[!] mitmdump reader stopped.")

    # Start dumpcap rotating capture
    def start_dumpcap(self, iface="Ethernet"):

        if self.dumpcap_proc:
            print("[!] dumpcap already running.")
            return

        print("[+] Starting dumpcap rotating pcap capture...")

        os.makedirs(self.pcap_dir, exist_ok=True)

        cmd = [
            "dumpcap",
            "-i", iface,
            "-b", "files:20",
            "-b", "duration:60",
            "-w", os.path.join(self.pcap_dir, "cap.pcapng")
        ]

        try:
            self.dumpcap_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except FileNotFoundError:
            print("[ERROR] dumpcap not found in PATH!")
            print("[ERROR] dumpcap not found in PATH! Continuing without packet capture.")
            self.dumpcap_proc = None

    def stop_dumpcap(self):
        if self.dumpcap_proc:
            print("[+] Stopping dumpcap...")
            self.dumpcap_proc.terminate()
            self.dumpcap_proc.wait(timeout=5)
            self.dumpcap_proc = None

    # Extract PCAP window
    def extract_pcap_window(self, out_file):
        pcaps = sorted(glob.glob(f"{self.pcap_dir}/*.pcap*"))
        last_10 = pcaps[-10:] if len(pcaps) >= 10 else pcaps

        print(f"[+] Merging past 10 minutes of pcaps → {out_file}")

        with open(out_file, "wb") as outfile:
            for p in last_10:
                with open(p, "rb") as f:
                    shutil.copyfileobj(f, outfile)

    # Extract HTTP window
    def extract_http_window(self, window_minutes, out_file):
        cutoff = time.time() - (window_minutes * 60)
        flows = [x for x in self.buffer if x["timestamp"] >= cutoff]

        print(f"[+] Writing {len(flows)} HTTP flows → {out_file}")

        with open(out_file, "w") as f:
            json.dump(flows, f, indent=2)

    # On ALERT → extract past + future windows
    def handle_alert(self, event):
        print("[!] ALERT -> Extracting past+future 10-minute window")

        timestamp = int(time.time())

        http_out = os.path.join(self.output_web, f"http_past10_{timestamp}.json")
        pcap_out = os.path.join(self.output_pcap, f"pcap_past10_{timestamp}.pcapng")

        self.extract_http_window(10, http_out)
        self.extract_pcap_window(pcap_out)

        # Auto-reconstruct past window
        self._run_reconstruction(http_out)

        # Update state
        self.alert_active = True
        self.alert_timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))
        self.future_capture_end = timestamp + (10 * 60)

        print("[+] Now capturing next 10 minutes...")
        threading.Timer(60 * 10, self._capture_future_window).start()

    def _capture_future_window(self):
        print("[+] 10 minutes passed → dumping future window")

        timestamp = int(time.time())

        http_out = os.path.join(self.output_web, f"http_future10_{timestamp}.json")
        pcap_out = os.path.join(self.output_pcap, f"pcap_future10_{timestamp}.pcapng")

        self.extract_http_window(10, http_out)
        self.extract_http_window(10, http_out)
        self.extract_pcap_window(pcap_out)

        # Auto-reconstruct future window
        self._run_reconstruction(http_out)

        print("[+] Capture complete!")

    def _run_reconstruction(self, json_path):
        def run():
            print(f"[+] Auto-reconstructing: {json_path}")
            try:
                reconstructed_dir = os.path.join(os.getcwd(), "data", "reconstructed")
                r = Reconstructor(json_path, outputdir=reconstructed_dir)
                if r.load_data():
                    r.reconstruct()
                    r.create_index_page()
                    print(f"[+] Reconstruction complete for {json_path}")
            except Exception as e:
                print(f"[ERROR] Auto-reconstruction failed: {e}")

        threading.Thread(target=run, daemon=True).start()

    # Start everything together
    def start_all(self):
        self.start_mitmdump()
        self.start_dumpcap()
