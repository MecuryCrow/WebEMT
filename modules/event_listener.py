import win32evtlog
import threading
import time
from typing import Callable, Optional, Dict, Any


class EventListener:
    def __init__(self, controller, log_name: str = "Application"):
        self.controller = controller
        self.log_name = log_name
        self.handle = None
        self.running = False
        self.thread = None

        # Symantec defaults
        self.event_id = 1090453555
        self.source = "Symantec AntiVirus"
        self.poll_interval = 1

    def start(self):
        if self.thread and self.thread.is_alive():
            print("[!] EventListener already running.")
            return

        self.thread = threading.Thread(target=self._listen_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.handle:
            win32evtlog.CloseEventLog(self.handle)
            self.handle = None
            print("[+] Event listener stopped.")

    def _listen_loop(self):
        try:
            self.handle = win32evtlog.OpenEventLog(None, self.log_name)
            flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

            # Skip old events
            while win32evtlog.ReadEventLog(self.handle, flags, 0):
                pass

            print(f"[+] Listening on Windows Event Log '{self.log_name}'...")
            self.running = True

            while self.running:
                events = win32evtlog.ReadEventLog(self.handle, flags, 0)
                if events:
                    for event in events:
                        if event.EventID == self.event_id and event.SourceName == self.source:
                            data = self._parse_event(event)
                            print("\n[!] SYMANTEC ALERT DETECTED!")
                            print(f"    Time:   {data['time_generated']}")
                            print(f"    Source: {data['source']}")
                            self.controller.handle_alert(data)
                time.sleep(self.poll_interval)

        finally:
            self.stop()

    def _parse_event(self, event) -> Dict[str, Any]:
        return {
            'event_id': event.EventID,
            'event_type_raw': event.EventType,
            'source': event.SourceName,
            'time_generated': event.TimeGenerated.Format(),
            'strings': event.StringInserts
        }
