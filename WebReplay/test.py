import win32evtlogutil

EVENT_ID = 1090453555
SOURCE = "Symantec AntiVirus"

win32evtlogutil.ReportEvent(
    SOURCE,
    EVENT_ID,
    eventType=1,  # 1 = ERROR, 2 = WARNING, 4 = INFORMATION
    strings=["Test Symantec alert from Python"]
)

print("Test event injected.")
