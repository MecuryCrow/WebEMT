from mitmproxy import http
import json
import base64
import time

class SimpleJsonLogger:
    def response(self, flow: http.HTTPFlow):
        try:
            entry = {
                "timestamp": time.time(),
                "client": str(flow.client_conn.address),
                "server": str(flow.server_conn.address),
                "url": flow.request.pretty_url,
                "method": flow.request.method,
                "req_headers": dict(flow.request.headers),
                "req_body": flow.request.get_text(strict=False),

                "status_code": flow.response.status_code,
                "resp_headers": dict(flow.response.headers),
                "mime_type": flow.response.headers.get("Content-Type", ""),
                "resp_body_b64": base64.b64encode(
                    flow.response.raw_content or b""
                ).decode()
            }

            print(json.dumps(entry), flush=True)

        except Exception as e:
            print(json.dumps({"error": str(e)}), flush=True)


addons = [
    SimpleJsonLogger()
]
