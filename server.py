"""
Local HTTP Server and REST API for Aviation Cybersecurity Risk Assessment Dashboard
"""

import http.server
import socketserver
import os
import json
import urllib.parse
from risk_engine import run_algorithm_1, calculate_numeric_risk, categorize_tolerability, convert_to_five_point_scale, PAPER_THREATS_DATASET, CyberThreat

PORT = 8088
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

class AviationRiskHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/threats":
            summary = run_algorithm_1()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(summary, indent=2).encode("utf-8"))
        elif parsed.path == "/api/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "healthy", "service": "Aviation Cybersecurity Engine"}).encode("utf-8"))
        else:
            super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/evaluate":
            content_length = int(self.headers.get("Content-Length", 0))
            post_body = self.rfile.read(content_length)
            try:
                data = json.loads(post_body.decode("utf-8"))
                likelihood = float(data.get("likelihood", 3.0))
                impact = float(data.get("impact", 3.0))
                
                # Algorithm 1 Execution
                r = calculate_numeric_risk(likelihood, impact)
                tolerability = categorize_tolerability(r)
                scale_5 = convert_to_five_point_scale(r)
                
                resp = {
                    "likelihood": likelihood,
                    "impact": impact,
                    "numeric_risk": r,
                    "tolerability": tolerability,
                    "five_point_scale": scale_5,
                    "status": "success"
                }
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps(resp).encode("utf-8"))
            except Exception as e:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

def run_server():
    os.chdir(DIRECTORY)
    with socketserver.TCPServer(("", PORT), AviationRiskHandler) as httpd:
        print(f"================================================================")
        print(f" Civil Aviation Cybersecurity Risk Assessment Dashboard Server ")
        print(f" Compliant with IEEE Access 2021 & ICAO Security Risk Standards ")
        print(f" Serving live at: http://localhost:{PORT}")
        print(f"================================================================")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server.")

if __name__ == "__main__":
    run_server()
