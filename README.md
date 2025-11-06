import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
import cgi

UPLOAD_FOLDER = "uploaded_logs"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

class SimpleUploadHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_type = self.headers.get('Content-Type')
        if not content_type:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"No Content-Type header")
            return
        
        ctype, pdict = cgi.parse_header(content_type)
        if ctype != 'multipart/form-data':
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Content-Type must be multipart/form-data")
            return

        pdict['boundary'] = bytes(pdict['boundary'], "utf-8")
        pdict['CONTENT-LENGTH'] = int(self.headers['Content-Length'])
        form = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ={'REQUEST_METHOD':'POST'}, keep_blank_values=True)

        if 'logfile' not in form:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"No file part in request")
            return

        file_item = form['logfile']
        filename = file_item.filename
        filepath = os.path.join(UPLOAD_FOLDER, filename)

        with open(filepath, 'wb') as f:
            f.write(file_item.file.read())

        # Respond success
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(f'{{"message":"File saved at {filepath}"}}'.encode())

# Run server
server_address = ("", 8000)
httpd = HTTPServer(server_address, SimpleUploadHandler)
print("Server running on http://127.0.0.1:8000")
httpd.serve_forever()
 ----------------------------------------------------------------------------------------------------------





 import requests

url = "http://127.0.0.1:8000"
file_path = "C:/Users/des/Desktop/sample.log"

with open(file_path, "rb") as f:
    files = {"logfile": f}  # must match server key
    response = requests.post(url, files=files)

print(response.text)
