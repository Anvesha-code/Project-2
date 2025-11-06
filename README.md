import os
from flask import Flask, request, jsonify

UPLOAD_FOLDER = "uploaded_logs"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)

@app.route("/upload", methods=["POST"])
def upload_file():
    if 'logfile' not in request.files:
        return jsonify({"error": "No file part in request"}), 400

    file = request.files['logfile']
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    local_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(local_path)

    # preview first 500 characters
    with open(local_path, "r") as f:
        print(f.read(500))

    return jsonify({"message": f"File uploaded and saved at {local_path}"})


if __name__ == "__main__":
    app.run(debug=True)








----------------------------------------
import requests

url = "http://127.0.0.1:5000/upload"
file_path = "C:/Users/des/Desktop/sample.log" # path to your log file

with open(file_path, "rb") as f:
    files = {"logfile": f}
    response = requests.post(url, files=files)

print(response.json())
