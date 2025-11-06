upload.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Upload and Download Log File</title>
</head>
<body>
    <h2>Upload a Log File</h2>

    <form action="/upload" method="post" enctype="multipart/form-data">
        <input type="file" name="file" required>
        <button type="submit">Upload</button>
    </form>

    <p>After upload, you’ll get a download button automatically.</p>
</body>
</html>


main.py


from fastapi import FastAPI, UploadFile, File, Request
from fastapi.responses import HTMLResponse, FileResponse
import os

app = FastAPI()

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.get("/", response_class=HTMLResponse)
def upload_form():
    html_file = os.path.join(os.path.dirname(__file__), "upload.html")

    if not os.path.exists(html_file):
        return HTMLResponse("<h2>upload.html not found in this folder</h2>", status_code=404)

    with open(html_file, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())


@app.post("/upload", response_class=HTMLResponse)
async def upload_file(request: Request, file: UploadFile = File(...)):
    file_path = os.path.join(UPLOAD_DIR, file.filename)
    with open(file_path, "wb") as f:
        f.write(await file.read())

    download_link = f"/download/{file.filename}"

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head><title>Upload Successful</title></head>
    <body>
        <h2>✅ File uploaded successfully!</h2>
        <p>Filename: <b>{file.filename}</b></p>
        <a href="{download_link}" download>
            <button>⬇️ Download File</button>
        </a>
        <br><br>
        <a href="/">Upload another file</a>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


@app.get("/download/{filename}")
async def download_file(filename: str):
    file_path = os.path.join(UPLOAD_DIR, filename)
    if os.path.exists(file_path):
        return FileResponse(file_path, media_type="application/octet-stream", filename=filename)

uvicorn main:app –reload

 http://127.0.0.1:8000 
