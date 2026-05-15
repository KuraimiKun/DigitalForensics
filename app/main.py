from __future__ import annotations

import shutil
import uuid
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .analyzer import analyze_files, write_reports


BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATE_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
RUNTIME_DIR = BASE_DIR / "runtime"
UPLOAD_DIR = RUNTIME_DIR / "uploads"
REPORT_DIR = RUNTIME_DIR / "reports"

MAX_UPLOAD_BYTES = 75 * 1024 * 1024
MAX_UPLOAD_FILES = 20

for directory in (UPLOAD_DIR, REPORT_DIR):
    directory.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="PDF Forensics Analyzer", version="1.0.0")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATE_DIR)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "rows": [],
            "summary": None,
            "report_id": None,
            "error": None,
        },
    )


@app.post("/analyze", response_class=HTMLResponse)
async def analyze(
    request: Request,
    pdf_files: Annotated[list[UploadFile], File(description="One or more PDFs to analyze")],
    baseline_pdf: Annotated[UploadFile | None, File(description="Optional baseline PDF")] = None,
    pdf_password: Annotated[str, Form(description="Optional password for encrypted PDFs")] = "",
) -> HTMLResponse:
    report_id = uuid.uuid4().hex
    upload_session = UPLOAD_DIR / report_id
    report_session = REPORT_DIR / report_id
    upload_session.mkdir(parents=True, exist_ok=True)
    report_session.mkdir(parents=True, exist_ok=True)

    try:
        saved_pdfs = await save_uploads(pdf_files, upload_session, required=True)
        if not saved_pdfs:
            raise ValueError("Upload at least one PDF file.")

        baseline_path = None
        if baseline_pdf and baseline_pdf.filename:
            baseline_saved = await save_uploads([baseline_pdf], upload_session / "baseline", required=False)
            baseline_path = baseline_saved[0] if baseline_saved else None

        password = pdf_password.strip() or None
        rows, summary = analyze_files(saved_pdfs, baseline_path, report_session, password=password)
        write_reports(rows, summary, report_session)

        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "rows": rows,
                "summary": summary,
                "report_id": report_id,
                "error": None,
            },
        )
    except Exception as exc:
        shutil.rmtree(upload_session, ignore_errors=True)
        shutil.rmtree(report_session, ignore_errors=True)
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "rows": [],
                "summary": None,
                "report_id": None,
                "error": str(exc),
            },
            status_code=400,
        )


@app.get("/download/{report_id}/{file_type}")
async def download_report(report_id: str, file_type: str) -> FileResponse:
    session_dir = safe_report_dir(report_id)
    downloads = {
        "csv": ("pdf_forensics_report.csv", "text/csv"),
        "xlsx": (
            "pdf_forensics_report.xlsx",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ),
        "json": ("pdf_forensics_report.json", "application/json"),
        "pdf": ("pdf_forensics_report.pdf", "application/pdf"),
        "zip": ("pdf_forensics_bundle.zip", "application/zip"),
    }
    if file_type not in downloads:
        raise HTTPException(status_code=404, detail="Unsupported report type")

    filename, media_type = downloads[file_type]
    path = session_dir / filename
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(path, media_type=media_type, filename=path.name)


@app.get("/annotated/{report_id}/{filename}")
async def annotated_pdf(report_id: str, filename: str) -> FileResponse:
    session_dir = safe_report_dir(report_id)
    safe_name = sanitize_filename(filename)
    path = session_dir / "annotated" / safe_name
    if not path.exists() or path.suffix.lower() != ".pdf":
        raise HTTPException(status_code=404, detail="Annotated PDF not found")
    return FileResponse(path, media_type="application/pdf", filename=path.name)


@app.get("/visual/{report_id}/{filename}")
async def visual_diff(report_id: str, filename: str) -> FileResponse:
    session_dir = safe_report_dir(report_id)
    safe_name = sanitize_filename(filename)
    path = session_dir / "visual_diffs" / safe_name
    if not path.exists() or path.suffix.lower() != ".png":
        raise HTTPException(status_code=404, detail="Visual diff not found")
    return FileResponse(path, media_type="image/png", filename=path.name)


async def save_uploads(files: list[UploadFile], destination: Path, required: bool) -> list[Path]:
    destination.mkdir(parents=True, exist_ok=True)
    saved: list[Path] = []
    if len(files) > MAX_UPLOAD_FILES:
        raise ValueError(f"Upload at most {MAX_UPLOAD_FILES} PDF files per run.")

    for index, upload in enumerate(files):
        if not upload.filename:
            continue
        filename = sanitize_filename(upload.filename)
        if not filename.lower().endswith(".pdf"):
            raise ValueError(f"{upload.filename} is not a PDF file.")

        target = destination / unique_filename(filename, destination, index)
        total = 0
        with target.open("wb") as output:
            while chunk := await upload.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_UPLOAD_BYTES:
                    output.close()
                    target.unlink(missing_ok=True)
                    max_mb = MAX_UPLOAD_BYTES // (1024 * 1024)
                    raise ValueError(f"{upload.filename} exceeds the {max_mb} MB upload limit.")
                output.write(chunk)
        saved.append(target)

    if required and not saved:
        raise ValueError("No PDF files were uploaded.")
    return saved


def sanitize_filename(filename: str) -> str:
    name = Path(filename).name.strip().replace("\x00", "")
    cleaned = "".join(char if char.isalnum() or char in "._- " else "_" for char in name)
    return cleaned.strip(" ._") or "uploaded.pdf"


def unique_filename(filename: str, destination: Path, index: int) -> str:
    candidate = filename
    if not (destination / candidate).exists():
        return candidate
    stem = Path(filename).stem
    suffix = Path(filename).suffix
    return f"{stem}_{index + 1}{suffix}"


def safe_report_dir(report_id: str) -> Path:
    if not report_id.isalnum():
        raise HTTPException(status_code=404, detail="Report not found")
    path = REPORT_DIR / report_id
    try:
        path.resolve().relative_to(REPORT_DIR.resolve())
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Report not found") from exc
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    return path
