# PDF Forensics Analyzer

A FastAPI web application for automated PDF tampering checks. It accepts one or more PDFs, optionally compares each file with a baseline/original PDF, and produces structured reports, annotated PDFs, and rendered visual diff artifacts.

## Features

- PDF metadata extraction and anomaly checks.
- Incremental update / revision marker detection with startxref and /Prev details.
- SHA-256 and MD5 hashing.
- Baseline comparison for page count, extracted text, embedded images, and rendered page pixels.
- Digital signature detection with best-effort PyMuPDF validation when the local API can validate signature widgets.
- Risk score with concrete scoring reasons for each PDF.
- Active-content indicators for JavaScript, OpenAction, Launch, embedded files, RichMedia, URI actions, forms, annotations, low-visibility text, and near-white overlays.
- Graceful handling for encrypted, unreadable, or corrupted PDFs, with optional password input.
- CSV, Excel, JSON, PDF report, and ZIP bundle downloads.
- Annotated PDF generation for baseline text/page differences.
- PNG visual diff generation for rendered page changes.

## Run

```powershell
pip install -r requirements.txt
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Then open `http://127.0.0.1:8000`.

## Notes

PDF signature validation depends on the signature structure and the validation support exposed by the installed PyMuPDF/MuPDF build. When full cryptographic trust validation is not possible, the report still records signature markers, signed widgets, ByteRange evidence, and any validation error reported by MuPDF.
