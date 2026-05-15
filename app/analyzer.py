from __future__ import annotations

import difflib
import hashlib
import json
import re
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

import fitz
try:
    import pytesseract
    pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
    _TESSERACT_AVAILABLE = True
except Exception:
    _TESSERACT_AVAILABLE = False
import pandas as pd
import pikepdf
from PIL import Image, ImageChops
from pymupdf import mupdf
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


PDF_DATE_RE = re.compile(
    r"^(?:D:)?"
    r"(?P<year>\d{4})"
    r"(?P<month>\d{2})?"
    r"(?P<day>\d{2})?"
    r"(?P<hour>\d{2})?"
    r"(?P<minute>\d{2})?"
    r"(?P<second>\d{2})?"
    r"(?P<offset>Z|[+-]\d{2}'?\d{2}'?)?"
)

EDITING_TOOL_HINTS = (
    "acrobat",
    "adobe pdf library",
    "canva",
    "dompdf",
    "foxit",
    "ghostscript",
    "illustrator",
    "inkscape",
    "itext",
    "libreoffice",
    "microsoft",
    "nitro",
    "openoffice",
    "pdf-xchange",
    "pdftk",
    "photoshop",
    "preview",
    "quartz",
    "reportlab",
    "sejda",
    "tcpdf",
    "wkhtmltopdf",
)

STRONG_METADATA_ISSUE_PREFIXES = (
    "Encrypted PDF requires a password",
    "Unreadable or corrupted PDF",
    "Could not open PDF",
    "Partial analysis failure",
    "CreationDate is in the future",
    "ModDate is in the future",
    "ModDate precedes CreationDate",
    "Unparseable CreationDate",
    "Unparseable ModDate",
    "PDF required repair while opening",
)

ACTIVE_CONTENT_PATTERNS = {
    "/JavaScript": rb"/JavaScript\b|/JS\b",
    "/OpenAction": rb"/OpenAction\b",
    "/Launch": rb"/Launch\b",
    "/AA": rb"/AA\b",
    "/EmbeddedFile": rb"/EmbeddedFile\b|/EmbeddedFiles\b",
    "/RichMedia": rb"/RichMedia\b",
    "/URI": rb"/URI\b",
}

VISUAL_DIFF_DPI = 96
VISUAL_DIFF_THRESHOLD = 0.01
MAX_VISUAL_DIFF_PAGES = 25
MAX_VISUAL_DIFF_ARTIFACTS = 8

OCR_RENDER_DPI = 150
OCR_MAX_PAGES = 10
OCR_MIN_TEXT_CHARS = 40
OCR_MISMATCH_FLAG_THRESHOLD = 0.50   # similarity below this is suspicious
OCR_MISMATCH_WARN_THRESHOLD = 0.72   # similarity below this is a mild warning


@dataclass
class VisualDiffResult:
    summary: str = "No baseline provided"
    changed_pages: int = 0
    max_change_percent: float = 0.0
    artifact_names: list[str] = field(default_factory=list)
    comparison_sets: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class PdfProfile:
    path: Path
    filename: str
    sha256: str
    md5: str
    size_bytes: int
    readable: bool = False
    encrypted: bool = False
    corrupted: bool = False
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, str] = field(default_factory=dict)
    metadata_issues: list[str] = field(default_factory=list)
    revision_summary: str = "Unavailable"
    revision_details: list[str] = field(default_factory=list)
    has_incremental_updates: bool = False
    page_count: int | None = None
    text_by_page: list[str] = field(default_factory=list)
    image_hashes: list[str] = field(default_factory=list)
    signature_status: str = "Unavailable"
    signature_flagged: bool = False
    forensic_indicators: list[str] = field(default_factory=list)

    @property
    def full_text(self) -> str:
        return "\n".join(self.text_by_page)


def analyze_files(
    pdf_paths: list[Path],
    baseline_path: Path | None,
    report_dir: Path,
    password: str | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    report_dir.mkdir(parents=True, exist_ok=True)
    annotated_dir = report_dir / "annotated"
    visual_dir = report_dir / "visual_diffs"
    annotated_dir.mkdir(parents=True, exist_ok=True)
    visual_dir.mkdir(parents=True, exist_ok=True)

    baseline = build_profile(baseline_path, password=password) if baseline_path else None
    rows: list[dict[str, Any]] = []

    for pdf_path in pdf_paths:
        profile = build_profile(pdf_path, password=password)
        visual = compare_visual_pages(profile, baseline, visual_dir) if baseline else VisualDiffResult()
        row = build_report_row(profile, baseline, visual)
        if baseline and profile.readable and baseline.readable and profile.sha256 != baseline.sha256:
            annotated = create_annotated_pdf(profile, baseline, annotated_dir, password=password)
            if annotated:
                row["Annotated PDF"] = annotated.name
        rows.append(row)

    summary = build_summary(rows, baseline)
    return rows, summary


def build_profile(path: Path, password: str | None = None) -> PdfProfile:
    data = path.read_bytes()
    revision_summary, has_incremental, revision_details = detect_revisions(data)
    profile = PdfProfile(
        path=path,
        filename=path.name,
        sha256=hashlib.sha256(data).hexdigest(),
        md5=hashlib.md5(data).hexdigest(),
        size_bytes=len(data),
        revision_summary=revision_summary,
        revision_details=revision_details,
        has_incremental_updates=has_incremental,
    )

    try:
        doc = fitz.open(stream=data, filetype="pdf")
    except Exception as exc:
        profile.corrupted = True
        profile.errors.append(f"Could not open PDF: {exc}")
        profile.metadata_issues.append("Unreadable or corrupted PDF")
        profile.signature_status = "Unavailable - unreadable"
        return profile

    try:
        profile.encrypted = bool(getattr(doc, "needs_pass", False) or getattr(doc, "is_encrypted", False))
        if profile.encrypted and getattr(doc, "needs_pass", False):
            if not password:
                profile.errors.append("PDF is encrypted and requires a password")
                profile.metadata_issues.append("Encrypted PDF requires a password")
                profile.signature_status = "Unavailable - encrypted"
                return profile
            authenticated = doc.authenticate(password)
            if authenticated <= 0:
                profile.errors.append("PDF password was rejected")
                profile.metadata_issues.append("Encrypted PDF requires a valid password")
                profile.signature_status = "Unavailable - encrypted"
                return profile

        profile.readable = True
        profile.page_count = doc.page_count
        profile.metadata = normalize_metadata(doc.metadata or {})
        profile.signature_status, profile.signature_flagged = detect_signatures(doc, data)
        profile.text_by_page = extract_text(doc)
        profile.image_hashes = extract_image_hashes(doc)
        profile.forensic_indicators.extend(summarize_pdf_structure(doc))
        profile.forensic_indicators.extend(detect_page_indicators(doc))
        profile.forensic_indicators.extend(scan_active_content(data))
        profile.forensic_indicators.extend(detect_ocr_mismatch(doc, profile.text_by_page))

        if getattr(doc, "is_repaired", False):
            profile.metadata_issues.append("PDF required repair while opening")
    except Exception as exc:
        profile.errors.append(f"Partial analysis failure: {exc}")
        if not profile.metadata_issues:
            profile.metadata_issues.append("Partial analysis failure")
    finally:
        doc.close()

    try:
        docinfo, pikepdf_indicators = extract_pikepdf_info(path, password=password)
        profile.metadata.update(docinfo)
        profile.forensic_indicators.extend(pikepdf_indicators)
    except pikepdf.PasswordError:
        if "Encrypted PDF requires a password" not in profile.metadata_issues:
            profile.metadata_issues.append("Encrypted PDF requires a password")
    except Exception as exc:
        profile.errors.append(f"pikepdf metadata read failed: {exc}")

    if profile.readable:
        profile.metadata_issues.extend(check_metadata(profile.metadata))
        profile.metadata_issues = unique_preserve_order(profile.metadata_issues)
        profile.forensic_indicators.extend(profile.revision_details)
        profile.forensic_indicators = unique_preserve_order(profile.forensic_indicators)

    return profile


def detect_revisions(data: bytes) -> tuple[str, bool, list[str]]:
    startxref_values = [value.decode("ascii", "ignore") for value in re.findall(rb"startxref\s+(\d+)", data)]
    eof_count = len(re.findall(rb"%%EOF", data))
    prev_values = [value.decode("ascii", "ignore") for value in re.findall(rb"/Prev\s+(\d+)", data)]

    startxref_count = len(startxref_values)
    has_incremental = startxref_count > 1 or eof_count > 1 or len(prev_values) > 0
    details: list[str] = []
    if startxref_values:
        details.append(f"startxref offsets: {', '.join(startxref_values[:8])}")
    if prev_values:
        details.append(f"/Prev chain offsets: {', '.join(prev_values[:8])}")
    if startxref_count > 8 or len(prev_values) > 8:
        details.append("Revision offset list truncated")

    if has_incremental:
        return (
            "Incremental updates suspected "
            f"(startxref={startxref_count}, EOF={eof_count}, /Prev={len(prev_values)})",
            True,
            details,
        )
    return f"Single revision (startxref={startxref_count}, EOF={eof_count})", False, details


def normalize_metadata(metadata: dict[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in metadata.items():
        if value is None:
            continue
        text = str(value).strip()
        if text:
            result[key] = text
    return result


def extract_pikepdf_info(path: Path, password: str | None = None) -> tuple[dict[str, str], list[str]]:
    result: dict[str, str] = {}
    indicators: list[str] = []
    kwargs = {"password": password} if password else {}
    with pikepdf.Pdf.open(path, **kwargs) as pdf:
        for key, value in pdf.docinfo.items():
            clean_key = str(key).lstrip("/")
            if clean_key and value is not None:
                result[f"Info.{clean_key}"] = str(value)

        indicators.append(f"PDF objects: {len(pdf.objects)}")
        root = pdf.Root
        if "/OpenAction" in root:
            indicators.append("OpenAction present")
        if "/AcroForm" in root:
            indicators.append("AcroForm present")
        if "/Names" in root:
            names = root["/Names"]
            if "/EmbeddedFiles" in names:
                indicators.append("Embedded files present")
            if "/JavaScript" in names:
                indicators.append("Document JavaScript name tree present")

        xmp_metadata = extract_xmp_metadata(pdf)
        for key, value in xmp_metadata.items():
            if value:
                result[f"XMP.{key}"] = value

        xmp_mismatches = detect_xmp_docinfo_mismatch(result, xmp_metadata)
        indicators.extend(xmp_mismatches)
    return result, indicators


def extract_xmp_metadata(pdf: pikepdf.Pdf) -> dict[str, str]:
    # Prefer parsed metadata when available, but fall back to raw XML scanning.
    metadata: dict[str, str] = {}

    try:
        with pdf.open_metadata(set_pikepdf_as_editor=False) as xmp:
            for key in ("xmp:CreateDate", "xmp:ModifyDate", "pdf:Producer", "xmp:CreatorTool"):
                value = xmp.get(key)
                if value:
                    metadata[key] = str(value).strip()
    except Exception:
        pass

    if metadata:
        return metadata

    try:
        root = pdf.Root
        if "/Metadata" not in root:
            return metadata
        raw = root["/Metadata"].read_bytes().decode("utf-8", "ignore")
    except Exception:
        return metadata

    xml_patterns = {
        "xmp:CreateDate": r"<xmp:CreateDate>(.*?)</xmp:CreateDate>",
        "xmp:ModifyDate": r"<xmp:ModifyDate>(.*?)</xmp:ModifyDate>",
        "pdf:Producer": r"<pdf:Producer>(.*?)</pdf:Producer>",
        "xmp:CreatorTool": r"<xmp:CreatorTool>(.*?)</xmp:CreatorTool>",
    }
    for key, pattern in xml_patterns.items():
        match = re.search(pattern, raw, flags=re.IGNORECASE | re.DOTALL)
        if match:
            metadata[key] = collapse_spaces(match.group(1))
    return metadata


def detect_xmp_docinfo_mismatch(docinfo: dict[str, str], xmp: dict[str, str]) -> list[str]:
    if not xmp:
        return []

    indicators: list[str] = []
    comparisons = (
        ("CreationDate", "xmp:CreateDate", "creation"),
        ("ModDate", "xmp:ModifyDate", "modification"),
        ("Producer", "pdf:Producer", "producer"),
        ("Creator", "xmp:CreatorTool", "creator tool"),
    )

    for info_key, xmp_key, label in comparisons:
        info_value = collapse_spaces(docinfo.get(f"Info.{info_key}", ""))
        xmp_value = collapse_spaces(xmp.get(xmp_key, ""))
        if info_value and xmp_value and info_value != xmp_value:
            indicators.append(
                f"DocInfo/XMP mismatch in {label}: Info={truncate(info_value, 60)} vs XMP={truncate(xmp_value, 60)}"
            )

    return unique_preserve_order(indicators)


def check_metadata(metadata: dict[str, str]) -> list[str]:
    issues: list[str] = []
    creation_raw = first_value(metadata, "creationDate", "CreationDate", "Info.CreationDate")
    mod_raw = first_value(metadata, "modDate", "ModDate", "Info.ModDate")

    creation_date, creation_error = parse_pdf_date(creation_raw)
    mod_date, mod_error = parse_pdf_date(mod_raw)

    if not creation_raw:
        issues.append("Missing CreationDate")
    elif creation_error:
        issues.append(f"Unparseable CreationDate: {creation_raw}")

    if not mod_raw:
        issues.append("Missing ModDate")
    elif mod_error:
        issues.append(f"Unparseable ModDate: {mod_raw}")

    now = datetime.now(timezone.utc) + timedelta(days=1)
    if creation_date and creation_date > now:
        issues.append("CreationDate is in the future")
    if mod_date and mod_date > now:
        issues.append("ModDate is in the future")
    if creation_date and mod_date:
        if mod_date < creation_date - timedelta(minutes=5):
            issues.append("ModDate precedes CreationDate")
        elif mod_date > creation_date + timedelta(minutes=1):
            issues.append("ModDate later than CreationDate")

    producer_creator = (
        f"{first_value(metadata, 'producer', 'Producer', 'Info.Producer') or ''} "
        f"{first_value(metadata, 'creator', 'Creator', 'Info.Creator') or ''}"
    )
    lowered = producer_creator.lower()
    if any(hint in lowered for hint in EDITING_TOOL_HINTS):
        issues.append("Producer/Creator indicates editing or conversion software")

    return unique_preserve_order(issues)


def first_value(metadata: dict[str, str], *keys: str) -> str | None:
    lowered = {key.lower(): value for key, value in metadata.items()}
    for key in keys:
        value = lowered.get(key.lower())
        if value:
            return value
    return None


def parse_pdf_date(value: str | None) -> tuple[datetime | None, str | None]:
    if not value:
        return None, None
    match = PDF_DATE_RE.search(value.strip())
    if not match:
        return None, "invalid format"
    parts = match.groupdict()
    try:
        year = int(parts["year"])
        month = int(parts["month"] or "1")
        day = int(parts["day"] or "1")
        hour = int(parts["hour"] or "0")
        minute = int(parts["minute"] or "0")
        second = int(parts["second"] or "0")
        tzinfo = timezone.utc
        offset = parts.get("offset")
        if offset and offset != "Z":
            sign = 1 if offset.startswith("+") else -1
            digits = re.sub(r"\D", "", offset)
            if len(digits) >= 4:
                hours = int(digits[:2])
                minutes = int(digits[2:4])
                tzinfo = timezone(sign * timedelta(hours=hours, minutes=minutes))
        return datetime(year, month, day, hour, minute, second, tzinfo=tzinfo), None
    except Exception as exc:
        return None, str(exc)


def extract_text(doc: fitz.Document) -> list[str]:
    text_by_page: list[str] = []
    for page_index in range(doc.page_count):
        try:
            text_by_page.append(doc.load_page(page_index).get_text("text"))
        except Exception as exc:
            text_by_page.append(f"[Text extraction failed on page {page_index + 1}: {exc}]")
    return text_by_page


def extract_image_hashes(doc: fitz.Document) -> list[str]:
    image_hashes: list[str] = []
    seen_xrefs: set[int] = set()
    for page_index in range(doc.page_count):
        try:
            images = doc.get_page_images(page_index, full=True)
        except Exception:
            continue
        for image in images:
            xref = int(image[0])
            if xref in seen_xrefs:
                continue
            seen_xrefs.add(xref)
            try:
                image_bytes = doc.extract_image(xref).get("image", b"")
                if image_bytes:
                    image_hashes.append(hashlib.sha256(image_bytes).hexdigest())
            except Exception:
                continue
    return image_hashes


def summarize_pdf_structure(doc: fitz.Document) -> list[str]:
    indicators: list[str] = []
    try:
        xref_total = max(0, doc.xref_length() - 1)
        indicators.append(f"XRef objects: {xref_total}")
        type_counts: Counter[str] = Counter()
        for xref in range(1, min(doc.xref_length(), 5000)):
            try:
                obj = doc.xref_object(xref, compressed=False)
            except Exception:
                continue
            for label, pattern in (
                ("Page", r"/Type\s*/Page\b"),
                ("Annot", r"/Type\s*/Annot\b"),
                ("XObject", r"/Type\s*/XObject\b"),
                ("ObjStm", r"/Type\s*/ObjStm\b"),
                ("Sig", r"/Type\s*/Sig\b|/FT\s*/Sig\b"),
            ):
                if re.search(pattern, obj):
                    type_counts[label] += 1
        if type_counts:
            indicators.append(
                "Object types: "
                + ", ".join(f"{key}={value}" for key, value in sorted(type_counts.items()))
            )
    except Exception:
        pass
    return indicators


def detect_page_indicators(doc: fitz.Document) -> list[str]:
    indicators: list[str] = []
    annotation_count = 0
    widget_count = 0
    external_links = 0
    hidden_text_spans = 0
    white_overlay_count = 0
    fake_redaction_confidences: list[float] = []

    for page in doc:
        try:
            annots = page.annots()
            if annots:
                annotation_count += sum(1 for _ in annots)
        except Exception:
            pass

        try:
            widgets = page.widgets()
            if widgets:
                widget_count += sum(1 for _ in widgets)
        except Exception:
            pass

        try:
            for link in page.get_links():
                if link.get("uri"):
                    external_links += 1
        except Exception:
            pass

        try:
            for span in page.get_texttrace():
                color = span.get("color")
                opacity = float(span.get("opacity", 1) or 0)
                if opacity < 0.05 or is_near_white(color):
                    hidden_text_spans += 1
        except Exception:
            pass

        try:
            page_area = max(1.0, page.rect.width * page.rect.height)
            for drawing in page.get_drawings():
                fill = drawing.get("fill")
                rect = drawing.get("rect")
                if fill and rect and is_near_white(fill):
                    area = rect_area(rect)
                    if area / page_area >= 0.08:
                        white_overlay_count += 1
        except Exception:
            pass

        try:
            fake_redaction_confidences.extend(detect_fake_redactions_on_page(page))
        except Exception:
            pass

    if annotation_count:
        indicators.append(f"Annotations present: {annotation_count}")
    if widget_count:
        indicators.append(f"Form/signature widgets present: {widget_count}")
    if external_links:
        indicators.append(f"External URI links present: {external_links}")
    if hidden_text_spans:
        indicators.append(f"Low-visibility text spans: {hidden_text_spans}")
    if white_overlay_count:
        indicators.append(f"Large near-white drawing overlays: {white_overlay_count}")
    if fake_redaction_confidences:
        max_conf = max(fake_redaction_confidences)
        avg_conf = sum(fake_redaction_confidences) / len(fake_redaction_confidences)
        grade = redaction_confidence_label(max_conf)
        indicators.append(
            "Potential fake redactions: "
            f"{len(fake_redaction_confidences)} "
            f"(confidence: {grade}, max={max_conf:.0%}, avg={avg_conf:.0%})"
        )

    try:
        is_form_pdf = doc.is_form_pdf() if callable(doc.is_form_pdf) else doc.is_form_pdf
        if is_form_pdf:
            indicators.append("Interactive form detected")
    except Exception:
        pass

    return indicators


def is_near_white(color: Any) -> bool:
    if not isinstance(color, (tuple, list)) or len(color) < 3:
        return False
    try:
        return all(float(channel) >= 0.92 for channel in color[:3])
    except Exception:
        return False


def is_near_black(color: Any) -> bool:
    if not isinstance(color, (tuple, list)) or len(color) < 3:
        return False
    try:
        return all(float(channel) <= 0.12 for channel in color[:3])
    except Exception:
        return False


def redaction_confidence_label(score: float) -> str:
    if score >= 0.78:
        return "High"
    if score >= 0.55:
        return "Medium"
    return "Low"


def detect_fake_redactions_on_page(page: fitz.Page) -> list[float]:
    words = page.get_text("words")
    if not words:
        return []

    word_rects = [fitz.Rect(word[0], word[1], word[2], word[3]) for word in words]
    page_area = max(1.0, page.rect.width * page.rect.height)
    confidences: list[float] = []

    for drawing in page.get_drawings():
        fill = drawing.get("fill")
        rect = drawing.get("rect")
        if not (fill and rect and is_near_black(fill)):
            continue

        draw_rect = fitz.Rect(rect)
        area_ratio = rect_area(draw_rect) / page_area
        if area_ratio < 0.002 or area_ratio > 0.35:
            continue

        covered_ratios: list[float] = []
        for word_rect in word_rects:
            inter = draw_rect & word_rect
            if inter.is_empty:
                continue
            denom = max(1.0, word_rect.width * word_rect.height)
            overlap_ratio = rect_area(inter) / denom
            if overlap_ratio >= 0.45:
                covered_ratios.append(overlap_ratio)

        if len(covered_ratios) >= 2:
            avg_overlap = sum(covered_ratios) / len(covered_ratios)
            density_factor = min(1.0, area_ratio / 0.03)
            score = 0.35 + min(0.3, 0.06 * len(covered_ratios)) + (0.25 * avg_overlap) + (0.1 * density_factor)
            confidences.append(min(0.99, score))

    return confidences


def rect_area(rect: Any) -> float:
    try:
        return max(0.0, float(rect.width) * float(rect.height))
    except Exception:
        try:
            left, top, right, bottom = rect
            return max(0.0, float(right - left) * float(bottom - top))
        except Exception:
            return 0.0


def scan_active_content(data: bytes) -> list[str]:
    indicators: list[str] = []
    for label, pattern in ACTIVE_CONTENT_PATTERNS.items():
        count = len(re.findall(pattern, data))
        if count:
            indicators.append(f"Active content marker {label} found ({count})")
    return indicators


def detect_signatures(doc: fitz.Document, data: bytes) -> tuple[str, bool]:
    statuses: list[str] = []
    flagged = False

    try:
        sigflags = doc.get_sigflags()
        if sigflags > 0:
            statuses.append(f"Signature flags present ({sigflags})")
    except Exception:
        sigflags = 0

    byte_range_markers = len(re.findall(rb"/ByteRange\s*\[", data))
    sig_object_markers = len(re.findall(rb"/Type\s*/Sig\b|/FT\s*/Sig\b", data))
    if byte_range_markers or sig_object_markers:
        statuses.append(
            f"Signature markers found (ByteRange={byte_range_markers}, SigObjects={sig_object_markers})"
        )

    try:
        validation_statuses, validation_flagged = validate_signature_widgets(doc)
        statuses.extend(validation_statuses)
        flagged = flagged or validation_flagged
    except Exception as exc:
        if sigflags > 0 or byte_range_markers or sig_object_markers:
            statuses.append(f"Signature validation unavailable: {exc}")
            flagged = True

    if not statuses:
        return "No signature", False

    if not any("Valid signature" in status for status in statuses):
        flagged = True
    return "; ".join(unique_preserve_order(statuses)), flagged


def validate_signature_widgets(doc: fitz.Document) -> tuple[list[str], bool]:
    statuses: list[str] = []
    flagged = False

    for page in doc:
        pdf_page = page.this.pdf_page_from_fz_page()
        widget = pdf_page.pdf_first_widget()
        while widget:
            try:
                widget_type = mupdf.pdf_widget_type(widget)
                if widget_type == fitz.PDF_WIDGET_TYPE_SIGNATURE:
                    signed = bool(mupdf.pdf_widget_is_signed(widget))
                    if not signed:
                        statuses.append("Unsigned signature field")
                        flagged = True
                    else:
                        err = mupdf.pdf_validate_signature(widget)
                        description = signature_error_description(err)
                        changed = bool(mupdf.pdf_incremental_change_since_signing_widget(widget))
                        if err == fitz.PDF_SIGNATURE_ERROR_OKAY and not changed:
                            statuses.append("Valid signature")
                        elif err == fitz.PDF_SIGNATURE_ERROR_OKAY and changed:
                            statuses.append("Valid signature; document changed after signing")
                            flagged = True
                        else:
                            statuses.append(f"Invalid or untrusted signature: {description}")
                            flagged = True
            finally:
                widget = mupdf.pdf_next_widget(widget)

    return statuses, flagged


def signature_error_description(error_code: int) -> str:
    try:
        description = mupdf.pdf_signature_error_description(error_code)
        if isinstance(description, bytes):
            return description.decode("utf-8", "replace")
        return str(description)
    except Exception:
        mapping = {
            fitz.PDF_SIGNATURE_ERROR_DIGEST_FAILURE: "digest failure",
            fitz.PDF_SIGNATURE_ERROR_NO_CERTIFICATE: "no certificate",
            fitz.PDF_SIGNATURE_ERROR_NO_SIGNATURES: "no signatures",
            fitz.PDF_SIGNATURE_ERROR_NOT_SIGNED: "not signed",
            fitz.PDF_SIGNATURE_ERROR_NOT_TRUSTED: "not trusted",
            fitz.PDF_SIGNATURE_ERROR_OKAY: "okay",
            fitz.PDF_SIGNATURE_ERROR_SELF_SIGNED: "self-signed",
            fitz.PDF_SIGNATURE_ERROR_SELF_SIGNED_IN_CHAIN: "self-signed in chain",
            fitz.PDF_SIGNATURE_ERROR_UNKNOWN: "unknown",
        }
        return mapping.get(error_code, f"error code {error_code}")


def compare_visual_pages(
    profile: PdfProfile,
    baseline: PdfProfile | None,
    visual_dir: Path,
) -> VisualDiffResult:
    if not baseline:
        return VisualDiffResult()
    if not baseline.readable:
        return VisualDiffResult(summary="Unavailable - baseline unreadable")
    if not profile.readable:
        return VisualDiffResult(summary="Unavailable - PDF unreadable")
    if profile.sha256 == baseline.sha256:
        return VisualDiffResult(summary="Identical file")

    result = VisualDiffResult(summary="No visual differences detected")
    visual_dir.mkdir(parents=True, exist_ok=True)

    try:
        baseline_doc = fitz.open(baseline.path)
        target_doc = fitz.open(profile.path)
    except Exception:
        return VisualDiffResult(summary="Visual diff unavailable")

    try:
        page_limit = min(baseline_doc.page_count, target_doc.page_count, MAX_VISUAL_DIFF_PAGES)
        for page_index in range(page_limit):
            baseline_image = render_page_image(baseline_doc, page_index)
            target_image = render_page_image(target_doc, page_index)
            baseline_image, target_image = equalize_image_sizes(baseline_image, target_image)

            diff = ImageChops.difference(baseline_image, target_image)
            mask = diff.convert("L").point(lambda pixel: 255 if pixel > 18 else 0)
            changed_pixels = mask.histogram()[255]
            total_pixels = max(1, mask.size[0] * mask.size[1])
            change_percent = changed_pixels / total_pixels * 100
            result.max_change_percent = max(result.max_change_percent, change_percent)

            if change_percent >= VISUAL_DIFF_THRESHOLD:
                result.changed_pages += 1
                if len(result.comparison_sets) < MAX_VISUAL_DIFF_ARTIFACTS:
                    stem = f"{safe_stem(profile.filename)}_page_{page_index + 1}"
                    baseline_name = f"{stem}_baseline.png"
                    current_name = f"{stem}_current.png"
                    diff_name = f"{stem}_diff.png"

                    baseline_path = visual_dir / baseline_name
                    current_path = visual_dir / current_name
                    diff_path = visual_dir / diff_name

                    baseline_image.save(baseline_path)
                    target_image.save(current_path)
                    save_visual_diff_artifact(target_image, mask, diff_path)

                    result.artifact_names.append(diff_name)
                    result.comparison_sets.append(
                        {
                            "page": page_index + 1,
                            "baseline": baseline_name,
                            "current": current_name,
                            "diff": diff_name,
                        }
                    )

        if baseline_doc.page_count != target_doc.page_count:
            result.changed_pages += abs(baseline_doc.page_count - target_doc.page_count)

        if result.changed_pages:
            result.summary = (
                f"{result.changed_pages} page(s) visually changed; "
                f"max pixel delta {result.max_change_percent:.2f}%"
            )
            if baseline_doc.page_count != target_doc.page_count:
                result.summary += f"; page count {baseline_doc.page_count} -> {target_doc.page_count}"
        elif baseline_doc.page_count != target_doc.page_count:
            result.summary = f"Page count changed ({baseline_doc.page_count} -> {target_doc.page_count})"
        elif max(baseline_doc.page_count, target_doc.page_count) > MAX_VISUAL_DIFF_PAGES:
            result.summary += f" across first {MAX_VISUAL_DIFF_PAGES} pages"
    finally:
        baseline_doc.close()
        target_doc.close()

    return result


def render_page_image(doc: fitz.Document, page_index: int) -> Image.Image:
    matrix = fitz.Matrix(VISUAL_DIFF_DPI / 72, VISUAL_DIFF_DPI / 72)
    pix = doc.load_page(page_index).get_pixmap(matrix=matrix, alpha=False)
    return Image.frombytes("RGB", (pix.width, pix.height), pix.samples)


def equalize_image_sizes(left: Image.Image, right: Image.Image) -> tuple[Image.Image, Image.Image]:
    width = max(left.width, right.width)
    height = max(left.height, right.height)
    if left.size == right.size:
        return left, right

    left_canvas = Image.new("RGB", (width, height), "white")
    right_canvas = Image.new("RGB", (width, height), "white")
    left_canvas.paste(left, (0, 0))
    right_canvas.paste(right, (0, 0))
    return left_canvas, right_canvas


def save_visual_diff_artifact(target_image: Image.Image, mask: Image.Image, path: Path) -> None:
    red = Image.new("RGB", target_image.size, (219, 42, 42))
    highlighted = Image.composite(red, target_image, mask)
    blended = Image.blend(target_image, highlighted, 0.55)
    blended.save(path)


def build_report_row(
    profile: PdfProfile,
    baseline: PdfProfile | None,
    visual: VisualDiffResult,
) -> dict[str, Any]:
    content_diff = compare_content(profile, baseline)
    hash_match = hash_match_summary(profile, baseline)
    score, reasons = score_profile(profile, baseline, hash_match, content_diff, visual)
    flagged = is_flagged(profile, baseline, hash_match, content_diff, visual, score)
    verdict = verdict_for(profile, baseline, flagged, hash_match, content_diff, visual, score)

    metadata_issues = "; ".join(profile.metadata_issues) if profile.metadata_issues else "None"
    forensic_indicators = "; ".join(profile.forensic_indicators) if profile.forensic_indicators else "None"

    return {
        "PDF": profile.filename,
        "Risk Score": score,
        "Risk Reasons": "; ".join(reasons) if reasons else "No strong indicators",
        "Metadata Issues": metadata_issues,
        "Revisions": profile.revision_summary,
        "Hash Match": hash_match,
        "Content Diff": content_diff,
        "Visual Diff": visual.summary,
        "Signature Validity": profile.signature_status,
        "Forensic Indicators": forensic_indicators,
        "Flagged": "Yes" if flagged else "No",
        "Verdict": verdict,
        "SHA256": profile.sha256,
        "MD5": profile.md5,
        "Size Bytes": profile.size_bytes,
        "Annotated PDF": "",
        "Visual Diff Files": "; ".join(visual.artifact_names),
        "Visual Diff Links": visual.artifact_names,
        "Visual Diff Pairs": visual.comparison_sets,
    }


def score_profile(
    profile: PdfProfile,
    baseline: PdfProfile | None,
    hash_match: str,
    content_diff: str,
    visual: VisualDiffResult,
) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []

    def add(points: int, reason: str) -> None:
        nonlocal score
        if reason not in reasons:
            score += points
            reasons.append(reason)

    if profile.corrupted or not profile.readable:
        add(80, "PDF is unreadable or corrupted")
    if profile.encrypted and not profile.readable:
        add(75, "PDF is encrypted and could not be analyzed")
    elif profile.encrypted:
        add(10, "PDF is encrypted but was readable with the supplied password")

    strong_metadata = [
        issue for issue in profile.metadata_issues if issue.startswith(STRONG_METADATA_ISSUE_PREFIXES)
    ]
    weak_metadata = [issue for issue in profile.metadata_issues if issue not in strong_metadata]
    if strong_metadata:
        add(min(35, 15 * len(strong_metadata)), "Strong metadata anomaly: " + ", ".join(strong_metadata[:3]))
    if weak_metadata:
        add(min(10, 3 * len(weak_metadata)), "Metadata warning: " + ", ".join(weak_metadata[:3]))

    if profile.has_incremental_updates:
        add(30, "Incremental revision history detected")

    signature_lower = profile.signature_status.lower()
    if profile.signature_flagged:
        if "invalid" in signature_lower or "untrusted" in signature_lower:
            add(45, "Digital signature is invalid or untrusted")
        elif "changed after signing" in signature_lower:
            add(45, "Document changed after signing")
        else:
            add(25, "Signature markers require review")

    if baseline:
        if hash_match != "Match":
            add(25, "SHA-256 differs from baseline")
        if "Page count changed" in content_diff:
            add(35, "Page count differs from baseline")
        if "Text changed" in content_diff or "Images changed" in content_diff:
            add(35, "Extracted content differs from baseline")
        if "No extracted content differences; binary hash differs" in content_diff:
            add(15, "Binary changed without extracted text or image delta")
        if visual.changed_pages:
            add(35, "Rendered page image differs from baseline")

    indicator_text = " ".join(profile.forensic_indicators).lower()
    if "active content marker /javascript" in indicator_text or "document javascript" in indicator_text:
        add(30, "PDF contains JavaScript indicators")
    if "active content marker /launch" in indicator_text or "openaction present" in indicator_text:
        add(30, "PDF contains automatic action or launch behavior")
    if "embedded files present" in indicator_text or "active content marker /embeddedfile" in indicator_text:
        add(25, "PDF contains embedded file indicators")
    if "low-visibility text spans" in indicator_text:
        add(25, "Low-visibility text layer detected")
    if "large near-white drawing overlays" in indicator_text:
        add(20, "Large near-white overlay detected")
    if "docinfo/xmp mismatch" in indicator_text:
        add(20, "DocInfo and XMP metadata values are inconsistent")
    if "potential fake redactions" in indicator_text:
        if "confidence: high" in indicator_text:
            add(45, "Potential fake redactions detected (high confidence)")
        elif "confidence: medium" in indicator_text:
            add(35, "Potential fake redactions detected (medium confidence)")
        else:
            add(25, "Potential fake redactions detected (low confidence)")
    if "annotations present" in indicator_text:
        add(8, "Annotations are present")
    if "acroform present" in indicator_text or "interactive form detected" in indicator_text:
        add(8, "Interactive form fields are present")

    # OCR mismatch — weighted by severity
    ocr_flags = [i for i in profile.forensic_indicators if i.startswith("OCR mismatch")]
    ocr_warns = [i for i in profile.forensic_indicators if i.startswith("OCR partial mismatch")]
    ocr_blanks = [i for i in profile.forensic_indicators if i.startswith("OCR found no text")]
    if ocr_flags:
        add(min(45, 20 * len(ocr_flags)), f"OCR mismatch on {len(ocr_flags)} page(s) — text layer may be fabricated")
    if ocr_warns:
        add(min(15, 8 * len(ocr_warns)), f"OCR partial mismatch on {len(ocr_warns)} page(s)")
    if ocr_blanks:
        add(min(30, 15 * len(ocr_blanks)), f"OCR found no visible text on {len(ocr_blanks)} page(s) that have an embedded text layer")

    return min(score, 100), reasons


def hash_match_summary(profile: PdfProfile, baseline: PdfProfile | None) -> str:
    if not baseline:
        return f"No baseline (SHA256 {profile.sha256[:12]}...)"
    if profile.sha256 == baseline.sha256:
        return "Match"
    return f"Different (baseline {baseline.sha256[:12]}..., file {profile.sha256[:12]}...)"


def compare_content(profile: PdfProfile, baseline: PdfProfile | None) -> str:
    if not baseline:
        return "No baseline provided"
    if not baseline.readable:
        return "Unavailable - baseline unreadable"
    if not profile.readable:
        return "Unavailable - PDF unreadable"
    if profile.sha256 == baseline.sha256:
        return "Identical file"

    details: list[str] = []
    if profile.page_count != baseline.page_count:
        details.append(f"Page count changed ({baseline.page_count} -> {profile.page_count})")

    baseline_text = baseline.full_text
    profile_text = profile.full_text
    if baseline_text != profile_text:
        ratio = text_similarity(baseline_text, profile_text)
        added, removed = line_delta_counts(baseline_text, profile_text)
        details.append(f"Text changed (similarity {ratio:.1%}, +{added}/-{removed} lines)")

    baseline_images = Counter(baseline.image_hashes)
    profile_images = Counter(profile.image_hashes)
    if baseline_images != profile_images:
        details.append(
            "Images changed "
            f"(baseline={sum(baseline_images.values())}, file={sum(profile_images.values())})"
        )

    if not details:
        return "No extracted content differences; binary hash differs"
    return "; ".join(details)


def text_similarity(left: str, right: str) -> float:
    if not left and not right:
        return 1.0
    return difflib.SequenceMatcher(None, left, right).ratio()


def line_delta_counts(left: str, right: str) -> tuple[int, int]:
    added = 0
    removed = 0
    for line in difflib.ndiff(left.splitlines(), right.splitlines()):
        if line.startswith("+ "):
            added += 1
        elif line.startswith("- "):
            removed += 1
    return added, removed


def is_flagged(
    profile: PdfProfile,
    baseline: PdfProfile | None,
    hash_match: str,
    content_diff: str,
    visual: VisualDiffResult,
    score: int,
) -> bool:
    if profile.corrupted or profile.encrypted and not profile.readable:
        return True
    if has_strong_metadata_issue(profile.metadata_issues):
        return True
    if profile.has_incremental_updates:
        return True
    if profile.signature_flagged:
        return True
    if baseline and hash_match != "Match":
        return True
    if baseline and content_diff not in ("Identical file", "No extracted content differences; binary hash differs"):
        return True
    if baseline and visual.changed_pages:
        return True
    return score >= 30


def has_strong_metadata_issue(metadata_issues: list[str]) -> bool:
    return any(issue.startswith(STRONG_METADATA_ISSUE_PREFIXES) for issue in metadata_issues)


def verdict_for(
    profile: PdfProfile,
    baseline: PdfProfile | None,
    flagged: bool,
    hash_match: str,
    content_diff: str,
    visual: VisualDiffResult,
    score: int,
) -> str:
    signature_lower = profile.signature_status.lower()
    indicators_lower = " ".join(profile.forensic_indicators).lower()

    if profile.corrupted or not profile.readable:
        return "Unreadable / corrupted"
    if profile.encrypted and not profile.readable:
        return "Encrypted / not analyzable"
    if profile.signature_flagged and ("invalid" in signature_lower or "untrusted" in signature_lower):
        return "Signature invalid or untrusted"
    if baseline and (
        content_diff not in ("Identical file", "No extracted content differences; binary hash differs")
        or visual.changed_pages
    ):
        return "Modified from baseline"
    if baseline and hash_match != "Match":
        return "Binary changed from baseline"
    if profile.has_incremental_updates:
        return "Revision history indicates edits"
    if (
        has_strong_metadata_issue(profile.metadata_issues)
        or "active content marker" in indicators_lower
        or "low-visibility text spans" in indicators_lower
        or "large near-white drawing overlays" in indicators_lower
        or "docinfo/xmp mismatch" in indicators_lower
    ):
        return "Suspicious metadata or active content"
    if "potential fake redactions" in indicators_lower:
        if "confidence: high" in indicators_lower:
            return "Potential fake redactions (High confidence)"
        if "confidence: medium" in indicators_lower:
            return "Potential fake redactions (Medium confidence)"
        return "Potential fake redactions (Low confidence)"
    if "ocr mismatch" in indicators_lower or "ocr found no text" in indicators_lower:
        return "OCR mismatch — text layer may be fabricated"
    if flagged or score >= 30:
        return "Needs review"
    return "No strong tamper indicators"


def build_summary(rows: list[dict[str, Any]], baseline: PdfProfile | None) -> dict[str, Any]:
    scores = [int(row["Risk Score"]) for row in rows]
    verdicts = [row["Verdict"] for row in rows]
    max_score = max(scores, default=0)
    average_score = round(sum(scores) / len(scores), 1) if scores else 0

    if "Modified from baseline" in verdicts:
        overall = "Modified from baseline"
    elif any(verdict.startswith("Potential fake redactions") for verdict in verdicts):
        if "Potential fake redactions (High confidence)" in verdicts:
            overall = "Potential fake redactions (High confidence)"
        elif "Potential fake redactions (Medium confidence)" in verdicts:
            overall = "Potential fake redactions (Medium confidence)"
        else:
            overall = "Potential fake redactions (Low confidence)"
    elif "Signature invalid or untrusted" in verdicts:
        overall = "Signature invalid or untrusted"
    elif "Unreadable / corrupted" in verdicts:
        overall = "Unreadable / corrupted"
    elif "OCR mismatch — text layer may be fabricated" in verdicts:
        overall = "OCR mismatch — text layer may be fabricated"
    elif max_score >= 70:
        overall = "High risk"
    elif max_score >= 30:
        overall = "Needs review"
    else:
        overall = "No strong tamper indicators"

    return {
        "overall_verdict": overall,
        "total": len(rows),
        "flagged": sum(1 for row in rows if row["Flagged"] == "Yes"),
        "max_risk_score": max_score,
        "average_risk_score": average_score,
        "baseline_name": baseline.filename if baseline else "",
        "baseline_sha256": baseline.sha256 if baseline else "",
        "baseline_issues": "; ".join(baseline.metadata_issues) if baseline and baseline.metadata_issues else "",
    }


def create_annotated_pdf(
    profile: PdfProfile,
    baseline: PdfProfile,
    annotated_dir: Path,
    password: str | None = None,
) -> Path | None:
    try:
        doc = fitz.open(profile.path)
        if getattr(doc, "needs_pass", False) and password:
            doc.authenticate(password)
    except Exception:
        return None

    try:
        page_total = min(doc.page_count, max(len(profile.text_by_page), len(baseline.text_by_page)))
        for page_index in range(page_total):
            if page_index >= doc.page_count:
                continue
            page = doc.load_page(page_index)
            baseline_text = baseline.text_by_page[page_index] if page_index < len(baseline.text_by_page) else ""
            target_text = profile.text_by_page[page_index] if page_index < len(profile.text_by_page) else ""

            if page_index >= len(baseline.text_by_page):
                add_page_note(page, "Page does not exist in baseline PDF.")
                continue

            for changed_line in changed_target_lines(baseline_text, target_text)[:30]:
                if not highlight_line(page, changed_line):
                    add_page_note(page, f"Changed text not located visually: {truncate(changed_line, 90)}")

            removed_count = max(0, line_delta_counts(baseline_text, target_text)[1])
            if removed_count:
                add_page_note(page, f"{removed_count} baseline text line(s) are absent from this page.")

        output = annotated_dir / f"{safe_stem(profile.filename)}_annotated.pdf"
        doc.save(output, garbage=4, deflate=True)
        return output
    except Exception:
        return None
    finally:
        doc.close()


def changed_target_lines(baseline_text: str, target_text: str) -> list[str]:
    lines: list[str] = []
    baseline_lines = [line.strip() for line in baseline_text.splitlines() if line.strip()]
    target_lines = [line.strip() for line in target_text.splitlines() if line.strip()]
    matcher = difflib.SequenceMatcher(None, baseline_lines, target_lines)
    for tag, _i1, _i2, j1, j2 in matcher.get_opcodes():
        if tag in {"replace", "insert"}:
            lines.extend(target_lines[j1:j2])
    return unique_preserve_order([line for line in lines if len(line) >= 4])


def highlight_line(page: fitz.Page, line: str) -> bool:
    text = collapse_spaces(line)
    if not text:
        return False

    candidates = [text]
    if len(text) > 80:
        candidates.append(text[:80])
    if len(text) > 40:
        candidates.append(text[:40])

    for candidate in candidates:
        rects = page.search_for(candidate, quads=True)
        if rects:
            for quad in rects[:5]:
                annot = page.add_highlight_annot(quad)
                annot.set_colors(stroke=(1, 0.72, 0.12))
                annot.update()
            return True
    return False


def add_page_note(page: fitz.Page, text: str) -> None:
    rect = fitz.Rect(36, 28, min(page.rect.width - 36, 420), 74)
    page.draw_rect(rect, color=(0.85, 0.18, 0.12), fill=(1, 0.94, 0.86), width=0.7)
    page.insert_textbox(
        rect + (6, 5, -6, -5),
        text,
        fontsize=8,
        color=(0.45, 0.08, 0.04),
        align=fitz.TEXT_ALIGN_LEFT,
    )


def collapse_spaces(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def truncate(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[: limit - 3] + "..."


def safe_stem(filename: str) -> str:
    stem = Path(filename).stem
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", stem).strip("._") or "pdf"


def unique_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


# ---------------------------------------------------------------------------
# OCR mismatch detection
# ---------------------------------------------------------------------------

def detect_ocr_mismatch(doc: fitz.Document, text_by_page: list[str]) -> list[str]:
    """Render pages to images, OCR them with Tesseract, and compare against
    the embedded text layer.  A large discrepancy indicates the text layer
    may have been injected or altered after the visible content was created."""
    if not _TESSERACT_AVAILABLE:
        return []

    from PIL import Image  # already installed; import here to keep top-level light

    indicators: list[str] = []
    page_limit = min(doc.page_count, OCR_MAX_PAGES)
    matrix = fitz.Matrix(OCR_RENDER_DPI / 72, OCR_RENDER_DPI / 72)

    for page_index in range(page_limit):
        embedded = text_by_page[page_index] if page_index < len(text_by_page) else ""
        embedded_clean = re.sub(r"\s+", " ", embedded).strip()
        if len(embedded_clean) < OCR_MIN_TEXT_CHARS:
            # Not enough embedded text to make a meaningful comparison
            continue

        try:
            pix = doc.load_page(page_index).get_pixmap(matrix=matrix, alpha=False)
            img = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
            ocr_raw = pytesseract.image_to_string(img, lang="eng", config="--psm 3")
            ocr_clean = re.sub(r"\s+", " ", ocr_raw).strip()
        except Exception as exc:
            indicators.append(f"OCR unavailable on page {page_index + 1}: {exc}")
            continue

        if len(ocr_clean) < OCR_MIN_TEXT_CHARS:
            # OCR produced almost nothing — may indicate invisible / white text
            if len(embedded_clean) >= OCR_MIN_TEXT_CHARS * 2:
                indicators.append(
                    f"OCR found no text on page {page_index + 1} despite embedded text layer"
                )
            continue

        similarity = text_similarity(embedded_clean, ocr_clean)
        if similarity < OCR_MISMATCH_FLAG_THRESHOLD:
            indicators.append(
                f"OCR mismatch page {page_index + 1}: embedded vs OCR similarity "
                f"{similarity:.0%} (below {OCR_MISMATCH_FLAG_THRESHOLD:.0%})"
            )
        elif similarity < OCR_MISMATCH_WARN_THRESHOLD:
            indicators.append(
                f"OCR partial mismatch page {page_index + 1}: similarity {similarity:.0%}"
            )

    return indicators


def write_reports(rows: list[dict[str, Any]], summary: dict[str, Any], report_dir: Path) -> dict[str, Path]:
    export_rows = [flatten_row_for_export(row) for row in rows]
    df = pd.DataFrame(export_rows)
    csv_path = report_dir / "pdf_forensics_report.csv"
    xlsx_path = report_dir / "pdf_forensics_report.xlsx"
    json_path = report_dir / "pdf_forensics_report.json"
    pdf_path = report_dir / "pdf_forensics_report.pdf"
    zip_path = report_dir / "pdf_forensics_bundle.zip"

    df.to_csv(csv_path, index=False)
    df.to_excel(xlsx_path, index=False)
    json_path.write_text(
        json.dumps({"summary": summary, "rows": export_rows}, indent=2),
        encoding="utf-8",
    )
    write_pdf_report(export_rows, summary, pdf_path)
    write_zip_bundle(report_dir, zip_path, [csv_path, xlsx_path, json_path, pdf_path])

    return {
        "csv": csv_path,
        "xlsx": xlsx_path,
        "json": json_path,
        "pdf": pdf_path,
        "zip": zip_path,
    }


def flatten_row_for_export(row: dict[str, Any]) -> dict[str, Any]:
    flattened: dict[str, Any] = {}
    for key, value in row.items():
        if key in {"Visual Diff Links", "Visual Diff Pairs"}:
            continue
        if isinstance(value, list):
            flattened[key] = "; ".join(str(item) for item in value)
        else:
            flattened[key] = value
    return flattened


def write_pdf_report(rows: list[dict[str, Any]], summary: dict[str, Any], path: Path) -> None:
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(path), pagesize=letter, rightMargin=32, leftMargin=32, topMargin=32, bottomMargin=32)
    story: list[Any] = []

    story.append(Paragraph("PDF Forensics Report", styles["Title"]))
    story.append(Spacer(1, 10))
    story.append(
        Table(
            [
                ["Overall verdict", summary.get("overall_verdict", "")],
                ["Total PDFs", str(summary.get("total", ""))],
                ["Flagged PDFs", str(summary.get("flagged", ""))],
                ["Max risk score", str(summary.get("max_risk_score", ""))],
                ["Average risk score", str(summary.get("average_risk_score", ""))],
                ["Baseline", summary.get("baseline_name", "Not provided") or "Not provided"],
            ],
            colWidths=[130, 360],
            style=report_table_style(),
        )
    )
    story.append(Spacer(1, 16))

    for row in rows:
        story.append(Paragraph(escape(str(row.get("PDF", ""))), styles["Heading2"]))
        table_data = [
            ["Risk score", str(row.get("Risk Score", ""))],
            ["Verdict", row.get("Verdict", "")],
            ["Flagged", row.get("Flagged", "")],
            ["Risk reasons", row.get("Risk Reasons", "")],
            ["Metadata issues", row.get("Metadata Issues", "")],
            ["Revisions", row.get("Revisions", "")],
            ["Content diff", row.get("Content Diff", "")],
            ["Visual diff", row.get("Visual Diff", "")],
            ["Signature", row.get("Signature Validity", "")],
            ["Forensic indicators", row.get("Forensic Indicators", "")],
            ["SHA256", row.get("SHA256", "")],
        ]
        story.append(
            Table(
                [[Paragraph(escape(str(left)), styles["BodyText"]), Paragraph(escape(str(right)), styles["BodyText"])]
                 for left, right in table_data],
                colWidths=[110, 380],
                style=report_table_style(),
            )
        )

        consistency_rows = extract_metadata_consistency_rows(str(row.get("Forensic Indicators", "")))
        story.append(Spacer(1, 6))
        story.append(Paragraph("Metadata consistency checks", styles["Heading3"]))
        if consistency_rows:
            consistency_table_data = [["Field", "Details"]] + [[field, details] for field, details in consistency_rows]
            story.append(
                Table(
                    [
                        [
                            Paragraph(escape(str(left)), styles["BodyText"]),
                            Paragraph(escape(str(right)), styles["BodyText"]),
                        ]
                        for left, right in consistency_table_data
                    ],
                    colWidths=[110, 380],
                    style=report_table_style(),
                )
            )
        else:
            story.append(Paragraph("No DocInfo/XMP inconsistencies detected.", styles["BodyText"]))

        story.append(Spacer(1, 14))

    doc.build(story)


def report_table_style() -> TableStyle:
    return TableStyle(
        [
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d9e1e5")),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#edf2f3")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]
    )


def extract_metadata_consistency_rows(forensic_indicators: str) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for part in [item.strip() for item in forensic_indicators.split(";") if item.strip()]:
        if not part.startswith("DocInfo/XMP mismatch in "):
            continue
        match = re.match(r"DocInfo/XMP mismatch in (.*?):\s*(.*)", part)
        if match:
            rows.append((match.group(1).capitalize(), match.group(2)))
    return rows


def write_zip_bundle(report_dir: Path, zip_path: Path, report_files: list[Path]) -> None:
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for report_file in report_files:
            if report_file.exists():
                archive.write(report_file, report_file.name)
        for artifact_dir_name in ("annotated", "visual_diffs"):
            artifact_dir = report_dir / artifact_dir_name
            if not artifact_dir.exists():
                continue
            for artifact in artifact_dir.iterdir():
                if artifact.is_file():
                    archive.write(artifact, f"{artifact_dir_name}/{artifact.name}")