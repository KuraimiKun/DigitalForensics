from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import fitz
import pikepdf

from app.analyzer import analyze_files, extract_metadata_consistency_rows, scan_active_content, write_reports


class AnalyzerTests(unittest.TestCase):
    def setUp(self) -> None:
        test_root = Path("runtime") / "test_runs"
        test_root.mkdir(parents=True, exist_ok=True)
        self.temp_dir = tempfile.TemporaryDirectory(dir=test_root)
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def write_pdf(
        self,
        name: str,
        text: str,
        metadata: dict[str, str] | None = None,
        fontsize: int = 12,
    ) -> Path:
        path = self.root / name
        doc = fitz.open()
        page = doc.new_page()
        page.insert_text((72, 72), text, fontsize=fontsize)
        if metadata:
            doc.set_metadata(metadata)
        doc.save(path)
        doc.close()
        return path

    def test_clean_pdf_without_baseline_is_not_tamper_flagged(self) -> None:
        pdf = self.write_pdf("clean.pdf", "Clean document")

        rows, summary = analyze_files([pdf], None, self.root / "report")

        self.assertEqual(rows[0]["Flagged"], "No")
        self.assertEqual(rows[0]["Verdict"], "No strong tamper indicators")
        self.assertLess(rows[0]["Risk Score"], 30)
        self.assertEqual(rows[0]["Signature Validity"], "No signature")
        self.assertEqual(summary["overall_verdict"], "No strong tamper indicators")

    def test_modified_pdf_against_baseline_is_flagged(self) -> None:
        metadata = {
            "creationDate": "D:20240501000000Z",
            "modDate": "D:20240501000000Z",
        }
        baseline = self.write_pdf("baseline.pdf", "Invoice\nAmount: 100", metadata)
        modified = self.write_pdf("modified.pdf", "Invoice\nAmount: 250", metadata)

        rows, summary = analyze_files([modified], baseline, self.root / "report")

        self.assertEqual(rows[0]["Flagged"], "Yes")
        self.assertEqual(rows[0]["Verdict"], "Modified from baseline")
        self.assertGreaterEqual(rows[0]["Risk Score"], 60)
        self.assertIn("Text changed", rows[0]["Content Diff"])
        self.assertEqual(summary["overall_verdict"], "Modified from baseline")

    def test_corrupted_pdf_is_handled_and_flagged(self) -> None:
        bad_pdf = self.root / "bad.pdf"
        bad_pdf.write_bytes(b"%PDF-1.7\nnot a valid document\n")

        rows, summary = analyze_files([bad_pdf], None, self.root / "report")

        self.assertEqual(rows[0]["Flagged"], "Yes")
        self.assertEqual(rows[0]["Verdict"], "Unreadable / corrupted")
        self.assertGreaterEqual(rows[0]["Risk Score"], 80)
        self.assertIn("Unreadable or corrupted PDF", rows[0]["Metadata Issues"])
        self.assertEqual(summary["overall_verdict"], "Unreadable / corrupted")

    def test_visual_diff_and_export_bundle_are_generated(self) -> None:
        baseline = self.write_pdf("baseline.pdf", "Amount: 100", fontsize=24)
        modified = self.write_pdf("modified.pdf", "Amount: 999999", fontsize=24)

        report_dir = self.root / "report"
        rows, summary = analyze_files([modified], baseline, report_dir)
        report_paths = write_reports(rows, summary, report_dir)

        self.assertIn("visually changed", rows[0]["Visual Diff"])
        self.assertTrue(rows[0]["Visual Diff Links"])
        self.assertTrue(rows[0]["Visual Diff Pairs"])
        self.assertTrue((report_dir / "visual_diffs" / rows[0]["Visual Diff Links"][0]).exists())
        first_pair = rows[0]["Visual Diff Pairs"][0]
        self.assertIn("risk_level", first_pair)
        self.assertIn(first_pair["risk_level"], {"low", "medium", "high"})
        self.assertIn("change_percent", first_pair)
        self.assertIsInstance(first_pair["change_percent"], float)
        self.assertTrue((report_dir / "visual_diffs" / first_pair["baseline"]).exists())
        self.assertTrue((report_dir / "visual_diffs" / first_pair["current"]).exists())
        self.assertTrue((report_dir / "visual_diffs" / first_pair["diff"]).exists())
        for path in report_paths.values():
            self.assertTrue(path.exists())

    def test_active_content_markers_are_detected(self) -> None:
        indicators = scan_active_content(b"<< /OpenAction 4 0 R /JavaScript 5 0 R /EmbeddedFile 6 0 R >>")

        self.assertTrue(any("/OpenAction" in indicator for indicator in indicators))
        self.assertTrue(any("/JavaScript" in indicator for indicator in indicators))
        self.assertTrue(any("/EmbeddedFile" in indicator for indicator in indicators))

    def test_ocr_mismatch_is_detected_when_text_layer_differs_from_image(self) -> None:
        """Create a PDF whose rendered image contains one phrase, but whose
        embedded text layer contains a completely different (injected) phrase.
        The OCR check should detect the discrepancy and add an indicator."""
        from app.analyzer import _TESSERACT_AVAILABLE, detect_ocr_mismatch

        if not _TESSERACT_AVAILABLE:
            self.skipTest("Tesseract not available in this environment")

        # Build a PDF with visible text "Hello World" on the page
        pdf_path = self.write_pdf(
            "ocr_test.pdf",
            "Hello World\n" * 30,  # enough chars to exceed OCR_MIN_TEXT_CHARS
        )

        doc = fitz.open(str(pdf_path))
        try:
            # Pass a *different* embedded text that doesn't match what Tesseract will read
            fabricated_text = ["Invoice total: $999999\n" * 30]
            indicators = detect_ocr_mismatch(doc, fabricated_text)
        finally:
            doc.close()

        # Should have flagged at least one page as mismatched
        self.assertTrue(
            any("mismatch" in ind.lower() or "no text" in ind.lower() for ind in indicators),
            f"Expected OCR mismatch indicator, got: {indicators}",
        )

    def test_xmp_docinfo_mismatch_is_reported(self) -> None:
        pdf_path = self.write_pdf(
            "xmp_mismatch.pdf",
            "Metadata mismatch sample",
            {
                "creationDate": "D:20240101000000Z",
                "modDate": "D:20240102000000Z",
                "producer": "DocInfo Producer",
                "creator": "DocInfo Creator",
            },
        )

        with pikepdf.Pdf.open(pdf_path, allow_overwriting_input=True) as pdf:
            with pdf.open_metadata(set_pikepdf_as_editor=False) as meta:
                meta["xmp:CreateDate"] = "2024-01-01T00:00:00Z"
                meta["xmp:ModifyDate"] = "2024-01-10T00:00:00Z"
                meta["pdf:Producer"] = "Different Producer"
                meta["xmp:CreatorTool"] = "Different Creator"
            pdf.save(pdf_path)

        rows, _summary = analyze_files([pdf_path], None, self.root / "report")
        indicators = rows[0]["Forensic Indicators"]

        self.assertIn("DocInfo/XMP mismatch", indicators)

        consistency_rows = extract_metadata_consistency_rows(indicators)
        self.assertTrue(consistency_rows)

    def test_fake_redaction_indicator_is_reported(self) -> None:
        path = self.root / "fake_redaction.pdf"
        doc = fitz.open()
        page = doc.new_page()
        page.insert_text((72, 72), "CONFIDENTIAL SALARY 95000", fontsize=18)
        page.draw_rect(fitz.Rect(70, 55, 330, 90), fill=(0, 0, 0), color=(0, 0, 0))
        doc.save(path)
        doc.close()

        rows, _summary = analyze_files([path], None, self.root / "report")

        self.assertIn("Potential fake redactions", rows[0]["Forensic Indicators"])
        self.assertIn("Potential fake redactions", rows[0]["Risk Reasons"])
        self.assertRegex(rows[0]["Forensic Indicators"], r"confidence:\s*(High|Medium|Low)")
        self.assertRegex(rows[0]["Verdict"], r"Potential fake redactions \((High|Medium|Low) confidence\)")


if __name__ == "__main__":
    unittest.main()
