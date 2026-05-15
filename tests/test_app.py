from __future__ import annotations

import io
import re
import unittest

import fitz
from fastapi.testclient import TestClient

from app.main import app


class AppRouteTests(unittest.TestCase):
    def pdf_bytes(self, text: str) -> bytes:
        doc = fitz.open()
        page = doc.new_page()
        page.insert_text((72, 72), text, fontsize=24)
        stream = doc.write()
        doc.close()
        return stream

    def test_upload_renders_results_and_downloads(self) -> None:
        client = TestClient(app)
        response = client.post(
            "/analyze",
            files=[
                ("pdf_files", ("modified.pdf", io.BytesIO(self.pdf_bytes("Amount: 999999")), "application/pdf")),
                ("baseline_pdf", ("baseline.pdf", io.BytesIO(self.pdf_bytes("Amount: 100")), "application/pdf")),
            ],
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("Modified from baseline", response.text)
        self.assertIn("Side-by-side Visual Diff", response.text)
        self.assertIn("_baseline.png", response.text)
        self.assertIn("_current.png", response.text)
        self.assertIn("_diff.png", response.text)
        match = re.search(r"/download/([a-f0-9]+)/csv", response.text)
        self.assertIsNotNone(match)
        report_id = match.group(1)

        for file_type in ("csv", "xlsx", "json", "pdf", "zip"):
            download = client.get(f"/download/{report_id}/{file_type}")
            self.assertEqual(download.status_code, 200)
            self.assertGreater(len(download.content), 100)


if __name__ == "__main__":
    unittest.main()
