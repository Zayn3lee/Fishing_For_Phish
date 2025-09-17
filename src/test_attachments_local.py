# test_attachments_local.py
"""
Local test harness for attachment_analyzer.py
Creates sample files (exe, pdf, zip with .exe inside, docm with macro text),
reads them as bytes, runs AttachmentRiskAnalyzer.analyze_attachments(),
prints readable output, then cleans up.
"""

import os
import zipfile
import tempfile
import shutil
from attachment_analyzer import AttachmentRiskAnalyzer  # uses your attachment_analyzer.py

def create_test_files(tmpdir):
    """Create a few test files in tmpdir and return their paths."""
    # 1) local exe file
    exe_path = os.path.join(tmpdir, "malware.exe")
    with open(exe_path, "wb") as f:
        f.write(b"Hello malicious world")  # dummy bytes

    # 2) harmless pdf (just header bytes)
    pdf_path = os.path.join(tmpdir, "safe.pdf")
    with open(pdf_path, "wb") as f:
        f.write(b"%PDF-1.4\n% Dummy PDF content\n")

    # 3) office docm with simple "macro-like" text (to trigger simple detector)
    docm_path = os.path.join(tmpdir, "macro.docm")
    with open(docm_path, "wb") as f:
        f.write(b"Sub AutoOpen()\n MsgBox \"Hello\"\nEnd Sub")  # simple textual macro indicator

    # 4) zip archive that contains an .exe inside
    zip_path = os.path.join(tmpdir, "archive_with_exe.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        # inside the zip add a file named 'payload.exe'
        z.writestr("payload.exe", b"Fake exe inside zip")

    return [exe_path, pdf_path, docm_path, zip_path]


def run_test():
    tmpdir = tempfile.mkdtemp(prefix="attachment_test_")
    try:
        print(f"[TEST] Creating test files in: {tmpdir}")
        paths = create_test_files(tmpdir)

        # Build attachments list (filename + content bytes)
        attachments = []
        for p in paths:
            with open(p, "rb") as fh:
                content = fh.read()
            attachments.append({
                "filename": os.path.basename(p),
                "content": content
            })

        # Optional context used by analyzer (subject/body)
        subject = "Important: Verify your PayPal account now"
        body = "Dear user, please check the attached invoice."

        # Run attachment analyzer
        analyzer = AttachmentRiskAnalyzer()
        results = analyzer.analyze_attachments(attachments, email_subject=subject, email_body=body)

        # Pretty-print results
        print("\n=== ATTACHMENT ANALYSIS RESULTS ===")
        for r in results:
            print(f"File: {r['filename']}")
            print(f"  Suspicious: {r['is_suspicious']}")
            if r['risk_factors']:
                for rf in r['risk_factors']:
                    print(f"   - {rf}\n")
            else:
                print("   - No risk factors found\n")
        print("=== END RESULTS ===\n")

    finally:
        # Cleanup temporary test files
        print(f"[TEST] Cleaning up {tmpdir}")
        shutil.rmtree(tmpdir)


if __name__ == "__main__":
    run_test()
