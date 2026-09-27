"""install.sh, çalışma zamanında import edilen tüm yerel modülleri /opt'a kopyalamalı.

'ModuleNotFoundError: No module named service_probes' türü kurulum hatalarını
kalıcı önler: giriş dosyalarının (wizard.py, report_v2.py, credential_probes.py)
import ettiği her YEREL modülün install.sh kopya listesinde bulunduğunu doğrular.
Ağ/Kali gerektirmez.
"""
import re
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ENTRY_FILES = ["wizard.py", "report_v2.py", "credential_probes.py"]

_IMPORT_RE = re.compile(r"^\s*(?:from\s+([a-zA-Z_][\w]*)\s+import|import\s+([a-zA-Z_][\w][\w,\s]*))", re.M)


def _local_modules():
    return {p.stem for p in REPO.glob("*.py")}


def _imports(pyfile: Path, local: set) -> set:
    found = set()
    for from_mod, import_mods in _IMPORT_RE.findall(pyfile.read_text(encoding="utf-8")):
        if from_mod:
            found.add(from_mod)
        for part in import_mods.split(","):
            name = part.strip().split(" ")[0].split(".")[0].strip()
            if name:
                found.add(name)
    return {m for m in found if m in local}


class InstallManifestTests(unittest.TestCase):
    def test_all_imported_local_modules_are_installed(self):
        install = (REPO / "install.sh").read_text(encoding="utf-8")
        local = _local_modules()
        required = set()
        for entry in ENTRY_FILES:
            required |= _imports(REPO / entry, local)
        # Giriş dosyalarının kendisi de kopyalanmalı.
        required |= {"wizard", "report_v2", "credential_probes"}
        missing = sorted(m for m in required
                         if f"/{m}.py" not in install and f'"{m}.py"' not in install and f"{m}.py" not in install)
        self.assertEqual(missing, [], f"install.sh bu modülleri kopyalamıyor: {missing}")

    def test_default_credentials_data_is_installed(self):
        install = (REPO / "install.sh").read_text(encoding="utf-8")
        self.assertIn("default_credentials.json", install)


if __name__ == "__main__":
    unittest.main()
