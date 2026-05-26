import os, shutil
from pathlib import Path

print("\n  OLIMPO ENGINE — DESINSTALACAO\n")

items = [
    "db/olimpo_audit.db",
    "data/raw/access.json",
    "core/__pycache__",
    "security/__pycache__",
    "tools/__pycache__",
    "__pycache__",
]

for item in items:
    p = Path(item)
    if p.exists():
        if p.is_dir(): shutil.rmtree(p); print(f"  Removido: {item}")
        else: p.unlink(); print(f"  Removido: {item}")
    else:
        print(f"  Nao encontrado: {item}")

print("\n  Olimpo Engine desinstalado.")
print("  Os arquivos .py foram mantidos.\n")
