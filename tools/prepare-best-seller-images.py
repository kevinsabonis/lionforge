"""Copy generated originals and encode web assets from a JSON manifest."""
import json
import shutil
import sys
from pathlib import Path
from PIL import Image

root = Path(__file__).resolve().parents[1]
originals = root / 'output' / 'best-seller-vials'
assets = root / 'assets' / 'lfp' / 'best-sellers'
originals.mkdir(parents=True, exist_ok=True)
assets.mkdir(parents=True, exist_ok=True)
for item in json.loads(Path(sys.argv[1]).read_text(encoding='utf-8-sig')):
    source = Path(item['source'])
    shutil.copy2(source, originals / f"{item['slug']}-v1.png")
    with Image.open(source) as im:
        im.save(assets / f"{item['slug']}-v1.webp", 'WEBP', quality=88, method=6)
    print(item['slug'])
