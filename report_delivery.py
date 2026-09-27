"""Copy a completed Kali run to the Windows user's local reports folder."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile


INDEX=Path('/opt/ubden-cyber/run-locations.json')


def latest_since(index: Path, after: str) -> Path | None:
    cutoff=dt.datetime.fromisoformat(after.replace('Z','+00:00'))
    if cutoff.tzinfo is None:
        raise ValueError('Başlangıç zamanı UTC saat dilimi içermeli')
    # Engagement timestamps are stored with second precision.
    cutoff=cutoff.replace(microsecond=0)
    try:
        locations=json.loads(index.read_text(encoding='utf-8'))
    except FileNotFoundError:
        return None
    if not isinstance(locations,list):
        raise ValueError('Görev dizini indeksi geçersiz')
    for value in reversed(locations):
        if not isinstance(value,str) or not value.startswith('/'):
            continue
        source=Path(value)
        try:
            meta=json.loads((source/'engagement.json').read_text(encoding='utf-8'))
            started=dt.datetime.fromisoformat(meta['started_at'].replace('Z','+00:00'))
        except (OSError,ValueError,KeyError,TypeError):
            continue
        if started>=cutoff and (source/'REPORT.html').is_file():
            return source
    return None


def files_in(source: Path) -> dict[Path,Path]:
    if source.is_symlink() or not source.is_dir():
        raise ValueError('Kaynak görev dizini geçersiz veya sembolik bağ')
    result={}
    for item in source.rglob('*'):
        if item.is_symlink():
            raise ValueError(f'Görev kanıtında sembolik bağ var: {item.name}')
        if item.is_file():
            result[item.relative_to(source)]=item
    if not result or Path('engagement.json') not in result:
        raise ValueError('Görev kanıtı eksik')
    return result


def digest(path: Path) -> str:
    sha=hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda:handle.read(1024*1024),b''):
            sha.update(block)
    return sha.hexdigest()


def verify(source: Path, destination: Path) -> int:
    originals=files_in(source)
    copies=files_in(destination)
    if originals.keys()!=copies.keys():
        raise ValueError('Windows rapor kopyasında dosya listesi farklı')
    for relative,path in originals.items():
        if digest(path)!=digest(copies[relative]):
            raise ValueError(f'Windows rapor kopyasında SHA-256 farklı: {relative}')
    return len(originals)


def deliver(source: Path, destination_root: Path) -> dict:
    source=source.absolute()
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,120}',source.name):
        raise ValueError('Görev klasörü adı geçersiz')
    files_in(source)
    destination_root.mkdir(parents=True,exist_ok=True)
    if destination_root.is_symlink():
        raise ValueError('Windows rapor kökü sembolik bağ olamaz')
    if destination_root.resolve()==source.resolve() or destination_root.resolve().is_relative_to(source.resolve()):
        raise ValueError('Raporlar kaynak dizinin içine kopyalanamaz')
    destination=destination_root/source.name
    if destination.exists():
        count=verify(source,destination)
        return {'status':'already_verified','source':str(source),'destination':str(destination),'files':count}
    staging=Path(tempfile.mkdtemp(prefix='.ubden-pending-',dir=destination_root))
    try:
        shutil.copytree(source,staging,dirs_exist_ok=True,symlinks=False)
        count=verify(source,staging)
        os.replace(staging,destination)
    finally:
        if staging.exists():
            if staging.resolve().parent!=destination_root.resolve():
                raise ValueError('Geçici rapor yolu beklenen kökün dışında')
            shutil.rmtree(staging)
    return {'status':'copied','source':str(source),'destination':str(destination),'files':count}


def main():
    parser=argparse.ArgumentParser()
    location=parser.add_mutually_exclusive_group(required=True)
    location.add_argument('--source',type=Path)
    location.add_argument('--latest',action='store_true')
    parser.add_argument('--after',help='Yeni görevin UTC başlangıç zamanı')
    parser.add_argument('--destination',type=Path,required=True)
    args=parser.parse_args()
    source=args.source if args.source else latest_since(INDEX,args.after or dt.datetime.min.replace(
        tzinfo=dt.timezone.utc).isoformat())
    result={'status':'none'} if source is None else deliver(source,args.destination)
    print(json.dumps(result,ensure_ascii=False))


if __name__=='__main__':
    main()
