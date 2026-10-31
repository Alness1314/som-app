import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import hashlib
import zipfile
import pytest
from som_api.services.files import inspect_file

def test_sha256_and_format(tmp_path):
    p=tmp_path/'events.csv'; p.write_text('a,b\n1,2',encoding='utf8')
    fmt,digest,size=inspect_file(p)
    assert fmt=='CSV' and digest==hashlib.sha256(p.read_bytes()).hexdigest() and size==p.stat().st_size

def test_unknown_preserved_as_unknown(tmp_path):
    p=tmp_path/'data.bin';p.write_bytes(b'not parsed')
    assert inspect_file(p)[0]=='UNKNOWN'

def test_zip_path_traversal_rejected(tmp_path):
    p=tmp_path/'bad.zip'
    with zipfile.ZipFile(p,'w') as z:z.writestr('../escape.txt','x')
    with pytest.raises(ValueError,match='ruta insegura'):inspect_file(p)
