import json
from pathlib import Path
import pytest
from model_assurance.cli import check_url, inventory, main, sha256_file

def test_hash(tmp_path):
    p = tmp_path / 'x.gguf'
    p.write_bytes(b'abc')
    assert sha256_file(p) == 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'

def test_inventory_and_review(tmp_path):
    (tmp_path / 'config.json').write_text('{"trust_remote_code": true}')
    files, findings = inventory(tmp_path, 10, 1024)
    assert len(files) == 1
    assert any(f['title'] == 'remote_code_configuration' for f in findings)

def test_symlink_skipped(tmp_path):
    target = tmp_path / 'target'
    target.write_text('hello')
    (tmp_path / 'link').symlink_to(target)
    files, findings = inventory(tmp_path, 10, 1024)
    assert len(files) == 1
    assert any(f['title'] == 'Symlink skipped' for f in findings)

def test_remote_denied():
    with pytest.raises(ValueError):
        check_url('https://example.com', False)
    assert check_url('http://127.0.0.1:11434', False).endswith('11434')

def test_cli_static(tmp_path):
    (tmp_path / 'model.gguf').write_bytes(b'GGUF')
    output = tmp_path / 'report.json'
    assert main(['--path', str(tmp_path), '--output', str(output)]) == 0
    report = json.loads(output.read_text())
    assert report['summary']['files_inventoried'] >= 1
    assert report['summary']['verdict'].startswith('ASSESSMENT_INCOMPLETE')
