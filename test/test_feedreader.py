import subprocess

def test_basic_atom():
    r = subprocess.run(["./feedreader", "https://xkcd.com/atom.xml"], capture_output=True)
    assert r.returncode == 0
    assert r.stdout

def test_basic_rss():
    r = subprocess.run(["./feedreader", "https://www.fit.vut.cz/fit/news-rss/"], capture_output=True)
    assert r.returncode == 0
    assert r.stdout

def test_invalid_url():
    r = subprocess.run(["./feedreader", "https://www.fit.vutfit/news-rss/"], capture_output=True)
    assert r.returncode != 0
    assert r.stderr

def test_invalid_xml():
    r = subprocess.run(["./feedreader", "https://www.google.com/"], capture_output=True)
    assert r.returncode != 0
    assert r.stderr

def test_invalid_args():
    r = subprocess.run(["./feedreader", "https://xkcd.com/atom.xml", "-w"], capture_output=True)
    assert r.returncode != 0
    assert r.stderr

def test_feedfile():
    r = subprocess.run(["./feedreader", "-f", "test/feedfile.txt"], capture_output=True)
    assert r.returncode == 0
    assert r.stdout

def test_no_urls():
    r = subprocess.run(["./feedreader", "-f", "test/empty.txt"], capture_output=True)
    assert r.returncode != 0
    assert r.stderr

def test_show_url():
    r = subprocess.run(["./feedreader", "https://what-if.xkcd.com/feed.atom", "-u"], capture_output=True)
    out_lines = r.stdout.splitlines()
    assert r.returncode == 0
    assert out_lines[2].startswith(b"URL: ")
    assert not out_lines[3]

def test_show_author():
    r = subprocess.run(["./feedreader", "https://what-if.xkcd.com/feed.atom", "-a"], capture_output=True)
    out_lines = r.stdout.splitlines()
    assert r.returncode == 0
    assert out_lines[2].startswith(b"Autor: ")
    assert not out_lines[3]

def test_show_time():
    r = subprocess.run(["./feedreader", "https://what-if.xkcd.com/feed.atom", "-T"], capture_output=True)
    out_lines = r.stdout.splitlines()
    assert r.returncode == 0
    assert out_lines[2].startswith(b"Aktualizace: ")
    assert not out_lines[3]

def test_no_empty_lines():
    r = subprocess.run(["./feedreader", "https://what-if.xkcd.com/feed.atom"], capture_output=True)
    out_lines = r.stdout.splitlines()
    assert r.returncode == 0
    for line in out_lines:
        assert line

def test_empty_lines_multiple_sources():
    r = subprocess.run(["./feedreader", "https://what-if.xkcd.com/feed.atom", "https://xkcd.com/atom.xml", "https://www.fit.vut.cz/fit/news-rss/"], capture_output=True)
    out_lines = r.stdout.splitlines()
    assert r.returncode == 0
    empty_lines = 0
    for line in out_lines:
        if not line:
            empty_lines += 1
    assert empty_lines == 2

def test_empty_lines_details():
    r = subprocess.run(["./feedreader", "https://what-if.xkcd.com/feed.atom", "-u"], capture_output=True)
    out_lines = r.stdout.splitlines()
    assert r.returncode == 0
    assert out_lines[0] and out_lines[1] and out_lines[2]
    assert not out_lines[3]
    assert out_lines[4]
