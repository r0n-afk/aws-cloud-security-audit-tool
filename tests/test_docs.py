import os

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


def _read(*parts):
    with open(os.path.join(BASE, *parts), encoding='utf-8') as f:
        return f.read()


def test_requirements_dev_pins_pytest():
    assert 'pytest==' in _read('requirements-dev.txt')


def test_readme_tests_section_installs_dev_requirements():
    assert 'requirements-dev.txt' in _read('README.md')


def test_readme_states_python_version_floor():
    txt = _read('README.md')
    assert '3.10–3.14' in txt
    assert 'Python 3.10+' not in txt


def test_srs_states_python_version_floor():
    txt = _read('docs', 'SRS.md')
    assert '3.10–3.14' in txt
    assert 'Python 3.10+' not in txt


def test_ci_workflow_runs_pytest_on_supported_pythons():
    txt = _read('.github', 'workflows', 'tests.yml')
    assert 'pytest tests' in txt
    assert "'3.10'" in txt and "'3.14'" in txt
    assert 'windows-latest' in txt and 'ubuntu-latest' in txt
    assert 'timeout-minutes: 15' in txt
    assert 'pip-audit' in txt


def test_weasyprint_import_stays_lazy():
    with open(os.path.join(BASE, 'src', 'reports', 'render.py'), encoding='utf-8') as f:
        for line in f:
            s = line.strip()
            if s.startswith('from weasyprint') or s.startswith('import weasyprint'):
                assert line.startswith(' '), f'weasyprint import must stay inside a function: {s}'


def test_readme_links_match_repo_identity():
    txt = _read('README.md')
    assert 'github.com/r0n-afk/aws-cloud-security-audit-tool' in txt
    assert 'github.com/r0n-k/' not in txt


def test_readme_image_links_resolve():
    import re
    txt = _read('README.md')
    for rel in re.findall(r'!\[[^\]]*\]\(([^)]+)\)', txt):
        if rel.startswith(('http://', 'https://')):
            continue
        assert os.path.exists(os.path.join(BASE, rel)), f'broken image: {rel}'


def test_contributing_documents_maintainer_split():
    txt = _read('CONTRIBUTING.md')
    assert 'r0n-afk' in txt and 'genrex-bot' in txt
    assert 'requirements-dev.txt' in txt
    assert 'pytest tests' in txt
