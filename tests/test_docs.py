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
