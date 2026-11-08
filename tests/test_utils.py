import uuid

from app.utils.helpers import generate_unique_filename
from app.utils.validators import validate_assessment_name, validate_severity


def test_validate_assessment_name():
    assert validate_assessment_name('ok') is True
    assert validate_assessment_name('') is False
    assert validate_assessment_name('   ') is False
    assert validate_assessment_name('x' * 201) is False
    assert validate_assessment_name('x' * 200) is True


def test_validate_severity():
    assert validate_severity('high') is True
    assert validate_severity('nope') is False


def test_generate_unique_filename():
    name = generate_unique_filename('pdf')
    assert name.endswith('.pdf')
    assert name.startswith('report_')
    # unique id portion present
    assert len(name.split('_')) >= 3