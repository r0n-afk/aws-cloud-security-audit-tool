import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src'))

from app import create_app

# Local dev: always pick up template/static edits without restarting.
os.environ.setdefault('FLASK_DEBUG', '1')

app = create_app()

debug = os.environ.get('FLASK_DEBUG', '1') == '1'
app.run(
    host='127.0.0.1',
    port=5000,
    debug=debug,
    use_reloader=debug,
    extra_files=None,
)
