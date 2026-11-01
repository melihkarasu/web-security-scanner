import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# Testler gerçek tarama geçmişine (data/) asla yazmasın: geçici veritabanı.
if not os.environ.get("WSS_HISTORY_DB"):
    os.environ["WSS_HISTORY_DB"] = os.path.join(tempfile.mkdtemp(prefix="wss-test-history-"), "history.sqlite3")
