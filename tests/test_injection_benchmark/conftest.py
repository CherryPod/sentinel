"""Path setup for injection benchmark tests."""
import sys
from pathlib import Path

_PROJECT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_PROJECT / "scripts"))
sys.path.insert(0, str(_PROJECT / "scripts" / "injection_benchmark"))
