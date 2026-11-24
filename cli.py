"""
PrismRedline CLI mode
Clean one-line status updates and text progress bars.
"""

import sys


class Status:
    def __init__(self):
        self.last_len = 0

    def update(self, msg: str):
        """Overwrite the current line with a status message."""
        padded = msg.ljust(self.last_len)
        sys.stdout.write(f"\r{padded}")
        sys.stdout.flush()
        self.last_len = len(msg)

    def progress(self, current: int, total: int, prefix: str = ""):
        """Linux-style text progress bar on one line."""
        if total <= 0:
            return
        width = 30
        filled = int(width * current / total)
        bar = "█" * filled + "░" * (width - filled)
        pct = int(100 * current / total)
        self.update(f"{prefix}[{bar}] {pct}% ({current}/{total})")

    def done(self, msg: str = "Done"):
        self.update(msg)
        print()  # newline when finished
        self.last_len = 0

    def info(self, msg: str):
        """Print a permanent one-line info message."""
        if self.last_len:
            print()
            self.last_len = 0
        print(msg)


def show_checklist(phase: int):
    """Print phase checklist criteria."""
    from pathlib import Path

    import yaml
    p = Path(__file__).parent / "phase_checklist.yaml"
    if not p.exists():
        return
    data = yaml.safe_load(p.read_text()) or {}
    info = data.get("phases", {}).get(phase, {})
    if not info:
        return
    print(f"\nPhase {phase} checklist — {info.get('name','')}")
    for c in info.get("criteria", []):
        print(f"  [ ] {c}")
    print()
