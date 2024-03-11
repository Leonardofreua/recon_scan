from dataclasses import dataclass
from pathlib import Path


@dataclass
class TargetScope:
    target: str
    report_dir_path: Path
