from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class TargetScope:
    target: str
    report_dir_path: Path = field(default=None)