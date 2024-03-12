from urllib.parse import quote

from scan.plugin import DirEnumeration, Executor
from scan.target_scope import TargetScope


class FeroxbusterRaftMedium(DirEnumeration):
    def __init__(self):
        super().__init__()
        self.label = "Feroxbuster Raft Medium"

    async def run(self, target_scope: TargetScope):
        print(f"[>] Executing plugin {self.label}...")

        cmd = (
            "feroxbuster -u {target} --quiet -o {output_path}/plugin_logs/dir_enumeration/"
            + quote(target_scope.target, safe="")
            + "_report.txt"
        )
        process, stdout, stderr = await Executor(target_scope).execute(cmd)

        return stdout.decode()
