from urllib.parse import quote

from scan.plugin import Executor, VulnerabilityScan
from scan.target_scope import TargetScope


class NucleiSSL(VulnerabilityScan):
    def __init__(self):
        super().__init__()
        self.label = "Nuclei SSL"

    async def run(self, target_scope: TargetScope):
        print(f"[>] Executing plugin {self.label} for {target_scope.target}...")

        cmd = (
            "nuclei -u {target} -o {output_path}/plugin_logs/vulnerability_scan/"
            + quote(target_scope.target, safe="")
            + "_result.txt"
        )
        process, stdout, stderr = await Executor(target_scope).execute(cmd)

        return stdout.decode()
