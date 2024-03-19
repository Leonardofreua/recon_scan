from scan.plugin import Executor, SubdomainEnumeration
from scan.target_scope import TargetScope


class Findomain(SubdomainEnumeration):
    def __init__(self):
        super().__init__()
        self.label = "Findomain"

    async def run(self, target_scope: TargetScope):
        print(f"[>] Executing plugin {self.label}...")

        cmd = "findomain --quiet -t {target} -u {output_path}/plugin_logs/subdomain_enumeration/findomain_report.txt"
        _, stdout, _ = await Executor(target_scope).execute(cmd)

        return stdout.decode() if stdout else None
