from scan.plugin import Executor, SubdomainEnumeration
from scan.target_scope import TargetScope


class Subfinder(SubdomainEnumeration):
    def __init__(self):
        super().__init__()
        self.label = "Subfinder"

    async def run(self, target_scope: TargetScope):
        print(f"[>] Executing plugin {self.label}...")

        cmd = "subfinder -silent -d {target} -o {output_path}/plugin_logs/subdomain_enumeration/subfinder_report.txt"
        _, stdout, _ = await Executor(target_scope).execute(cmd)

        return stdout.decode() if stdout else None
