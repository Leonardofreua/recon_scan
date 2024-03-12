from scan.plugin import Executor, PortScan
from scan.target_scope import TargetScope


class RustscanAllPorts(PortScan):
    def __init__(self):
        super().__init__()
        self.label = "Rustscan All Ports"
        self.mono_process = True

    async def run(self, target_scope: TargetScope):
        print(f"[>] Executing plugin {self.label} for {target_scope.target}...")

        cmd = "rustscan -a {target} -- -A -Pn -sC -sV 2>&1 | sed -r 's/\x1b\[[0-9;]*m//g' | tee {output_path}/plugin_logs/port_scan/rustscan_{target}_report.txt"  # TODO adicionar -sS no comando do rustscan
        process, stdout, stderr = await Executor(target_scope).execute(cmd)

        return stdout.decode()
