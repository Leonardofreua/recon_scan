from scan.plugin import PortScan, Executor
from scan.target_scope import TargetScope


class NaabuAllPorts(PortScan):
    def __init__(self):
        super().__init__()
        self.label = "Naabu All Ports"

    async def run(self, target_scope: TargetScope):
        print(f"[>] Executing plugin {self.label} for {target_scope.target}...")

        cmd = "naabu -silent -host {target} -o {output_path}/plugin_logs/port_scan/naabu_{target}_report.txt"
        process, stdout, stderr = await Executor(target_scope).execute(cmd)

        return stdout.decode()
