from scan.plugin import Executor, Util
from scan.target_scope import TargetScope


class Dnsx(Util):
    def __init__(self):
        super().__init__()
        self.label = "Dnsx | DNS toolkit"

    async def run(self, target_scope: TargetScope):
        print(f"[>] Executing plugin {self.label} for {target_scope.target}")

        cmd = "echo {target} | dnsx -silent -a -re"
        process, stdout, stderr = await Executor(target_scope).execute(cmd)

        return stdout.decode() if stdout else None
