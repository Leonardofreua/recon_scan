import asyncio
from typing import Protocol

from scan.target_scope import TargetScope


class Plugin(Protocol):
    title: str
    enabled: bool = True

    async def run(self, service):
        raise NotImplementedError


class PortScan(Plugin):
    def __init__(self) -> None:
        super().__init__()
        self.specific_ports = False


class SubdomainEnumeration(Plugin):
    pass


class DirEnumeration(Plugin):
    pass


class VulnerabilityScan(Plugin):
    pass


class Executor:
    def __init__(self, target_scope: TargetScope) -> None:
        self.target_scope = target_scope

    async def execute(self, cmd: str):
        if cmd and not cmd.isspace():
            process = await asyncio.create_subprocess_shell(
                cmd.format(
                    target=self.target_scope.target,
                    output_path=self.target_scope.report_dir_path,
                ),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await process.communicate()
            return process, stdout, stderr
