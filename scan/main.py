import argparse
import asyncio
import re
from datetime import datetime
from functools import reduce
from operator import iconcat
from pathlib import Path

from scan.plugin import Plugin, PortScan, SubdomainEnumeration, VulnerabilityScan
from scan.plugin_loader import PluginLoader
from scan.target_scope import TargetScope

DNSX_CMD = {
    "label": "dnsx",
    "cmd": "echo {domain} | dnsx -silent -a -re",
}

# Reports Directories
REPORTS_BASE_PATH = Path.cwd() / "reports"
PLUGIN_LOGS_DIR_NAME = "plugin_logs"
PORT_SCAN_DIR_NAME = "port_scan"
VULNERABILITY_SCAN_DIR_NAME = "vulnerability_scan"

MIN_SCAN = 1
MAX_SCAN = 5


async def subdomain_enumeration(
    target_scope: TargetScope, plugins: set[SubdomainEnumeration]
) -> set[str]:
    print("\n[>] Scanning subdomains:\n")
    tasks = [plugin.run(target_scope) for plugin in plugins]
    return {
        subs
        for subs in reduce(
            iconcat,
            [subdomains.splitlines() for subdomains in await asyncio.gather(*tasks)],
            [],
        )
    }


# TODO: refatorar
async def port_scan(
    ip_adresses: set[str], target_dir_path: Path, plugins: set[PortScan]
):
    print("\n[>] Scanning ports:\n")
    for plugin in plugins:
        max_scan = MIN_SCAN if "rustscan" in plugin.label.lower() else MAX_SCAN
        semaphore = asyncio.Semaphore(max_scan)
        tasks = [
            asyncio.create_task(
                manage_plugin_execution_by_semaphore(
                    TargetScope(ip, target_dir_path), plugin, semaphore
                )
            )
            for ip in ip_adresses
        ]
        await asyncio.gather(*tasks)


async def vulnerability_scan(
    subdomains: set[str], target_dir_path: Path, plugins: set[VulnerabilityScan]
):
    print("\n[>] Executing Vulnerability Scan plugins\n")
    semaphore = asyncio.Semaphore(MAX_SCAN)
    tasks = [
        asyncio.create_task(
            manage_plugin_execution_by_semaphore(
                TargetScope(subdomain, target_dir_path), plugin, semaphore
            )
        )
        for plugin in plugins
        for subdomain in subdomains
    ]
    await asyncio.gather(*tasks)


async def manage_plugin_execution_by_semaphore(
    target_scope: TargetScope, plugin: Plugin, semaphore
):
    async with semaphore:
        await plugin.run(target_scope)


async def extract_ip_adresses_from_subdomains(subdomains: set[str]) -> set[str] | None:
    print("[>] Extracting ip address from subdomains.")

    async def run_dnsx_by_subdomain(subdomain: str):
        print(f"\n[>] Running dnsx for {subdomain}\n")
        try:
            process = await asyncio.create_subprocess_shell(
                cmd=DNSX_CMD["cmd"].format(domain=subdomain),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await process.communicate()

            if stderr:
                print(f"[x] Error: {stderr.decode()}")

            if stdout:
                print(f"[>] Output: \n{stdout.decode()}")
                return stdout.decode()

            return None
        except Exception as e:
            print(f"[x] Plugin {DNSX_CMD['label']} execution failed: {e}")

    ips = {
        ip
        for ip in reduce(
            iconcat,
            [
                hosts.splitlines()
                for hosts in await asyncio.gather(
                    *[run_dnsx_by_subdomain(subdomain) for subdomain in subdomains]
                )
                if hosts is not None
            ],
            [],
        )
    }

    if ips:
        pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
        return {pattern.search(ip.strip())[0] for ip in ips}

    print("[~] No ip address was found.")
    return None


def create_target_reports_directory(target: str) -> Path:
    target_dir_name = re.sub(r"^https?:\/\/", "", target).replace("/", "")
    target_dir_path = REPORTS_BASE_PATH.joinpath(
        f"{target_dir_name}_{datetime.now().timestamp()}"
    )
    target_dir_path.mkdir(parents=True, exist_ok=True)
    return target_dir_path


def create_plugin_logs_directory(target_dir_path: Path) -> Path:
    plugin_logs_path = target_dir_path.joinpath(PLUGIN_LOGS_DIR_NAME)
    plugin_logs_path.mkdir(exist_ok=True)
    return plugin_logs_path


"""TODO
    - se a lista de plugins dos subdominios estiver vazia, então segue executando 
    os demais plugins para o target (verificar se as demais listas de plugins também estão preenchidas)
"""


async def run() -> None:
    parser = argparse.ArgumentParser(prog="ReconScan")
    parser.add_argument("target")
    args = parser.parse_args(["http://php.testsparker.com/"])  # FIXME remover
    target = args.target

    if target:
        target_dir_path = create_target_reports_directory(target)
        plugins = PluginLoader().load()

        print(f"[>] Scanning {target}")

        # FIXME criar apenas se existir plugins para executar
        if plugins["SubdomainEnumeration"]:
            plugin_logs_dir_path = create_plugin_logs_directory(target_dir_path)

            subdomains = await subdomain_enumeration(
                TargetScope(target, target_dir_path), plugins["SubdomainEnumeration"]
            )
            if not subdomains:
                subdomains.add(target)

            if subdomains and plugins["VulnerabilityScan"]:
                plugin_logs_dir_path.joinpath(VULNERABILITY_SCAN_DIR_NAME).mkdir(
                    exist_ok=True
                )
                asyncio.create_task(
                    vulnerability_scan(
                        subdomains, target_dir_path, plugins["VulnerabilityScan"]
                    )
                )

            if subdomains and plugins["PortScan"]:
                plugin_logs_dir_path.joinpath(PORT_SCAN_DIR_NAME).mkdir(exist_ok=True)
                ip_adresses = await extract_ip_adresses_from_subdomains(subdomains)

                if ip_adresses:
                    await port_scan(ip_adresses, target_dir_path, plugins["PortScan"])

        print("Scanning completed.")


def main() -> None:
    try:
        # loop = asyncio.get_event_loop()
        # loop.run_until_complete(run())
        asyncio.run(run())
    except asyncio.exceptions.CancelledError:
        pass
    except RuntimeError:
        pass


if __name__ == "__main__":
    main()
