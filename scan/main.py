import argparse
import asyncio
import re
from datetime import datetime
from functools import reduce
from operator import iconcat
from pathlib import Path

from scan.plugin import Plugin, PortScan, SubdomainEnumeration
from scan.plugin_loader import PluginLoader
from scan.plugins.util.dnsx import Dnsx
from scan.target_scope import TargetScope

# Reports Directories
REPORTS_BASE_PATH = Path.cwd() / "reports"
PLUGIN_LOGS_DIR_NAME = "plugin_logs"

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


async def port_scan(
    target_domains: set[str], target_dir_path: Path, plugins: set[PortScan]
):
    print("\n[>] Scanning ports:\n")

    ip_adresses = await extract_ip_adresses_from_target(target_domains)
    if ip_adresses:
        plugins = sorted(plugins, key=lambda plugin: plugin.mono_process)
        for plugin in plugins:
            semaphore = asyncio.Semaphore(MIN_SCAN if plugin.mono_process else MAX_SCAN)
            tasks = [
                asyncio.create_task(
                    manage_plugin_execution_by_semaphore(
                        TargetScope(ip, target_dir_path), plugin, semaphore
                    )
                )
                for ip in ip_adresses
            ]
            await asyncio.gather(*tasks)


async def general_plugins(
    target_domains: set[str],
    target_dir_path: Path,
    plugins: set[Plugin],
):
    print("\n[>] Executing Scan for general plugins\n")
    semaphore = asyncio.Semaphore(MAX_SCAN)
    tasks = [
        asyncio.create_task(
            manage_plugin_execution_by_semaphore(
                TargetScope(target_domain, target_dir_path), plugin, semaphore
            )
        )
        for plugin in plugins
        for target_domain in target_domains
    ]
    await asyncio.gather(*tasks)


async def extract_ip_adresses_from_target(target_domains: set[str]) -> set[str] | None:
    print("[>] Extracting ip address from subdomains.")
    semaphore = asyncio.Semaphore(MAX_SCAN)
    dnsx = Dnsx()
    tasks = [
        asyncio.create_task(
            manage_plugin_execution_by_semaphore(
                TargetScope(target_domain), dnsx, semaphore
            )
        )
        for target_domain in target_domains
    ]

    ips = {
        ip
        for ip in reduce(
            iconcat,
            [
                hosts.splitlines()
                for hosts in await asyncio.gather(*tasks)
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


async def manage_plugin_execution_by_semaphore(
    target_scope: TargetScope, plugin: Plugin, semaphore
):
    async with semaphore:
        return await plugin.run(target_scope)


def create_target_reports_directory(target: str) -> Path:
    target_dir_path = REPORTS_BASE_PATH.joinpath(
        f"{target}_{datetime.now().timestamp()}"
    )
    target_dir_path.mkdir(parents=True, exist_ok=True)
    return target_dir_path


def create_plugin_logs_directory(target_dir_path: Path) -> Path:
    plugin_logs_path = target_dir_path.joinpath(PLUGIN_LOGS_DIR_NAME)
    plugin_logs_path.mkdir(exist_ok=True)
    return plugin_logs_path


def create_plugins_directory_by_category(
    target_dir_path: Path, plugins_categories: set[str]
):
    plugin_logs_dir_path = create_plugin_logs_directory(target_dir_path)
    for category in plugins_categories:
        plugin_logs_dir_path.joinpath(category).mkdir(exist_ok=True)


def normalize_url(url: str):
    return (
        re.sub(r"^https?:\/\/(www\.)?", "", url, flags=re.IGNORECASE).strip().strip("/")
    )


async def run() -> None:
    parser = argparse.ArgumentParser(prog="ReconScan")
    parser.add_argument("target")
    args = parser.parse_args()
    target = args.target

    if target:
        categorized_plugins = PluginLoader().load()

        print(f"[>] Scanning {target}")

        target = normalize_url(target)
        target_dir_path = create_target_reports_directory(target)

        create_plugins_directory_by_category(
            target_dir_path,
            {category for category, plugins in categorized_plugins.items() if plugins},
        )

        target_domains = {target}
        if categorized_plugins["subdomain_enumeration"]:
            subdomains = await subdomain_enumeration(
                TargetScope(target, target_dir_path),
                categorized_plugins["subdomain_enumeration"],
            )
            target_domains.update(subdomains)

        if target_domains:
            for category, plugins in categorized_plugins.items():
                if category == "subdomain_enumeration":
                    continue

                if category in ["vulnerability_scan", "dir_enumeration"]:
                    asyncio.create_task(
                        general_plugins(target_domains, target_dir_path, plugins)
                    )
                elif category == "port_scan":
                    await port_scan(target_domains, target_dir_path, plugins)

        print("Scanning completed.")


def main() -> None:
    try:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(run())

        pending = asyncio.all_tasks(loop)
        loop.run_until_complete(asyncio.gather(*pending))
    except asyncio.exceptions.CancelledError:
        pass
    except RuntimeError:
        pass


if __name__ == "__main__":
    main()
