import importlib.util
import inspect
from pathlib import Path

from scan.plugin import (DirEnumeration, Plugin, PortScan,
                         SubdomainEnumeration, VulnerabilityScan)

PLUGIN_TYPE_ERROR_MESSAGE = "The plugin {label} from {filename} needs to be a subclass of PortScan, SubdomainEnumeration, DirEnumeration or VulnerabilityScan."


class PluginLoader:
    def __init__(self) -> None:
        self.plugins = {
            "port_scan": set(),
            "subdomain_enumeration": set(),
            "dir_enumeration": set(),
            "vulnerability_scan": set(),
        }

    def load(self) -> dict[set[Plugin]]:
        plugins_path = Path("scan/plugins")
        for plugin_file in plugins_path.iterdir():
            try:
                if (
                    plugin_file.is_file()
                    and not plugin_file.name.startswith("_")
                    and plugin_file.name.endswith(".py")
                ):
                    plugins_module_path = str(plugins_path).replace("/", ".")
                    spec = importlib.util.spec_from_file_location(
                        plugins_module_path, str(plugin_file.absolute())
                    )
                    plugin = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(plugin)

                    members = inspect.getmembers(plugin, predicate=inspect.isclass)
                    for _, plugin_object in members:
                        if plugins_module_path == plugin_object.__module__:
                            if self._is_valid_plugin_type(plugin_object):
                                self._add(plugin_object(), plugin_file.name)
                            else:
                                print(
                                    PLUGIN_TYPE_ERROR_MESSAGE.format(
                                        label=plugin_object.__name__,
                                        filename=plugin_file.name,
                                    )
                                )
            except ImportError as e:
                print(f"Cannot import {plugin_file.name}")
                raise e
        return self.plugins

    def _add(self, plugin: Plugin, filename: str) -> None:
        if plugin.enabled:
            if plugin.label is None or plugin.label.isspace():
                raise NameError(
                    f"The plugin of class {plugin.__class__.__name__}, present in file {filename}, must have a label."
                )

            match plugin:
                case PortScan():
                    self.plugins["port_scan"].add(plugin)
                case SubdomainEnumeration():
                    self.plugins["subdomain_enumeration"].add(plugin)
                case DirEnumeration():
                    self.plugins["dir_enumeration"].add(plugin)
                case VulnerabilityScan():
                    self.plugins["vulnerability_scan"].add(plugin)
                case _:
                    raise TypeError(
                        PLUGIN_TYPE_ERROR_MESSAGE.format(
                            label=plugin.label, filename=filename
                        )
                    )

    @staticmethod
    def _is_valid_plugin_type(plugin: Plugin):
        return (
            issubclass(plugin, PortScan)
            or issubclass(plugin, SubdomainEnumeration)
            or issubclass(plugin, VulnerabilityScan)
            or issubclass(plugin, DirEnumeration)
        )
