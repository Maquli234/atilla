"""
plugins/base.py — Plugin base class and loader for ATILLA.

To create a plugin:
  1. Create a .py file in the plugins/ directory
  2. Subclass AtillaPlugin
  3. Implement on_response() and/or on_request()
  4. ATILLA auto-discovers and loads all plugins at startup

Example plugin file (plugins/my_plugin.py):

    from plugins.base import AtillaPlugin

    class MyPlugin(AtillaPlugin):
        name        = "my_plugin"
        description = "Detect custom app-specific XSS indicator"
        version     = "1.0"

        def on_response(self, param, payload, response_text, headers):
            if "my_custom_indicator" in response_text:
                return self.finding(param, payload,
                    confidence=80, detail="Custom indicator matched")
            return None
"""

import importlib
import importlib.util
import os
import sys
from typing import Dict, List, Optional


class PluginFinding:
    """A vulnerability finding returned by a plugin."""
    def __init__(self, param: str, payload: str, confidence: int,
                 detail: str, category: str = "PLUGIN"):
        self.param      = param
        self.payload    = payload
        self.confidence = confidence
        self.detail     = detail
        self.category   = category

    def __repr__(self):
        return f"<PluginFinding {self.param} conf={self.confidence} {self.detail[:40]}>"


class AtillaPlugin:
    """
    Base class for all ATILLA plugins.
    Subclass this and implement the hook methods you need.
    """
    name:        str = "unnamed_plugin"
    description: str = ""
    version:     str = "1.0"
    enabled:     bool = True

    # ── Hook: called before every request ─────────────────────────────
    def on_request(self, url: str, param: str, payload: str, headers: dict) -> Optional[dict]:
        """
        Called before a request is sent.
        Return a dict of extra headers to add, or None.
        """
        return None

    # ── Hook: called after every response ─────────────────────────────
    def on_response(
        self,
        param:         str,
        payload:       str,
        response_text: str,
        headers:       dict,
    ) -> Optional[PluginFinding]:
        """
        Called after each HTTP response.
        Return a PluginFinding if a vulnerability is detected, else None.
        """
        return None

    # ── Hook: called when a vulnerability is confirmed ─────────────────
    def on_finding(self, vuln) -> None:
        """Called whenever the engine records a confirmed finding."""
        pass

    # ── Hook: called at the end of the scan ───────────────────────────
    def on_scan_complete(self, all_vulns: list) -> None:
        """Called once when the scan finishes."""
        pass

    # ── Helper ─────────────────────────────────────────────────────────
    def finding(self, param: str, payload: str,
                confidence: int = 70, detail: str = "",
                category: str = "PLUGIN") -> PluginFinding:
        return PluginFinding(param, payload, confidence, detail, category)


# ── Plugin Loader ──────────────────────────────────────────────────────────

class PluginLoader:
    def __init__(self, plugin_dir: str = None):
        if plugin_dir is None:
            plugin_dir = os.path.join(os.path.dirname(__file__))
        self.plugin_dir = plugin_dir
        self.plugins: List[AtillaPlugin] = []

    def load_all(self) -> List[AtillaPlugin]:
        """Discover and load all .py files in plugin_dir (except __init__ and base)."""
        loaded = []
        if not os.path.isdir(self.plugin_dir):
            return loaded

        for fname in os.listdir(self.plugin_dir):
            if not fname.endswith(".py"):
                continue
            if fname.startswith("_") or fname == "base.py":
                continue
            plugin_path = os.path.join(self.plugin_dir, fname)
            try:
                plugin = self._load_file(plugin_path)
                if plugin:
                    loaded.append(plugin)
                    print(f"  [plugin] Loaded: {plugin.name} v{plugin.version}")
            except Exception as e:
                print(f"  [plugin] Failed to load {fname}: {e}")

        self.plugins = loaded
        return loaded

    def _load_file(self, path: str) -> Optional[AtillaPlugin]:
        """Load a single plugin file and return an instance of its AtillaPlugin subclass."""
        spec   = importlib.util.spec_from_file_location("_plugin_mod", path)
        module = importlib.util.module_from_spec(spec)
        sys.path.insert(0, os.path.dirname(path))
        spec.loader.exec_module(module)
        sys.path.pop(0)

        for attr_name in dir(module):
            obj = getattr(module, attr_name)
            if (isinstance(obj, type) and issubclass(obj, AtillaPlugin)
                    and obj is not AtillaPlugin):
                instance = obj()
                if instance.enabled:
                    return instance
        return None

    def run_on_response(self, param, payload, response_text, headers) -> List[PluginFinding]:
        """Run all plugins' on_response hook and collect findings."""
        findings = []
        for plugin in self.plugins:
            try:
                result = plugin.on_response(param, payload, response_text, headers)
                if result:
                    findings.append(result)
            except Exception as e:
                print(f"  [plugin:{plugin.name}] on_response error: {e}")
        return findings

    def run_on_finding(self, vuln) -> None:
        for plugin in self.plugins:
            try:
                plugin.on_finding(vuln)
            except Exception:
                pass

    def run_on_scan_complete(self, vulns) -> None:
        for plugin in self.plugins:
            try:
                plugin.on_scan_complete(vulns)
            except Exception:
                pass
