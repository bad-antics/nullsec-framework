"""
NullSec Framework — Base Module Class
All framework modules inherit from this base.
"""

import os
import sys
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any


class BaseModule:
    """Base class for all NullSec Framework modules."""

    name = "base_module"
    description = "Base module"
    author = "bad-antics"
    version = "1.0.0"
    category = "misc"
    language = "Python"

    def __init__(self):
        self.options = {}
        self.results = []
        self.start_time = None
        self.end_time = None

    def set_option(self, key: str, value: Any):
        """Set a module option."""
        self.options[key] = value

    def get_option(self, key: str, default=None):
        """Get a module option."""
        return self.options.get(key, default)

    def validate(self) -> bool:
        """Validate that required options are set. Override in subclass."""
        return True

    def run(self, **kwargs) -> Dict:
        """Execute the module. Override in subclass."""
        raise NotImplementedError("Module must implement run()")

    def execute(self, **kwargs) -> Dict:
        """Execute with timing and error handling."""
        self.start_time = time.time()
        try:
            if not self.validate():
                return {"error": "Validation failed", "module": self.name}
            result = self.run(**kwargs)
            self.end_time = time.time()
            result["_meta"] = {
                "module": self.name,
                "version": self.version,
                "duration": round(self.end_time - self.start_time, 3),
                "timestamp": datetime.utcnow().isoformat(),
            }
            self.results.append(result)
            return result
        except Exception as e:
            self.end_time = time.time()
            return {
                "error": str(e),
                "module": self.name,
                "duration": round(self.end_time - self.start_time, 3),
            }

    def report(self, format="json") -> str:
        """Generate a report from results."""
        if format == "json":
            return json.dumps(self.results, indent=2, default=str)
        elif format == "text":
            lines = [f"=== {self.name} v{self.version} Report ==="]
            for r in self.results:
                lines.append(json.dumps(r, indent=2, default=str))
            return "\n".join(lines)
        return str(self.results)

    def info(self) -> Dict:
        """Module metadata."""
        return {
            "name": self.name,
            "description": self.description,
            "author": self.author,
            "version": self.version,
            "category": self.category,
            "language": self.language,
        }
