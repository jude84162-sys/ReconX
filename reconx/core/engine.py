class Module:
    """Base class for all reconnaissance modules."""

    name = "base"
    description = "Base reconnaissance module"
    author = "jude84162-sys"

    def __init__(self, verbose=False, timeout=10):
        self.verbose = verbose
        self.timeout = timeout
        self.results = []

    def run(self, target):
        raise NotImplementedError("Subclasses must implement run()")

    def add_result(self, platform, url, status, extra=None):
        """Add a result entry."""
        entry = {
            "platform": platform,
            "url": url,
            "status": status,
            "extra": extra or {},
        }
        self.results.append(entry)
        return entry

    def get_results(self):
        return self.results


class Engine:
    """Main OSINT engine that coordinates all modules."""

    def __init__(self, verbose=False, timeout=10):
        self.verbose = verbose
        self.timeout = timeout
        self.modules = {}

    def register(self, module_cls):
        """Register a reconnaissance module."""
        instance = module_cls(verbose=self.verbose, timeout=self.timeout)
        self.modules[instance.name] = instance

    def list_modules(self):
        """List all registered modules."""
        return [
            {"name": m.name, "description": m.description}
            for m in self.modules.values()
        ]

    def run_module(self, module_name, target):
        """Run a specific module against a target."""
        if module_name not in self.modules:
            raise ValueError(f"Module '{module_name}' not found")
        module = self.modules[module_name]
        module.run(target)
        return module.get_results()

    def run_all(self, target):
        """Run all registered modules against a target."""
        all_results = {}
        for name, module in self.modules.items():
            try:
                module.run(target)
                all_results[name] = module.get_results()
            except Exception as e:
                all_results[name] = {"error": str(e)}
        return all_results
