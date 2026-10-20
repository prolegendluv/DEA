"""Architect-owned worker write manifest; roots are repository-relative."""
from pathlib import PurePosixPath, PureWindowsPath
from types import MappingProxyType

WORK_PACKAGES = MappingProxyType({
    1: ("src/dea/runtime", "tests/runtime"),
    2: ("src/dea/sessions", "tests/sessions"),
    3: ("src/dea/state", "tests/state"),
    4: ("src/dea/adapters/gdb", "tests/gdb"),
    5: ("src/dea/adapters/lldb", "tests/lldb"),
    6: ("src/dea/adapters/pdb", "tests/pdb"),
    7: ("src/dea/gateways", "skills/dea", "tests/gateways"),
    8: ("tests/integration", "demos"),
})


def _normalized(path: str) -> PurePosixPath:
    windows = PureWindowsPath(path)
    result = PurePosixPath(path.replace("\\", "/").lower())
    if windows.drive or windows.root or result.is_absolute() or ".." in result.parts:
        raise ValueError("Use a repository-relative path without traversal")
    return result


def validate_ownership() -> None:
    roots = [(package, _normalized(root)) for package, paths in WORK_PACKAGES.items() for root in paths]
    for index, (package, root) in enumerate(roots):
        for other_package, other in roots[index + 1:]:
            if root == other or root in other.parents or other in root.parents:
                raise ValueError(f"Overlapping ownership: {package} and {other_package}")


def worker_can_write(package: int, path: str) -> bool:
    candidate = _normalized(path)
    return any(candidate == (root := _normalized(allowed)) or root in candidate.parents
               for allowed in WORK_PACKAGES[package])


if __name__ == "__main__":
    validate_ownership()
    print("8 disjoint worker write sets validated")

