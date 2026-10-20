"""LLDB runs in a probed, ABI-compatible Python helper, never in this process."""
from .adapter import LldbAdapter

__all__ = ["LldbAdapter"]

