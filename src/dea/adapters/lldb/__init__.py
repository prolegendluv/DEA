"""WP5: LLDB Python helper and asynchronous event adapter."""
from dea.contracts.adapter import UnimplementedAdapter
from dea.contracts.models import Backend


class LldbAdapter(UnimplementedAdapter):
    backend = Backend.LLDB

