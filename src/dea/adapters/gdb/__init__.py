"""WP4: GDB/MI parser and adapter."""
from dea.contracts.adapter import UnimplementedAdapter
from dea.contracts.models import Backend


class GdbAdapter(UnimplementedAdapter):
    backend = Backend.GDB

