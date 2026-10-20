"""WP6: structured pdb.Pdb helper; launch only in v1."""
from dea.contracts.adapter import UnimplementedAdapter
from dea.contracts.models import Backend


class PdbAdapter(UnimplementedAdapter):
    backend = Backend.PDB

