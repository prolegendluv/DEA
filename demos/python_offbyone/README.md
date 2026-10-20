# Deterministic Python off-by-one demo

From the repository root, using the Python environment containing DEA:

```powershell
python demos/python_offbyone/buggy.py
python demos/python_offbyone/fixed.py
python -m pytest tests/integration/test_pdb_python_offbyone.py -q
```

The batch processes exactly 10,000 integer records, indexed 0 through 9999.
At **zero-based index 4096 (the 4097th iteration)**, the buggy program uses
4095 instead of 4096. Its checksum is always **49,994,999**; the correct sum
is **49,995,000**. There is no exception, stack trace, randomness, external
input, or timing dependence. Stack location alone cannot establish the wrong
value; inspect the locals across the assignment.

The expected minimal patch replaces `item = index - 1` with `item = index`.
`fixed.py` keeps that patch separate from the buggy source. Removing the
redundant conditional entirely is an equivalent cleanup.

The integration scenario uses the real PDB helper, session manager, state
packer, and public MCP tools. Launch `buggy.py`, await entry, and set a
conditional source breakpoint on `item = index - 1` with `index == 4096`.
Before that line, `index == item == 4096` and `total == 8386560`. Evaluate
`item - index` (zero), await the evaluation's baseline reset, and step over.
At the next stop, `item` changes from 4096 to 4095 while `total` is unchanged.
The test verifies that compact delta, paginated inspection, both 191-token
limits, completed termination, and native process exit. It also checks the
fixed reference and applies the minimal patch to a temporary copy.

No C/C++, Rust, attach/detach, or native LLDB capability is claimed by this
Python-only slice. The smoke test skips explicitly if the running Python
interpreter or its standard-library PDB module is unavailable; debugger or
gateway failures on an otherwise equipped host fail the tests.
