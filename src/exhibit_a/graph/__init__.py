"""SLICE: a static call graph of the repository, entry points, sinks and reachability.

The graph only proposes. Reachability is not exploitability: a path from an entry point
through a changed function to a sink tells the loop where to look and which entry point the
oracle must see, but only sandboxed execution under the oracle proves anything. Imprecision
can cost recall (a missed path) or money (a useless model call), never a false proof.
"""

from .build import build_graph
from .catalog import find_entries, sink_hits
from .reach import changed_lines, changed_nodes, find_paths, functions_in, reach_from_diff, render

__all__ = [
    "build_graph",
    "changed_lines",
    "changed_nodes",
    "find_entries",
    "find_paths",
    "functions_in",
    "reach_from_diff",
    "render",
    "sink_hits",
]
