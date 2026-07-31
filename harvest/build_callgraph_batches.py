#!/usr/bin/env python3
"""Harvest phase: build the call graph and emit cycle-aware, callee-first batches.

This implements Algorithm 1 of the paper. Functions must be analysed before their
callers, so that a caller's context can include what was already learned about its
callees. A plain topological order is undefined on a cyclic call graph, and real
SMM modules do contain cycles (recursive parsers, dispatcher re-entry), so cycles
are condensed rather than traversed:

  1. Build the directed call graph G from the extracted per-function sources.
  2. Repeat until G is empty:
       a. Take every node whose out-degree is 0 (it calls nothing still pending)
          as the next batch.
       b. If no such node exists, every remaining node lies on a cycle. Locate the
          strongly connected components and delete the edges *inside* them: a pair
          of mutually recursive functions imposes no ordering on one another, so
          those edges are dropped from the ordering computation. Then retry (a) --
          the members of a cycle therefore land in the same batch.
       c. Emit the batch and remove its nodes from G.

Removing intra-cycle edges affects only the *ordering*. The relations written to
function_call_relations.txt are the unpruned ones, because the Analyze phase still
needs a function's true callees for its short-term memory: two mutually recursive
functions each receive the other's pseudocode.

Inputs are the per-function .c files produced by the IDA/efiXplorer extraction
step. Outputs, written next to them:
    function_call_relations.txt   caller: callees, one line per function
    function_batches.txt          "Batch <n>: f1, f2, ..." in analysis order

Usage:
    python build_callgraph_batches.py <extracted_functions_dir>
"""
import os
import re
import sys

import networkx as nx

CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
# Tokens that look like calls but are language or compiler constructs.
NOT_CALLS = {
    "if", "for", "while", "switch", "return", "sizeof", "do", "else",
    "case", "break", "continue", "goto", "default", "typedef", "struct",
}


def function_names(folder):
    return {
        os.path.splitext(f)[0]
        for f in os.listdir(folder)
        if f.endswith(".c")
    }


def build_graph(folder):
    """Build the call graph over the extracted per-function .c files."""
    names = function_names(folder)
    graph = nx.DiGraph()
    graph.add_nodes_from(names)

    for name in names:
        path = os.path.join(folder, name + ".c")
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                body = fh.read()
        except OSError as exc:
            print(f"skipping {path}: {exc}", file=sys.stderr)
            continue
        for callee in CALL_RE.findall(body):
            # Only edges between functions we actually extracted; ignore
            # self-loops, which impose no ordering constraint.
            if callee in names and callee != name and callee not in NOT_CALLS:
                graph.add_edge(name, callee)
    return graph


def drop_reciprocal_edges(graph):
    """Remove every mutual-call edge pair, and every self-loop, up front.

    If u calls v and v calls u, neither can be ordered before the other, so the
    pair imposes no constraint and both edges leave the ordering computation. This
    is done globally before any peeling because the level at which mutual recursion
    appears is not known in advance. Returns the number of edges removed.
    """
    removed = 0
    for u, v in list(graph.edges()):
        if u == v:
            graph.remove_edge(u, v)
            removed += 1
        elif graph.has_edge(v, u):
            graph.remove_edge(u, v)
            graph.remove_edge(v, u)
            removed += 2
    return removed


def next_batch(graph):
    """Take the functions of least out-degree as the next batch.

    Normally the minimum is 0 and this is ordinary callee-first peeling: a function
    is ready once every callee it depends on has been emitted.

    When a cycle longer than two functions survives (A -> B -> C -> A) nothing
    reaches out-degree 0, and the cycle is taken as one batch, since its members
    cannot be ordered with respect to one another. The least-out-degree rule is
    applied only among functions that actually lie on a cycle: an ordinary caller
    of the cycle (D -> A) may share their out-degree, but it genuinely depends on
    them and must still be analysed afterwards. Edges among the batch members are
    then dropped so they no longer order anything.
    """
    ready = sorted(n for n, d in graph.out_degree() if d == 0)
    if ready:
        return ready

    on_cycle = {n for scc in nx.strongly_connected_components(graph)
                if len(scc) > 1 for n in scc}
    candidates = on_cycle or set(graph.nodes)
    least = min(graph.out_degree(n) for n in candidates)
    batch = sorted(n for n in candidates if graph.out_degree(n) == least)

    members = set(batch)
    for u, v in list(graph.edges(batch)):
        if u in members and v in members:
            graph.remove_edge(u, v)
    return batch


def batches(graph):
    """Yield analysis batches, callees before callers."""
    pending = graph.copy()
    n = drop_reciprocal_edges(pending)
    if n:
        print(f"dropped {n} mutual-call/self-loop edges from the ordering")

    while pending.number_of_nodes():
        batch = next_batch(pending)
        yield batch
        pending.remove_nodes_from(batch)


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 1
    folder = sys.argv[1]

    graph = build_graph(folder)
    print(f"{graph.number_of_nodes()} functions, "
          f"{graph.number_of_edges()} call edges")

    # Call relations come from the UNPRUNED graph: the Analyze phase needs a
    # function's true callees for short-term memory.
    rel_path = os.path.join(folder, "function_call_relations.txt")
    with open(rel_path, "w", encoding="utf-8") as fh:
        for node in sorted(graph.nodes):
            fh.write(f"{node}: {', '.join(sorted(graph.successors(node)))}\n")

    batch_path = os.path.join(folder, "function_batches.txt")
    with open(batch_path, "w", encoding="utf-8") as fh:
        for i, batch in enumerate(batches(graph), start=1):
            fh.write(f"Batch {i}: {', '.join(batch)}\n")
            print(f"Batch {i}: {len(batch)} functions")

    print(f"wrote {rel_path}\nwrote {batch_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
