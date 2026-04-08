"""
core/graph/builder.py

Attack Chain Graph Builder
Role: Converts the UnifiedContext into a directed graph representing the attack chain.
      Uses NetworkX for graph operations.

Node types:
  email, pdf, reader_process, child_process, dropped_file, executed_file,
  network_ip, domain

Edge relations:
  delivered_to, opened_by, spawned, wrote, executed, connected_to

Why graphs?
  - Visualize the full kill chain
  - Detect multi-hop attack patterns
  - Compute graph-level features (depth, branching factor)
  - Store for case comparison and pattern matching
"""
import networkx as nx
from models.schemas import UnifiedContext, AttackGraph, GraphNode, GraphEdge
from utils.logger import get_logger

log = get_logger("graph_builder")


def build_attack_graph(ctx: UnifiedContext) -> AttackGraph:
    """
    Build a directed attack chain graph from the unified context.

    Algorithm:
      1. Create root nodes (email → pdf → reader)
      2. Add child process nodes + edges from reader
      3. Add dropped file nodes + edges from child processes
      4. Add executed file nodes + edges
      5. Add network destination nodes + edges from executed files
    """
    G = nx.DiGraph()
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []

    def add_node(node_id: str, node_type: str, label: str, **attrs) -> GraphNode:
        n = GraphNode(node_id=node_id, node_type=node_type, label=label, attributes=attrs)
        nodes.append(n)
        G.add_node(node_id, type=node_type, label=label, **attrs)
        return n

    def add_edge(src: str, tgt: str, relation: str):
        edges.append(GraphEdge(source=src, target=tgt, relation=relation))
        G.add_edge(src, tgt, relation=relation)

    # ── Layer 1: Email source ─────────────────────────────────────────────────
    if ctx.pdf.origin == "external_email" and ctx.pdf.sender:
        email_id = f"email_{ctx.pdf.sender}"
        add_node(email_id, "email", ctx.pdf.sender,
                 reputation=ctx.pdf.sender_reputation)
        pdf_id = f"pdf_{ctx.pdf.hash[:8]}"
        add_node(pdf_id, "pdf", ctx.pdf.path,
                 hash=ctx.pdf.hash, has_js=ctx.pdf.embedded_js,
                 obfuscation=ctx.pdf.obfuscation_score)
        add_edge(email_id, pdf_id, "delivered_to")
    else:
        pdf_id = f"pdf_{ctx.pdf.hash[:8]}"
        add_node(pdf_id, "pdf", ctx.pdf.path,
                 hash=ctx.pdf.hash, origin=ctx.pdf.origin)

    # ── Layer 2: PDF reader process ───────────────────────────────────────────
    if ctx.runtime.reader_process:
        reader_id = f"reader_{ctx.runtime.reader_process}"
        add_node(reader_id, "reader_process", ctx.runtime.reader_process,
                 user=ctx.user, host=ctx.host)
        add_edge(pdf_id, reader_id, "opened_by")
    else:
        reader_id = pdf_id  # no reader observed, connect directly

    # ── Layer 3: Child processes ──────────────────────────────────────────────
    child_ids: list[str] = []
    for i, proc in enumerate(ctx.runtime.child_processes):
        child_id = f"child_{proc}_{i}"
        add_node(child_id, "child_process", proc,
                 command=ctx.runtime.commands[i] if i < len(ctx.runtime.commands) else "")
        add_edge(reader_id, child_id, "spawned")
        child_ids.append(child_id)

    # ── Layer 4: Dropped files ────────────────────────────────────────────────
    drop_ids: list[str] = []
    for i, fpath in enumerate(ctx.runtime.dropped_files):
        drop_id = f"drop_{i}"
        add_node(drop_id, "dropped_file", fpath)
        # Attribute the drop to the last child process if available
        parent = child_ids[-1] if child_ids else reader_id
        add_edge(parent, drop_id, "wrote")
        drop_ids.append(drop_id)

    # ── Layer 5: Executed files ───────────────────────────────────────────────
    exec_ids: list[str] = []
    for i, fpath in enumerate(ctx.runtime.executed_files):
        exec_id = f"exec_{i}"
        add_node(exec_id, "executed_file", fpath)
        # Link to the corresponding drop if it exists
        parent = drop_ids[i] if i < len(drop_ids) else (child_ids[-1] if child_ids else reader_id)
        add_edge(parent, exec_id, "executed")
        exec_ids.append(exec_id)

    # ── Layer 6: Network destinations ────────────────────────────────────────
    for dest in ctx.runtime.network_destinations:
        net_id = f"net_{dest}"
        node_type = "domain" if not dest[0].isdigit() else "network_ip"
        add_node(net_id, node_type, dest)
        parent = exec_ids[-1] if exec_ids else (child_ids[-1] if child_ids else reader_id)
        add_edge(parent, net_id, "connected_to")

    # ── Graph-level stats ─────────────────────────────────────────────────────
    depth = nx.dag_longest_path_length(G) if nx.is_directed_acyclic_graph(G) else len(nodes)
    log.info(
        f"Attack graph built: {len(nodes)} nodes, {len(edges)} edges, "
        f"chain depth={depth}"
    )

    return AttackGraph(case_id=ctx.case_id, nodes=nodes, edges=edges)


def graph_to_summary(graph: AttackGraph) -> dict:
    """
    Produce a human-readable summary of the attack graph.
    Used as additional context for the LLM prompt.
    """
    node_types = {}
    for n in graph.nodes:
        node_types[n.node_type] = node_types.get(n.node_type, 0) + 1

    chain = " → ".join(
        f"{e.source}--[{e.relation}]-->{e.target}"
        for e in graph.edges[:8]  # first 8 edges for brevity
    )

    return {
        "total_nodes": len(graph.nodes),
        "total_edges": len(graph.edges),
        "node_type_counts": node_types,
        "chain_preview": chain,
    }
