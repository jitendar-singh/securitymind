"""
DFD generator: produces structured artifacts (Mermaid, boundary-crossing flows,
nodes/edges) plus an optional PNG fallback from `app_details`.

Mermaid is the primary, LLM-consumable representation. PNG is a secondary artifact
for HTML report embedding, rendered via Graphviz (with a NetworkX/matplotlib fallback
if Graphviz isn't available).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import textwrap
from typing import Any, Dict, List, Optional, TypedDict

import networkx as nx

logger = logging.getLogger(__name__)


NODE_TYPE_TO_DFD = {
    "frontend": "external_entity",
    "external_service": "external_entity",
    "service": "process",
    "ml_model": "process",
    "model": "process",
    "llm": "process",
    "training_pipeline": "process",
    "database": "data_store",
    "vector_db": "data_store",
    "cache": "data_store",
    "queue": "data_store",
}


class DFDValidationError(ValueError):
    """Raised when input app_details fail DFD schema validation."""


class DFDArtifacts(TypedDict, total=False):
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]
    boundaries: List[Dict[str, Any]]
    boundary_crossings: List[Dict[str, Any]]
    mermaid: str
    dfd_path: Optional[str]


class DFDGenerator:
    """Builds a DFD model from `app_details` and renders Mermaid + (optionally) PNG."""

    REPORTS_DIR_ENV = "REPORTS_DIR"
    DEFAULT_REPORTS_DIR = "reports"

    def __init__(self, app_details: Dict[str, Any]):
        if not isinstance(app_details, dict):
            raise DFDValidationError("app_details must be a dict")
        self.app_details = app_details
        self.graph: nx.DiGraph = nx.DiGraph()
        self.boundaries: List[Dict[str, Any]] = []
        self._build()

    def _build(self) -> None:
        components = self._require_list("components")
        external = self._require_list("external_services")
        flows = self._require_list("data_flows")
        boundaries = self._require_list("trust_boundaries")

        for c in components:
            self._add_node(c, default_dfd_type="process")
        for s in external:
            self._add_node(s, default_dfd_type="external_entity", forced_raw_type="external_service")

        for flow in flows:
            self._add_flow(flow)

        for b in boundaries:
            self._add_boundary(b)

    def _require_list(self, key: str) -> List[Any]:
        value = self.app_details.get(key) or []
        if not isinstance(value, list):
            raise DFDValidationError(f"'{key}' must be a list, got {type(value).__name__}")
        return value

    def _add_node(
        self,
        spec: Any,
        default_dfd_type: str,
        forced_raw_type: Optional[str] = None,
    ) -> None:
        if not isinstance(spec, dict) or "id" not in spec or "name" not in spec:
            raise DFDValidationError(f"node spec needs 'id' and 'name': {spec!r}")
        raw_type = forced_raw_type if forced_raw_type else (spec.get("type") or "")
        dfd_type = NODE_TYPE_TO_DFD.get(str(raw_type).lower(), default_dfd_type)
        self.graph.add_node(
            spec["id"],
            name=spec["name"],
            raw_type=raw_type,
            dfd_type=dfd_type,
            technology=spec.get("technology"),
        )

    def _add_flow(self, flow: Any) -> None:
        if not isinstance(flow, dict):
            raise DFDValidationError(f"data_flow must be a dict: {flow!r}")
        src = flow.get("from") or flow.get("source") or flow.get("src")
        dst = flow.get("to") or flow.get("destination") or flow.get("dest")
        if not src or not dst:
            logger.warning("Skipping data_flow with missing src/dst: %r", flow)
            return
        if src not in self.graph.nodes or dst not in self.graph.nodes:
            logger.warning(
                "Skipping data_flow %s -> %s: endpoint not declared in components/external_services",
                src,
                dst,
            )
            return
        self.graph.add_edge(
            src,
            dst,
            label=flow.get("label", ""),
            protocol=flow.get("protocol"),
            auth=flow.get("auth"),
            encryption=flow.get("encryption"),
            data_classification=flow.get("data_classification"),
        )

    def _add_boundary(self, b: Any) -> None:
        if not isinstance(b, dict) or "name" not in b or "components" not in b:
            raise DFDValidationError(f"trust_boundary needs 'name' and 'components': {b!r}")
        members = [cid for cid in b["components"] if cid in self.graph.nodes]
        if not members:
            logger.warning("Trust boundary %r has no resolvable members; skipping", b["name"])
            return
        self.boundaries.append({"name": b["name"], "components": members})

    def generate(self, render_png: bool = True) -> DFDArtifacts:
        if self.graph.number_of_nodes() == 0:
            raise DFDValidationError(
                "DFD graph is empty — declare at least one component or external_service"
            )

        artifacts: DFDArtifacts = {
            "nodes": self._nodes(),
            "edges": self._edges(),
            "boundaries": list(self.boundaries),
            "boundary_crossings": self._boundary_crossings(),
            "mermaid": self._to_mermaid(),
            "dfd_path": None,
        }
        if render_png:
            artifacts["dfd_path"] = self._render_png()
        return artifacts

    def to_mermaid(self) -> str:
        return self._to_mermaid()

    def generate_dfd(self) -> Optional[str]:
        """Backward-compatible API: render PNG and return its path (or None on failure).

        Prefer `generate()` for new callers — it returns full artifacts including
        Mermaid and boundary-crossing flows.
        """
        try:
            return self.generate(render_png=True).get("dfd_path")
        except DFDValidationError:
            logger.warning("DFD validation failed; returning None")
            return None

    def _nodes(self) -> List[Dict[str, Any]]:
        return [
            {
                "id": nid,
                "name": data.get("name", nid),
                "dfd_type": data.get("dfd_type"),
                "raw_type": data.get("raw_type"),
                "technology": data.get("technology"),
            }
            for nid, data in self.graph.nodes(data=True)
        ]

    def _edges(self) -> List[Dict[str, Any]]:
        return [
            {
                "source": s,
                "destination": d,
                **{k: v for k, v in data.items() if v},
            }
            for s, d, data in self.graph.edges(data=True)
        ]

    def _boundary_for_node(self) -> Dict[str, Optional[str]]:
        m: Dict[str, Optional[str]] = {nid: None for nid in self.graph.nodes}
        for b in self.boundaries:
            for cid in b["components"]:
                m[cid] = b["name"]
        return m

    def _boundary_crossings(self) -> List[Dict[str, Any]]:
        bmap = self._boundary_for_node()
        out: List[Dict[str, Any]] = []
        for s, d, data in self.graph.edges(data=True):
            sb, db = bmap.get(s), bmap.get(d)
            if sb != db:
                out.append({
                    "source": s,
                    "destination": d,
                    "from_boundary": sb,
                    "to_boundary": db,
                    "label": data.get("label", ""),
                    "protocol": data.get("protocol"),
                    "auth": data.get("auth"),
                    "encryption": data.get("encryption"),
                })
        return out

    @staticmethod
    def _mermaid_id(raw_id: str) -> str:
        return "n_" + "".join(ch if ch.isalnum() else "_" for ch in str(raw_id))

    @staticmethod
    def _mermaid_label(name: str) -> str:
        return str(name).replace('"', "'")

    @staticmethod
    def _wrap_label(text: str, width: int = 24) -> str:
        return "\\n".join(textwrap.wrap(text, width=width)) or text

    def _edge_label(self, data: Dict[str, Any]) -> str:
        parts: List[str] = []
        if data.get("label"):
            parts.append(str(data["label"]))
        if data.get("protocol"):
            parts.append(str(data["protocol"]))
        if data.get("encryption"):
            parts.append(f"enc:{data['encryption']}")
        if data.get("auth"):
            parts.append(f"auth:{data['auth']}")
        return " / ".join(parts)

    def _to_mermaid(self) -> str:
        shape = {
            "process": ("((", "))"),
            "data_store": ("[(", ")]"),
            "external_entity": ("[/", "/]"),
        }
        lines = ["flowchart TD"]
        bmap = self._boundary_for_node()

        in_boundary: Dict[str, List[str]] = {}
        outside: List[str] = []
        for nid, b in bmap.items():
            if b:
                in_boundary.setdefault(b, []).append(nid)
            else:
                outside.append(nid)

        def emit_node(nid: str, indent: str) -> None:
            data = self.graph.nodes[nid]
            open_, close_ = shape.get(data.get("dfd_type", "process"), ("((", "))"))
            label = self._mermaid_label(data.get("name", nid))
            lines.append(f'{indent}{self._mermaid_id(nid)}{open_}"{label}"{close_}')

        for boundary_name, members in in_boundary.items():
            sg_id = self._mermaid_id("tb_" + boundary_name)
            lines.append(
                f'    subgraph {sg_id}["Trust Boundary: {self._mermaid_label(boundary_name)}"]'
            )
            for nid in members:
                emit_node(nid, indent="        ")
            lines.append("    end")

        for nid in outside:
            emit_node(nid, indent="    ")

        for s, d, data in self.graph.edges(data=True):
            edge_label = self._edge_label(data)
            if edge_label:
                lines.append(
                    f'    {self._mermaid_id(s)} -->|"{self._mermaid_label(edge_label)}"| {self._mermaid_id(d)}'
                )
            else:
                lines.append(f"    {self._mermaid_id(s)} --> {self._mermaid_id(d)}")

        return "\n".join(lines)

    def _output_path(self) -> str:
        reports_dir = os.path.abspath(os.environ.get(self.REPORTS_DIR_ENV, self.DEFAULT_REPORTS_DIR))
        os.makedirs(reports_dir, exist_ok=True)
        digest = hashlib.sha256(
            json.dumps(self.app_details, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()[:8]
        return os.path.join(reports_dir, f"dfd_{digest}.png")

    def _render_png(self) -> Optional[str]:
        path = self._output_path()
        try:
            self._render_graphviz(path)
            logger.info("DFD rendered (Graphviz) to %s", path)
            return path
        except Exception as exc:
            logger.warning("Graphviz render unavailable or failed (%s); using matplotlib fallback", exc)
        try:
            self._render_matplotlib(path)
            logger.info("DFD rendered (matplotlib fallback) to %s", path)
            return path
        except Exception as exc:
            logger.error("matplotlib DFD render failed: %s", exc, exc_info=True)
            return None

    def _render_graphviz(self, path: str) -> None:
        import pydot

        gv_shape = {"process": "circle", "data_store": "cylinder", "external_entity": "box"}
        gv_color = {"process": "lightgreen", "data_store": "lightyellow", "external_entity": "lightblue"}

        dot = pydot.Dot("DFD", graph_type="digraph", rankdir="LR", labelloc="t", label="Data Flow Diagram")
        dot.set_node_defaults(style="filled", fontname="Helvetica", fontsize="11")
        dot.set_edge_defaults(fontname="Helvetica", fontsize="9")

        bmap = self._boundary_for_node()
        clusters: Dict[str, pydot.Subgraph] = {}
        for b in self.boundaries:
            cluster = pydot.Subgraph(
                f"cluster_{self._mermaid_id(b['name'])}",
                label=f"Trust Boundary: {b['name']}",
                style="dashed",
                color="red",
                fontcolor="red",
            )
            clusters[b["name"]] = cluster
            dot.add_subgraph(cluster)

        for nid, data in self.graph.nodes(data=True):
            dfd_type = data.get("dfd_type", "process")
            label = self._wrap_label(data.get("name", nid))
            node = pydot.Node(
                self._mermaid_id(nid),
                label=label,
                shape=gv_shape.get(dfd_type, "circle"),
                fillcolor=gv_color.get(dfd_type, "lightgray"),
            )
            container = clusters.get(bmap.get(nid)) if bmap.get(nid) else None
            (container or dot).add_node(node)

        for s, d, data in self.graph.edges(data=True):
            label = self._edge_label(data)
            dot.add_edge(
                pydot.Edge(
                    self._mermaid_id(s),
                    self._mermaid_id(d),
                    label=self._wrap_label(label) if label else "",
                    color="red" if bmap.get(s) != bmap.get(d) else "black",
                    fontcolor="red" if bmap.get(s) != bmap.get(d) else "black",
                )
            )

        legend = pydot.Subgraph("cluster_legend", label="Legend", style="rounded", color="gray")
        legend.add_node(pydot.Node("legend_process", label="Process", shape="circle", style="filled", fillcolor="lightgreen"))
        legend.add_node(pydot.Node("legend_store", label="Data Store", shape="cylinder", style="filled", fillcolor="lightyellow"))
        legend.add_node(pydot.Node("legend_entity", label="External Entity", shape="box", style="filled", fillcolor="lightblue"))
        dot.add_subgraph(legend)

        dot.write_png(path)

    def _render_matplotlib(self, path: str) -> None:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        plt.figure(figsize=(25, 20))
        pos = nx.spring_layout(self.graph, k=0.8, iterations=100, seed=42)

        bmap = self._boundary_for_node()
        node_lists = {"process": [], "data_store": [], "external_entity": []}
        for nid, data in self.graph.nodes(data=True):
            node_lists.setdefault(data.get("dfd_type", "process"), []).append(nid)

        nx.draw_networkx_nodes(self.graph, pos, nodelist=node_lists.get("external_entity", []),
                               node_size=5000, node_color="lightblue", node_shape="s")
        nx.draw_networkx_nodes(self.graph, pos, nodelist=node_lists.get("process", []),
                               node_size=5000, node_color="lightgreen", node_shape="o")
        nx.draw_networkx_nodes(self.graph, pos, nodelist=node_lists.get("data_store", []),
                               node_size=5000, node_color="lightyellow", node_shape="D")

        # Edge color: red for boundary crossings, black otherwise
        crossing_edges, normal_edges = [], []
        for s, d in self.graph.edges():
            (crossing_edges if bmap.get(s) != bmap.get(d) else normal_edges).append((s, d))
        nx.draw_networkx_edges(self.graph, pos, edgelist=normal_edges, arrowstyle="->",
                               arrowsize=20, connectionstyle="arc3,rad=0.1")
        nx.draw_networkx_edges(self.graph, pos, edgelist=crossing_edges, arrowstyle="->",
                               arrowsize=20, edge_color="red", connectionstyle="arc3,rad=0.1")

        # Per-render labels (do NOT mutate self.graph)
        labels = {nid: self._wrap_label(data.get("name", nid)).replace("\\n", "\n")
                  for nid, data in self.graph.nodes(data=True)}
        for nid, data in self.graph.nodes(data=True):
            if data.get("dfd_type") == "data_store":
                labels[nid] = f"<<Data Store>>\n{labels[nid]}"
        nx.draw_networkx_labels(self.graph, pos, labels=labels, font_size=10, font_weight="bold")

        edge_labels = {(s, d): self._edge_label(data) for s, d, data in self.graph.edges(data=True)
                       if self._edge_label(data)}
        nx.draw_networkx_edge_labels(self.graph, pos, edge_labels=edge_labels,
                                     font_size=9, label_pos=0.5, font_color="darkred")

        # Trust-boundary rectangles (informational only in matplotlib fallback)
        for boundary in self.boundaries:
            member_pos = {cid: pos[cid] for cid in boundary["components"] if cid in pos}
            if not member_pos:
                continue
            xs = [p[0] for p in member_pos.values()]
            ys = [p[1] for p in member_pos.values()]
            min_x, max_x = min(xs) - 0.1, max(xs) + 0.1
            min_y, max_y = min(ys) - 0.1, max(ys) + 0.1
            rect = plt.Rectangle((min_x, min_y), max_x - min_x, max_y - min_y,
                                 fill=False, edgecolor="red", linestyle="--", linewidth=2)
            plt.gca().add_patch(rect)
            plt.text(min_x, max_y + 0.05, f"Trust Boundary: {boundary['name']}",
                     fontsize=10, color="red")

        plt.title("Data Flow Diagram", size=15)
        plt.axis("off")
        plt.savefig(path, bbox_inches="tight")
        plt.close()


def format_dfd_context(artifacts: DFDArtifacts) -> str:
    """Render DFDArtifacts as a prompt-ready section for the threat-modeling LLM."""
    lines = [
        "**Data Flow Diagram (Mermaid):**",
        "```mermaid",
        artifacts.get("mermaid", ""),
        "```",
    ]
    crossings = artifacts.get("boundary_crossings") or []
    if crossings:
        lines.append("")
        lines.append(
            "**Trust-boundary-crossing flows (canonical STRIDE focus — every entry below "
            "deserves explicit threat coverage):**"
        )
        for c in crossings:
            sb = c.get("from_boundary") or "(outside)"
            db = c.get("to_boundary") or "(outside)"
            label_bits = [
                c.get("label") or "",
                c.get("protocol") or "",
                f"auth={c['auth']}" if c.get("auth") else "",
                f"enc={c['encryption']}" if c.get("encryption") else "",
            ]
            label = " / ".join(b for b in label_bits if b)
            line = f"- {c['source']} -> {c['destination']}  [{sb} -> {db}]"
            if label:
                line += f"  {label}"
            lines.append(line)

    nodes = artifacts.get("nodes") or []
    if nodes:
        ids = ", ".join(n["id"] for n in nodes)
        lines.append("")
        lines.append(
            f"**Use these exact DFD node IDs in `affected_components`:** {ids}"
        )
    return "\n".join(lines)
