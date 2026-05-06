import pytest
from unittest.mock import patch

from secmind.sub_agents.threat_modeling_agent.dfd_generator import (
    DFDGenerator,
    DFDValidationError,
    DFDArtifacts,
    format_dfd_context,
)


VALID_APP_DETAILS = {
    "components": [
        {"id": "web", "name": "Web Frontend", "type": "frontend"},
        {"id": "api", "name": "API Server", "type": "service"},
        {"id": "db", "name": "Database", "type": "database"},
    ],
    "external_services": [
        {"id": "auth0", "name": "Auth0 IdP"},
    ],
    "data_flows": [
        {"from": "web", "to": "api", "label": "REST API", "protocol": "HTTPS"},
        {"from": "api", "to": "db", "label": "SQL queries", "protocol": "TCP"},
        {"from": "api", "to": "auth0", "label": "Token validation", "protocol": "HTTPS"},
    ],
    "trust_boundaries": [
        {"name": "Internal Network", "components": ["api", "db"]},
    ],
}


class TestDFDGeneratorInit:
    def test_valid_app_details(self):
        gen = DFDGenerator(VALID_APP_DETAILS)
        assert gen.graph.number_of_nodes() == 4
        assert gen.graph.number_of_edges() == 3

    def test_non_dict_raises(self):
        with pytest.raises(DFDValidationError, match="must be a dict"):
            DFDGenerator("not a dict")

    def test_non_dict_none_raises(self):
        with pytest.raises(DFDValidationError, match="must be a dict"):
            DFDGenerator(None)

    def test_missing_component_id_raises(self):
        details = {
            "components": [{"name": "no-id"}],
            "external_services": [],
            "data_flows": [],
            "trust_boundaries": [],
        }
        with pytest.raises(DFDValidationError, match="'id' and 'name'"):
            DFDGenerator(details)

    def test_empty_components_ok(self):
        details = {
            "components": [],
            "external_services": [{"id": "ext", "name": "External"}],
            "data_flows": [],
            "trust_boundaries": [],
        }
        gen = DFDGenerator(details)
        assert gen.graph.number_of_nodes() == 1


class TestDFDGeneratorGenerate:
    def test_generates_all_artifact_keys(self):
        gen = DFDGenerator(VALID_APP_DETAILS)
        artifacts = gen.generate(render_png=False)
        assert "nodes" in artifacts
        assert "edges" in artifacts
        assert "boundaries" in artifacts
        assert "boundary_crossings" in artifacts
        assert "mermaid" in artifacts

    def test_mermaid_output_starts_with_flowchart(self):
        gen = DFDGenerator(VALID_APP_DETAILS)
        artifacts = gen.generate(render_png=False)
        assert artifacts["mermaid"].startswith("flowchart TD")

    def test_boundary_crossings_detected(self):
        gen = DFDGenerator(VALID_APP_DETAILS)
        artifacts = gen.generate(render_png=False)
        crossings = artifacts["boundary_crossings"]
        crossing_pairs = {(c["source"], c["destination"]) for c in crossings}
        assert ("web", "api") in crossing_pairs
        assert ("api", "auth0") in crossing_pairs

    def test_internal_flow_not_crossing(self):
        gen = DFDGenerator(VALID_APP_DETAILS)
        artifacts = gen.generate(render_png=False)
        crossings = artifacts["boundary_crossings"]
        crossing_pairs = {(c["source"], c["destination"]) for c in crossings}
        assert ("api", "db") not in crossing_pairs

    def test_empty_graph_raises_on_generate(self):
        details = {
            "components": [],
            "external_services": [],
            "data_flows": [],
            "trust_boundaries": [],
        }
        gen = DFDGenerator(details)
        with pytest.raises(DFDValidationError, match="empty"):
            gen.generate(render_png=False)

    def test_node_dfd_types(self):
        gen = DFDGenerator(VALID_APP_DETAILS)
        artifacts = gen.generate(render_png=False)
        node_map = {n["id"]: n for n in artifacts["nodes"]}
        assert node_map["web"]["dfd_type"] == "external_entity"
        assert node_map["api"]["dfd_type"] == "process"
        assert node_map["db"]["dfd_type"] == "data_store"
        assert node_map["auth0"]["dfd_type"] == "external_entity"

    def test_skips_flow_with_unknown_endpoint(self):
        details = {
            "components": [{"id": "a", "name": "A"}],
            "external_services": [],
            "data_flows": [{"from": "a", "to": "nonexistent"}],
            "trust_boundaries": [],
        }
        gen = DFDGenerator(details)
        assert gen.graph.number_of_edges() == 0


class TestFormatDFDContext:
    def test_contains_mermaid_block(self):
        artifacts: DFDArtifacts = {
            "mermaid": "flowchart TD\n    A --> B",
            "nodes": [{"id": "A"}, {"id": "B"}],
            "boundary_crossings": [],
        }
        text = format_dfd_context(artifacts)
        assert "```mermaid" in text
        assert "flowchart TD" in text

    def test_includes_boundary_crossings(self):
        artifacts: DFDArtifacts = {
            "mermaid": "flowchart TD",
            "nodes": [],
            "boundary_crossings": [
                {
                    "source": "web",
                    "destination": "api",
                    "from_boundary": None,
                    "to_boundary": "Internal",
                    "label": "REST",
                    "protocol": "HTTPS",
                    "auth": "JWT",
                    "encryption": "TLS",
                }
            ],
        }
        text = format_dfd_context(artifacts)
        assert "web -> api" in text
        assert "(outside)" in text
        assert "Internal" in text

    def test_includes_node_ids(self):
        artifacts: DFDArtifacts = {
            "mermaid": "flowchart TD",
            "nodes": [{"id": "svc1"}, {"id": "svc2"}],
            "boundary_crossings": [],
        }
        text = format_dfd_context(artifacts)
        assert "svc1, svc2" in text
