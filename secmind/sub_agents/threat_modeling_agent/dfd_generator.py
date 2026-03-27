"""
DFD (Data Flow Diagram) generator using NetworkX and Matplotlib.
"""

import logging
import networkx as nx
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import os
import textwrap

logger = logging.getLogger(__name__)

class DFDGenerator:
    """Generates a DFD from application details."""

    def __init__(self, app_details):
        self.app_details = app_details
        self.graph = nx.DiGraph()
        self.node_labels = {}
        self.edge_labels = {}

    def _wrap_text(self, text, width=20):
        """Wraps text to a specified width."""
        return '\n'.join(textwrap.wrap(text, width=width))

    def generate_dfd(self):
        """
        Generates the DFD from the application details and saves it to a file.

        Returns:
            A string containing the path to the generated DFD image.
        """
        self._add_components()
        self._add_data_flows()
        self._add_external_services()

        if not self.graph:
            logger.warning("DFD graph is empty. Skipping DFD generation.")
            return None

        plt.figure(figsize=(25, 20))
        pos = nx.spring_layout(self.graph, k=0.8, iterations=100, seed=42)

        # Group nodes by type
        entity_nodes = [node for node, attr in self.graph.nodes(data=True) if attr.get('type') in ['frontend', 'external_service']]
        process_nodes = [node for node, attr in self.graph.nodes(data=True) if attr.get('type') == 'service']
        store_nodes = [node for node, attr in self.graph.nodes(data=True) if attr.get('type') == 'database']
        other_nodes = [node for node, attr in self.graph.nodes(data=True) if attr.get('type') not in ['frontend', 'external_service', 'service', 'database']]


        # Draw nodes
        nx.draw_networkx_nodes(self.graph, pos, nodelist=entity_nodes, node_size=5000, node_color='lightblue', node_shape='s')
        nx.draw_networkx_nodes(self.graph, pos, nodelist=process_nodes, node_size=5000, node_color='lightgreen', node_shape='o')
        nx.draw_networkx_nodes(self.graph, pos, nodelist=store_nodes, node_size=5000, node_color='lightyellow', node_shape='s')
        nx.draw_networkx_nodes(self.graph, pos, nodelist=other_nodes, node_size=5000, node_color='lightgray', node_shape='s')


        # Draw edges
        nx.draw_networkx_edges(
            self.graph, pos, arrowstyle='->', arrowsize=20,
            connectionstyle='arc3,rad=0.1'
        )

        # Draw labels
        for node in store_nodes:
            self.node_labels[node] = f"<<Data Store>>\n{self.node_labels[node]}"

        entity_and_other_labels = {node: self.node_labels[node] for node in entity_nodes + other_nodes}
        process_labels = {node: self.node_labels[node] for node in process_nodes}
        store_labels = {node: self.node_labels[node] for node in store_nodes}

        nx.draw_networkx_labels(self.graph, pos, labels=entity_and_other_labels, font_size=10, font_weight='bold',
                                bbox=dict(facecolor="lightblue", edgecolor='black', boxstyle='round,pad=0.2'))
        nx.draw_networkx_labels(self.graph, pos, labels=process_labels, font_size=10, font_weight='bold',
                                bbox=dict(facecolor="lightgreen", edgecolor='black', boxstyle='round,pad=0.2'))
        nx.draw_networkx_labels(self.graph, pos, labels=store_labels, font_size=10, font_weight='bold',
                                bbox=dict(facecolor="lightyellow", edgecolor='black', boxstyle='round,pad=0.2'))

        nx.draw_networkx_edge_labels(
            self.graph, pos, edge_labels=self.edge_labels, font_size=10,
            label_pos=0.3, font_color='red'
        )

        # Draw trust boundaries
        self._add_trust_boundaries(pos)

        plt.title("Data Flow Diagram", size=15)
        plt.axis('off')
        
        if not os.path.exists('reports'):
            os.makedirs('reports')

        dfd_image_path = "reports/dfd.png"
        plt.savefig(dfd_image_path, bbox_inches='tight')
        plt.close()

        logger.info(f"DFD image saved to {dfd_image_path}")
        return dfd_image_path

    def _add_components(self):
        """Adds components to the DFD."""
        if 'components' in self.app_details:
            for component in self.app_details['components']:
                self.graph.add_node(component['id'], type=component.get('type'))
                self.node_labels[component['id']] = self._wrap_text(component['name'])

    def _add_data_flows(self):
        """Adds data flows to the DFD."""
        if 'data_flows' in self.app_details:
            for flow in self.app_details['data_flows']:
                source = flow.get('from') or flow.get('source') or flow.get('src')
                destination = flow.get('to') or flow.get('destination') or flow.get('dest')

                if not source or not destination:
                    logger.warning(f"Skipping data flow due to missing source or destination: {flow}")
                    continue

                self.graph.add_edge(source, destination)
                self.edge_labels[(source, destination)] = self._wrap_text(flow.get('label', ''))

    def _add_external_services(self):
        """Adds external services to the DFD."""
        if 'external_services' in self.app_details:
            for service in self.app_details['external_services']:
                self.graph.add_node(service['id'], type='external_service')
                self.node_labels[service['id']] = self._wrap_text(service['name'])

    def _add_trust_boundaries(self, pos):
        """Adds trust boundaries to the DFD."""
        if 'trust_boundaries' in self.app_details:
            for i, boundary in enumerate(self.app_details['trust_boundaries']):
                component_pos = {comp_id: pos[comp_id] for comp_id in boundary['components'] if comp_id in pos}
                if not component_pos:
                    continue

                # Get the bounding box of the components in the trust boundary
                min_x = min(p[0] for p in component_pos.values()) - 0.1
                max_x = max(p[0] for p in component_pos.values()) + 0.1
                min_y = min(p[1] for p in component_pos.values()) - 0.1
                max_y = max(p[1] for p in component_pos.values()) + 0.1

                # Draw a rectangle around the components
                rect = plt.Rectangle((min_x, min_y), max_x - min_x, max_y - min_y,
                                     fill=False, edgecolor='red', linestyle='--', linewidth=2)
                plt.gca().add_patch(rect)
                plt.text(min_x, max_y + 0.05, boundary['name'], fontsize=10, color='red')

