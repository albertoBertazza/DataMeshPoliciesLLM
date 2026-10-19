import json
from pathlib import Path
from typing import Optional

import matplotlib.pyplot as plt
import networkx as nx

def plot_data_mesh_tree(data_mesh_file: str | Path, output_file: Optional[str | Path] = None) -> None:
    """
    Draw the Data Mesh hierarchy as a tree.

    Hierarchy:

        ROOT
        └── catalog
            └── schema
                └── table
                    └── column

    The input JSON must have the structure:

        {
            "catalogs": [
                {
                    "name": "...",
                    "schemas": [
                        {
                            "name": "...",
                            "tables": [
                                {
                                    "name": "...",
                                    "columns": [
                                        {
                                            "name": "...",
                                            "type": "..."
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ]
        }
    """
    data_mesh_file = Path(data_mesh_file)

    # ==========================================================
    # LOAD JSON
    # ==========================================================
    with data_mesh_file.open( "r", encoding="utf-8") as file:
        data = json.load(file)
    if not isinstance(data, dict):
        raise ValueError( "Data mesh JSON must contain an object." )

    # ==========================================================
    # CREATE GRAPH
    # ==========================================================
    graph = nx.DiGraph()
    # Root
    root_id = "ROOT"
    graph.add_node( root_id, type="root", label="ROOT")

    # ==========================================================
    # BUILD TREE
    # ==========================================================
    for catalog in data.get("catalogs", []):
        catalog_name = catalog["name"]
        catalog_id = ( f"catalog::{catalog_name}" )
        graph.add_node( catalog_id, type="catalog", label=catalog_name)
        graph.add_edge( root_id, catalog_id)

        # ------------------------------------------------------
        # SCHEMAS
        # ------------------------------------------------------
        for schema in catalog.get( "schemas", []):
            schema_name = schema["name"]
            schema_id = ( f"{catalog_id}::schema::{schema_name}" )
            graph.add_node( schema_id, type="schema", label=schema_name)
            graph.add_edge( catalog_id, schema_id)

            # --------------------------------------------------
            # TABLES
            # --------------------------------------------------
            for table in schema.get( "tables", []):
                table_name = table["name"]
                table_id = ( f"{schema_id}::table::{table_name}" )
                graph.add_node( table_id, type="table", label=table_name)
                graph.add_edge( schema_id, table_id)

                # ----------------------------------------------
                # COLUMNS
                # ----------------------------------------------
                for column in table.get( "columns", []):
                    column_name = column["name"]
                    column_type = column.get( "type", "")
                    column_id = ( f"{table_id}::column::{column_name}" )
                    label = column_name
                    if column_type:
                        label = ( f"{column_name}\n" f"({column_type})" )
                    graph.add_node( column_id, type="column", label=label)
                    graph.add_edge( table_id, column_id)

    # ==========================================================
    # INFORMATION
    # ==========================================================
    print()
    print("=" * 100)
    print("DATA MESH HIERARCHY")
    print("=" * 100)
    print()
    print( f"Nodes: {graph.number_of_nodes()}" )
    print( f"Edges: {graph.number_of_edges()}" )
    print()

    # ==========================================================
    # TREE LAYOUT
    # ==========================================================
    def hierarchy_layout(graph):
        positions = {}

        # ------------------------------------------------------
        # Get depth of every node
        # ------------------------------------------------------
        depths = {}
        for node in graph.nodes:
            depths[node] = nx.shortest_path_length( graph, root_id, node)

        # ------------------------------------------------------
        # Group nodes by depth
        # ------------------------------------------------------
        levels = {}
        for node, depth in depths.items():
            levels.setdefault( depth, []).append(node)

        # ------------------------------------------------------
        # Calculate X positions recursively
        # ------------------------------------------------------
        leaf_counter = [0]

        def assign_position( node, depth):
            children = list( graph.successors(node) )
            if not children:
                x = leaf_counter[0]
                leaf_counter[0] += 1
            else:
                child_positions = []
                for child in children:
                    child_x = assign_position( child, depth + 1)
                    child_positions.append( child_x )
                x = sum( child_positions ) / len(child_positions)
            positions[node] = ( x, -depth)
            return x
        assign_position( root_id, 0)
        return positions
    pos = hierarchy_layout(graph)

    # ==========================================================
    # FIGURE SIZE
    # ==========================================================
    max_depth = max( depth for depth in nx.single_source_shortest_path_length( graph, root_id).values() )
    number_of_leaves = sum( 1 for node in graph.nodes if graph.out_degree(node) == 0 )
    figure_width = max( 14, number_of_leaves * 1.4)
    figure_height = max( 8, (max_depth + 1) * 2.0)
    fig, ax = plt.subplots( figsize=( figure_width, figure_height) )

    # ==========================================================
    # NODE TYPES
    # ==========================================================
    node_types = { node: graph.nodes[node]["type"] for node in graph.nodes }
    type_sizes = { "root": 1800, "catalog": 1500, "schema": 1300, "table": 1000, "column": 700}

    # ==========================================================
    # DRAW EDGES
    # ==========================================================
    nx.draw_networkx_edges( graph, pos, ax=ax, arrows=False, width=1.2, alpha=0.5)

    # ==========================================================
    # DRAW NODES
    # ==========================================================
    for node_type in [ "root", "catalog", "schema", "table", "column"]:
        nodes = [ node for node in graph.nodes if node_types[node] == node_type ]
        if not nodes:
            continue
        nx.draw_networkx_nodes( graph, pos, nodelist=nodes, node_size=type_sizes[node_type], node_shape="o", ax=ax, alpha=0.9)

    # ==========================================================
    # LABELS
    # ==========================================================
    labels = { node: graph.nodes[node]["label"] for node in graph.nodes }
    nx.draw_networkx_labels( graph, pos, labels=labels, ax=ax, font_size=8, font_weight="bold")

    # ==========================================================
    # TITLE
    # ==========================================================
    ax.set_title( "Data Mesh Resource Hierarchy", fontsize=18, fontweight="bold", pad=25)

    # ==========================================================
    # LEGEND
    # ==========================================================
    legend_text = ( "ROOT  →  Catalog  →  Schema  →  Table  →  Column" )
    fig.text( 0.5, 0.02, legend_text, ha="center", fontsize=10, alpha=0.7)

    # ==========================================================
    # AXIS
    # ==========================================================
    ax.axis("off")

    # ==========================================================
    # OUTPUT
    # ==========================================================
    if output_file is None:
        output_file = ( data_mesh_file.parent / "data_mesh_tree.png" )
    else:
        output_file = Path( output_file )
    fig.savefig( output_file, dpi=300, bbox_inches="tight")
    plt.close(fig)

    # ==========================================================
    # RESULT
    # ==========================================================

    print()
    print("Data Mesh tree written to:")
    print(output_file)

if __name__ == "__main__":
    plot_data_mesh_tree( "Structure/data_mesh.json", output_file="Analysis/output/data_mesh_tree.png")
