import json
from pathlib import Path
from typing import Optional

import matplotlib.pyplot as plt
import networkx as nx

def plot_permission_tree( policy_file: str | Path, permission: str, security_group: str, path: str, output_file: Optional[str | Path] = None) -> None:
    """
    Draw a focused Data Mesh permission tree.

    Node status:
        ALLOW     -> green
        DENY      -> red
        UNDEFINED -> neutral blue-gray

    Selected path:
        - thicker node border
        - darker border color
        - thicker connecting edge

    Only the selected branch is expanded.
    """
    policy_file = Path(policy_file)

    # ==========================================================
    # LOAD POLICY
    # ==========================================================

    with policy_file.open( "r", encoding="utf-8") as file:
        data = json.load(file)

    # ==========================================================
    # NORMALIZE PATH
    # ==========================================================
    path = path.strip()
    if ":" in path:
        path_parts = [ part.strip() for part in path.split("/") if part.strip() ]
    else:
        raw_parts = [ part.strip() for part in path.split("/") if part.strip() ]
        level_names = [ "catalog", "schema", "table", "column"]
        path_parts = [ f"{level}:{value}" for level, value in zip( level_names, raw_parts) ]
    selected_path = set(path_parts)

    # ==========================================================
    # GRAPH
    # ==========================================================
    graph = nx.DiGraph()
    root_id = "root"

    # ==========================================================
    # HELPERS
    # ==========================================================
    def get_permission_status( permissions: dict) -> str:
        group_permissions = permissions.get( security_group, {})
        allow = group_permissions.get( "allow", [])
        deny = group_permissions.get( "deny", [])
        if permission in deny:
            return "deny"
        if permission in allow:
            return "allow"
        return "undefined"
    def path_key( level: str, name: str) -> str:
        return f"{level}:{name}"

    # ==========================================================
    # ROOT
    # ==========================================================
    root_permissions = ( data .get("resource_values", {}) .get("root", {}) .get("permissions", {}) )
    graph.add_node( root_id, type="root", name="ROOT", permission_status=get_permission_status( root_permissions ))

    # ==========================================================
    # BUILD TREE
    # ==========================================================
    resource_values = data.get( "resource_values", {})
    for catalog in resource_values.get( "catalogs", []):
        catalog_name = catalog.get( "catalogName", "")
        catalog_key = path_key( "catalog", catalog_name)
        catalog_id = ( f"catalog::{catalog_name}" )
        graph.add_node( catalog_id, type="catalog", name=catalog_name, permission_status=get_permission_status( catalog.get( "permissions", {}) ), path_key=catalog_key)
        graph.add_edge( root_id, catalog_id)

        # ======================================================
        # SCHEMAS
        # ======================================================
        for schema in catalog.get( "schemas", []):
            schema_name = schema.get( "schemaName", "")
            schema_key = path_key( "schema", schema_name)
            schema_id = ( f"{catalog_id}::schema::{schema_name}" )
            graph.add_node( schema_id, type="schema", name=schema_name, permission_status=get_permission_status( schema.get( "permissions", {}) ), path_key=schema_key)
            graph.add_edge( catalog_id, schema_id)

            # ==================================================
            # TABLES
            # ==================================================
            for table in schema.get( "tables", []):
                table_name = table.get( "tableName", "")
                table_key = path_key( "table", table_name)
                table_id = ( f"{schema_id}::table::{table_name}" )
                graph.add_node( table_id, type="table", name=table_name, permission_status=get_permission_status( table.get( "permissions", {}) ), path_key=table_key)
                graph.add_edge( schema_id, table_id)

                # ==============================================
                # COLUMNS
                # ==============================================
                for column in table.get( "columns", []):
                    if isinstance( column, dict):
                        column_name = column.get( "name", "")
                        column_type = column.get( "type", "")
                    else:
                        column_name = str(column)
                        column_type = ""
                    column_key = path_key( "column", column_name)
                    column_id = ( f"{table_id}::column::{column_name}" )
                    graph.add_node( column_id, type="column", name=column_name, column_type=column_type, permission_status="undefined", path_key=column_key)
                    graph.add_edge( table_id, column_id)

    # ==========================================================
    # SELECTED NODES
    # ==========================================================
    for node in graph.nodes:
        node_path = graph.nodes[node].get( "path_key" )
        graph.nodes[node]["selected"] = ( node == root_id or node_path in selected_path )

    # ==========================================================
    # VISIBLE TREE
    # ==========================================================
    visible_nodes = {root_id}
    selected_nodes = { node for node in graph.nodes if graph.nodes[node].get( "selected", False) }
    # Show selected nodes and their direct children.
    for node in selected_nodes:
        visible_nodes.add(node)
        for child in graph.successors(node):
            visible_nodes.add(child)

    # Add ancestors.
    changed = True
    while changed:
        changed = False
        for node in list(visible_nodes):
            for parent in graph.predecessors( node ):
                if parent not in visible_nodes:
                    visible_nodes.add(parent)
                    changed = True
    visible_graph = graph.subgraph( visible_nodes ).copy()

    # ==========================================================
    # HIERARCHICAL LAYOUT
    # ==========================================================
    positions = {}
    leaf_counter = [0]
    def assign_position( node, depth):
        children = list( visible_graph.successors(node) )
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

    # ==========================================================
    # FIGURE
    # ==========================================================
    number_of_nodes = len( visible_graph.nodes )
    number_of_leaves = sum( 1 for node in visible_graph.nodes if visible_graph.out_degree(node) == 0 )
    max_depth = max( -y for x, y in positions.values() )
    figure_width = max( 12, number_of_leaves * 1.8)
    figure_height = max( 7, (max_depth + 1) * 2.0)
    fig, ax = plt.subplots( figsize=( figure_width, figure_height))

    # ==========================================================
    # COLOR PALETTE
    # ==========================================================
    # Soft fills
    fill_colors = { "allow": "#DFF3E4", "deny": "#F9DEDE", "undefined": "#E8EDF3"}
    # Strong borders
    border_colors = { "allow": "#238636", "deny": "#C62828", "undefined": "#64748B"}
    # Selected path colors
    selected_border_colors = { "allow": "#176B2C", "deny": "#9B1C1C", "undefined": "#334155"}

    # ==========================================================
    # EDGES
    # ==========================================================
    normal_edges = []
    selected_path_edges = []
    for parent, child in visible_graph.edges:
        parent_selected = ( visible_graph.nodes[parent].get( "selected", False) )
        child_selected = ( visible_graph.nodes[child].get( "selected", False) )
        if ( parent_selected and child_selected ):
            selected_path_edges.append( (parent, child) )
        else:
            normal_edges.append( (parent, child) )

    # ----------------------------------------------------------
    # Normal edges
    # ----------------------------------------------------------
    nx.draw_networkx_edges( visible_graph, positions, edgelist=normal_edges, ax=ax, arrows=False, width=1.2, edge_color="#CBD5E1", alpha=0.8)

    # ----------------------------------------------------------
    # Selected path edges
    # ----------------------------------------------------------
    for status in [ "allow", "deny", "undefined"]:
        edges = []
        for parent, child in selected_path_edges:
            child_status = visible_graph.nodes[ child ].get( "permission_status", "undefined")
            if child_status == status:
                edges.append( (parent, child) )
        if edges:
            nx.draw_networkx_edges( visible_graph, positions, edgelist=edges, ax=ax, arrows=False, width=4.0, edge_color=selected_border_colors[ status ], alpha=0.9)

    # ==========================================================
    # NODES
    # ==========================================================
    node_sizes = { "root": 2200, "catalog": 2000, "schema": 1800, "table": 1600, "column": 1300}
    for node in visible_graph.nodes:
        node_data = visible_graph.nodes[node]
        node_type = node_data.get( "type", "unknown")
        status = node_data.get( "permission_status", "undefined")
        selected = node_data.get( "selected", False)
        if selected:
            border_color = selected_border_colors[ status ]
            linewidth = 4.0
        else:
            border_color = border_colors[ status ]
            linewidth = 1.8
        nx.draw_networkx_nodes( visible_graph, positions, nodelist=[node], node_size=node_sizes.get( node_type, 1400), node_color=fill_colors[ status ], edgecolors=border_color, linewidths=linewidth, node_shape="o", ax=ax)

    # ==========================================================
    # LABELS
    # ==========================================================
    labels = {}
    for node in visible_graph.nodes:
        node_data = visible_graph.nodes[node]
        name = node_data.get( "name", "")
        if node_data.get( "type" ) == "column":
            column_type = node_data.get( "column_type", "")
            if column_type:
                name = ( f"{name}\n" f"({column_type})" )
        labels[node] = name
    nx.draw_networkx_labels( visible_graph, positions, labels=labels, ax=ax, font_size=8.5, font_weight="bold", font_color="#1E293B")

    # ==========================================================
    # TITLE
    # ==========================================================
    ax.set_title( ( f'Permission: "{permission}"\n' f'Group: "{security_group}"\n' f'Path: {path}' ), fontsize=16, fontweight="bold", color="#1E293B", pad=25)

    # ==========================================================
    # LEGEND
    # ==========================================================
    legend_text = ( "ALLOW" "    •    " "DENY" "    •    " "UNDEFINED" "    |    " "Thick border = selected path" )
    fig.text( 0.5, 0.025, legend_text, ha="center", fontsize=10, color="#475569")

    # ==========================================================
    # AXIS
    # ==========================================================
    ax.axis("off")

    # ==========================================================
    # OUTPUT
    # ==========================================================
    if output_file is None:
        output_file = ( policy_file.parent / "permission_tree.png" )
    else:
        output_file = Path( output_file )
    fig.savefig( output_file, dpi=300, bbox_inches="tight", facecolor="white")

    plt.close(fig)

    # ==========================================================
    # RESULT
    # ==========================================================

    print()
    print("=" * 80)
    print("PERMISSION TREE")
    print("=" * 80)
    print()
    print(f"Permission:     {permission}")
    print(f"Security group: {security_group}")
    print(f"Path:            {path}")
    print()
    print(f"Visible nodes:  {number_of_nodes}")
    print()
    print("Graph written to:")
    print(output_file)

# ==============================================================
# EXAMPLE
# ==============================================================

if __name__ == "__main__":

    plot_permission_tree(
        policy_file="Pipelines/A_GenerationPipeline/output_generation/cumulative_tree/cumulative_tree.json",
        permission="SelectFromColumns",
        security_group="auditor",
        path="catalog:iceberg/schema:hr/table:people",
        output_file="Draw/output/select_from_columns_tree.png",
    )
