import json
from pathlib import Path
from typing import Optional

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.colors import ListedColormap

def plot_permission_action_matrix( check_for_action_file: str | Path, output_file: Optional[str | Path] = None) -> None:
    """
    Plot a Permission × Action dependency matrix.

    Rows    = permissions
    Columns = actions

    A filled cell means that the action requires that permission.
    """
    check_for_action_file = Path(check_for_action_file)

    # ==========================================================
    # LOAD JSON
    # ==========================================================

    with check_for_action_file.open( "r", encoding="utf-8") as file:
        data = json.load(file)
    if not isinstance(data, dict):
        raise ValueError( "checkForAction.json must contain a JSON object." )

    # ==========================================================
    # SELECT ACTIONS
    # ==========================================================
    actions = list(data.keys())
    if not actions:
        raise ValueError( "At least one action is required." )

    # ==========================================================
    # ACTION → PERMISSIONS
    # ==========================================================
    action_permissions = { action: list(dict.fromkeys(data[action])) for action in actions }

    # ==========================================================
    # ALL PERMISSIONS — MOST USED AT BOTTOM
    # ==========================================================
    permission_usage = {}
    for action in actions:
        for permission in action_permissions[action]:
            permission_usage[permission] = ( permission_usage.get(permission, 0) + 1 )
    # Least used at top, most used at bottom
    permissions = sorted( permission_usage, key=lambda permission: permission_usage[permission])
    if not permissions:
        raise ValueError( "No permissions found." )

    # ==========================================================
    # BUILD MATRIX
    # ==========================================================
    matrix = np.zeros( ( len(permissions), len(actions)), dtype=int)
    permission_index = { permission: index for index, permission in enumerate(permissions) }
    for column, action in enumerate(actions):
        for permission in action_permissions[action]:
            row = permission_index[permission]
            matrix[row, column] = 1

    # ==========================================================
    # PRINT SUMMARY
    # ==========================================================

    print()
    print("=" * 100)
    print("PERMISSION × ACTION MATRIX")
    print("=" * 100)
    print()
    print(f"Permissions: {len(permissions)}")
    print(f"Actions:     {len(actions)}")
    print()

    # ==========================================================
    # FIGURE SIZE
    # ==========================================================
    figure_width = max( 12, len(actions) * 0.75)
    figure_height = max( 7, len(permissions) * 0.45)
    fig, ax = plt.subplots( figsize=( figure_width, figure_height) )

    # ==========================================================
    # DRAW MATRIX
    # ==========================================================
    cmap = ListedColormap([
        "white",  # 0 = not required
        "lightblue",  # 1 = required
    ])
    ax.imshow( matrix, aspect="auto", interpolation="none", cmap=cmap)

    # ==========================================================
    # AXIS LABELS
    # ==========================================================
    ax.set_xticks( np.arange(len(actions)) )
    ax.set_yticks( np.arange(len(permissions)) )
    ax.set_xticklabels( actions, rotation=60, ha="right", fontsize=9)
    ax.set_yticklabels( permissions, fontsize=10)

    # ==========================================================
    # CELL GRID
    # ==========================================================
    ax.set_xticks( np.arange(-0.5, len(actions), 1), minor=True)
    ax.set_yticks( np.arange(-0.5, len(permissions), 1), minor=True)
    ax.grid( which="minor", linewidth=0.5, alpha=0.35)
    ax.tick_params( which="minor", bottom=False, left=False)

    # ==========================================================
    # MARK CELLS
    # ==========================================================
    for row in range(len(permissions)):
        for column in range(len(actions)):
            if matrix[row, column] == 1:
                ax.text( column, row, "✓", ha="center", va="center", fontsize=11, fontweight="bold")

    # ==========================================================
    # TITLES
    # ==========================================================
    ax.set_xlabel( "Trino Actions", fontsize=12, fontweight="bold", labelpad=12)
    ax.set_ylabel( "Permissions", fontsize=12, fontweight="bold", labelpad=12)
    ax.set_title( "Permission × Action Dependency Matrix", fontsize=17, fontweight="bold", pad=20)

    # ==========================================================
    # EXPLANATION
    # ==========================================================
    fig.text( 0.5, 0.01, "✓ = permission required by the action", ha="center", fontsize=10, alpha=0.7)

    # ==========================================================
    # LAYOUT
    # ==========================================================
    plt.tight_layout( rect=(0, 0.03, 1, 1) )

    # ==========================================================
    # OUTPUT
    # ==========================================================
    if output_file is None:
        output_file = ( check_for_action_file.parent / "permission_action_matrix.png" )
    else:
        output_file = Path(output_file)
    fig.savefig( output_file, dpi=300, bbox_inches="tight")
    plt.close(fig)

    # ==========================================================
    # RESULT
    # ==========================================================

    print()
    print("Permission × Action matrix written to:")
    print(output_file)

if __name__ == "__main__":
        plot_permission_action_matrix( "Analysis/docker-opa-mapping-aware/opa/checkForAction.json", output_file="Analysis/output/action_permission_euler.png")
