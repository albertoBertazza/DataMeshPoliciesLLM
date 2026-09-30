from __future__ import annotations

from typing import Any


# ANSI terminal colors
GREEN = "\033[92m"
RED = "\033[91m"
GRAY = "\033[90m"
RESET = "\033[0m"
BOLD = "\033[1m"


FILTER_PERMISSIONS = {
    "GetRowFilters",
    "GetColumnMask",
}


def _get_permission_status(
    permission: str,
    permission_detail: dict[str, Any],
    path: str,
) -> str:
    """
    Return the local declaration status of a permission at a specific path.

    ALLOW     -> explicitly allowed at this node
    DENY      -> explicitly denied at this node
    UNDEFINED -> no local declaration at this node
    """
    declarations = permission_detail.get("declarations", [])

    for declaration in declarations:
        if declaration.get("path") != path:
            continue

        if permission in declaration.get("allow", []):
            return "ALLOW"

        if permission in declaration.get("deny", []):
            return "DENY"

    return "UNDEFINED"


def _color_status(status: str) -> str:
    """Return a colored authorization status."""
    if status == "ALLOW":
        return f"{GREEN}{status}{RESET}"

    if status == "DENY":
        return f"{RED}{status}{RESET}"

    return f"{GRAY}{status}{RESET}"


def _build_resource_nodes(
    resource_path: str,
) -> list[tuple[str, str]]:
    """
    Build the resource hierarchy from root to the target.

    Example:
        root/iceberg/hr/employees/salary

    becomes:
        root
        root/iceberg
        root/iceberg/hr
        root/iceberg/hr/employees
        root/iceberg/hr/employees/salary
    """
    parts = resource_path.strip("/").split("/")

    if not parts or parts[0] != "root":
        parts.insert(0, "root")

    nodes: list[tuple[str, str]] = []

    current_path = ""

    for part in parts:
        current_path = (
            part
            if not current_path
            else f"{current_path}/{part}"
        )

        nodes.append((part, current_path))

    return nodes


def _print_permission_tree(
    permission: str,
    permission_detail: dict[str, Any],
    nodes: list[tuple[str, str]],
) -> None:
    """Print one normal permission over the resource hierarchy."""

    print(
        f"{BOLD}Permission: {permission}{RESET}"
    )

    for index, (node_name, node_path) in enumerate(nodes):

        status = _get_permission_status(
            permission=permission,
            permission_detail=permission_detail,
            path=node_path,
        )

        colored_status = _color_status(status)

        if index == 0:
            print(
                f"{node_name} "
                f"[{colored_status}]"
            )
        else:
            indentation = "    " * (index - 1)

            print(
                f"{indentation}"
                f"└── "
                f"{node_name} "
                f"[{colored_status}]"
            )

    print()


def _get_filter_value(
    action_data: dict[str, Any],
    permission: str,
) -> Any:
    """
    Get the value associated with a filter permission.

    GetRowFilters:
        row_filter == null -> []

    GetColumnMask:
        column_masks == {} -> []

    Otherwise return the actual configured value.
    """

    if permission == "GetRowFilters":
        value = action_data.get("row_filter")

        if value is None:
            return []

        return value

    if permission == "GetColumnMask":
        value = action_data.get("column_masks")

        if value == {} or value is None:
            return []

        return value

    return None


def _print_filter_permission(
    permission: str,
    action_data: dict[str, Any],
) -> None:
    """
    Print the actual row-filter or column-mask value.

    These permissions are special and therefore do not use the
    hierarchical ALLOW/DENY tree.
    """

    value = _get_filter_value(
        action_data,
        permission,
    )

    print(
        f"{BOLD}{permission}:{RESET} {value}"
    )

    print()


def print_permission_tree(
    results: list[dict[str, Any]],
) -> None:
    """
    Print authorization information as a hierarchical resource tree.

    Normal permissions:
        ALLOW     -> green
        DENY      -> red
        UNDEFINED -> gray

    Special permissions:
        GetRowFilters  -> value of row_filter, null becomes []
        GetColumnMask  -> value of column_masks, {} becomes []
    """

    for result_index, result in enumerate(
        results,
        start=1,
    ):

        security_group = result.get(
            "securityGroup",
            "unknown",
        )

        resource_path = result.get(
            "resourcePath",
            "root",
        )

        resource_type = result.get(
            "resourceType",
            "unknown",
        )

        actions = result.get(
            "actions",
            {},
        )

        print()
        print("=" * 90)

        print(
            f"{BOLD}Result #{result_index}{RESET}"
        )

        print(
            f"{BOLD}Security Group:{RESET} "
            f"{security_group}"
        )

        print(
            f"{BOLD}Resource:{RESET} "
            f"{resource_path}"
        )

        print(
            f"{BOLD}Resource Type:{RESET} "
            f"{resource_type}"
        )

        print("=" * 90)

        nodes = _build_resource_nodes(
            resource_path
        )

        for action_name, action_data in actions.items():

            required_permissions = action_data.get(
                "requiredPermissions",
                [],
            )

            permission_details = action_data.get(
                "permissionDetails",
                {},
            )

            allowed = action_data.get(
                "allowed",
                False,
            )

            decision = (
                "ALLOW"
                if allowed
                else "DENY"
            )

            print()

            print(
                f"{BOLD}Action:{RESET} "
                f"{action_name} "
                f"→ {_color_status(decision)}"
            )

            print(
                f"{BOLD}Required permissions:{RESET} "
                f"{', '.join(required_permissions)}"
            )

            print()

            for permission in required_permissions:

                # -------------------------------------------------
                # GetRowFilters / GetColumnMask are special.
                # Do NOT print them as hierarchical permissions.
                # -------------------------------------------------
                if permission in FILTER_PERMISSIONS:
                    _print_filter_permission(
                        permission=permission,
                        action_data=action_data,
                    )
                    continue

                # -------------------------------------------------
                # Normal permission
                # -------------------------------------------------
                permission_detail = permission_details.get(
                    permission,
                    {},
                )

                _print_permission_tree(
                    permission=permission,
                    permission_detail=permission_detail,
                    nodes=nodes,
                )