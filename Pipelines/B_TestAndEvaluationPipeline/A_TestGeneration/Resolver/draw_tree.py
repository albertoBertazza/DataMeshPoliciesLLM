from __future__ import annotations

from typing import Any

# ANSI terminal colors
GREEN = "\033[92m"
RED = "\033[91m"
GRAY = "\033[90m"
RESET = "\033[0m"
BOLD = "\033[1m"

# These are special obligation permissions.
OBLIGATION_PERMISSIONS = { "GetRowFilters", "GetColumnMask"}

# These are actual metadata filter declarations.
METADATA_FILTERS = ( "FilterCatalogs", "FilterSchemas", "FilterTables", "FilterColumns")

def _get_permission_status( permission: str, permission_detail: dict[str, Any], path: str) -> str:
    """
    Return the local declaration status of a normal permission
    at a specific resource path.

    ALLOW     -> explicitly allowed at this node
    DENY      -> explicitly denied at this node
    UNDEFINED -> no local declaration at this node
    """

    declarations = permission_detail.get( "declarations", [] )

    for declaration in declarations:

        if declaration.get("path") != path:
            continue

        if permission in declaration.get( "allow", [] ):
            return "ALLOW"

        if permission in declaration.get( "deny", [] ):
            return "DENY"

    return "UNDEFINED"

def _color_status(status: str) -> str:
    """Return a colored authorization status."""

    if status == "ALLOW":
        return f"{GREEN}{status}{RESET}"

    if status == "DENY":
        return f"{RED}{status}{RESET}"

    return f"{GRAY}{status}{RESET}"

def _build_resource_nodes( resource_path: str) -> list[tuple[str, str]]:
    """
    Build the resource hierarchy from root to target.

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

        current_path = ( part if not current_path else f"{current_path}/{part}" )

        nodes.append( (part, current_path) )

    return nodes

def _print_permission_tree( permission: str, permission_detail: dict[str, Any], nodes: list[tuple[str, str]]) -> None:
    """Print one normal permission over the resource hierarchy."""

    print( f"{BOLD}Permission: {permission}{RESET}" )

    for index, ( node_name, node_path) in enumerate(nodes):

        status = _get_permission_status( permission=permission, permission_detail=permission_detail, path=node_path)

        colored_status = _color_status(status)

        if index == 0:

            print( f"{node_name} " f"[{colored_status}]" )

        else:

            indentation = "    " * ( index - 1 )

            print( f"{indentation}" f"└── " f"{node_name} " f"[{colored_status}]" )

    print()

def _print_filter_declarations( filters: dict[str, Any]) -> None:
    """
    Print actual metadata visibility filters.

    IMPORTANT:

    These are NOT normal ALLOW/DENY permissions.

    Example resolver value:

        "FilterSchemas": {
            "allowed": [],
            "deny": ["hr"]
        }

    is displayed as:

        FilterSchemas → filtered out: ['hr']

    because the list contains the objects removed from the
    corresponding metadata response.
    """

    if not isinstance(filters, dict):
        return

    active = False

    for filter_name in METADATA_FILTERS:

        value = filters.get( filter_name, { "allowed": [], "deny": []})

        if isinstance(value, list):
            # Backwards-compatible shorthand:
            #
            # FilterSchemas = ["hr"]
            allowed = []
            deny = value

        elif isinstance(value, dict):

            allowed = value.get( "allowed", [] )

            deny = value.get( "deny", [] )

            if not isinstance( allowed, list ):
                allowed = []

            if not isinstance( deny, list ):
                deny = []

        else:
            continue

        # -----------------------------------------------------
        # Only print active declarations.
        # -----------------------------------------------------

        if not allowed and not deny:
            continue

        active = True

        print( f"{BOLD}{filter_name}:{RESET}" )

        # -----------------------------------------------------
        # DENY means objects filtered OUT from metadata.
        # -----------------------------------------------------

        if deny:

            print( "    " f"{RED}filtered out{RESET}: " f"{deny}" )

        # -----------------------------------------------------
        # Allowed is still a declaration, but it does NOT mean
        # normal authorization ALLOW. It means the listed
        # metadata objects are explicitly allowed by the filter.
        # -----------------------------------------------------

        if allowed:

            print( "    " f"{GREEN}explicitly allowed{RESET}: " f"{allowed}" )

        print()

    if active:
        return

def _get_filter_value( action_data: dict[str, Any], permission: str) -> Any:
    """
    Get the value associated with a special obligation.

    GetRowFilters:
        row_filter == null -> []

    GetColumnMask:
        column_masks == {} -> []
    """

    if permission == "GetRowFilters":

        value = action_data.get( "row_filter" )

        if value is None:
            return []

        return value

    if permission == "GetColumnMask":

        value = action_data.get( "column_masks" )

        if value == {} or value is None:
            return []

        return value

    return None

def _print_filter_permission( permission: str, action_data: dict[str, Any]) -> None:
    """
    Print the actual row-filter or column-mask value.

    These permissions are special and therefore do not use the
    hierarchical ALLOW/DENY tree.
    """

    value = _get_filter_value( action_data=action_data, permission=permission)

    print( f"{BOLD}{permission}:{RESET} " f"{value}" )

    print()

def print_permission_tree( results: list[dict[str, Any]]) -> None:
    """
    Print authorization information as a hierarchical resource tree.

    Normal permissions:
        ALLOW      -> green
        DENY       -> red
        UNDEFINED  -> gray

    Special obligations:
        GetRowFilters
        GetColumnMask

    Metadata filters:
        FilterCatalogs
        FilterSchemas
        FilterTables
        FilterColumns

    Metadata filter declarations are printed as actual filtered
    objects, not as normal ALLOW/DENY permissions.
    """

    for result_index, result in enumerate( results, start=1):

        security_group = result.get( "securityGroup", "unknown")

        resource_path = result.get( "resourcePath", "root")

        resource_type = result.get( "resourceType", "unknown")

        actions = result.get( "actions", {} )

        if not isinstance( actions, dict):
            actions = {}

        print()

        print("=" * 90)

        print( f"{BOLD}Result #{result_index}{RESET}" )

        print( f"{BOLD}Security Group:{RESET} " f"{security_group}" )

        print( f"{BOLD}Resource:{RESET} " f"{resource_path}" )

        print( f"{BOLD}Resource Type:{RESET} " f"{resource_type}" )

        print("=" * 90)

        # -----------------------------------------------------
        # Resource hierarchy
        # -----------------------------------------------------

        nodes = _build_resource_nodes( resource_path )

        # -----------------------------------------------------
        # ACTUAL METADATA FILTERS
        #
        # IMPORTANT:
        # These are stored at result["filters"] and can exist
        # even when actions == {}.
        # -----------------------------------------------------

        filters = result.get( "filters", {} )

        if isinstance( filters, dict):

            _print_filter_declarations( filters )

        # -----------------------------------------------------
        # Top-level obligations.
        #
        # This makes filter-only / mask-only / row-filter-only
        # rules visible even when there are no actions.
        # -----------------------------------------------------

        top_row_filter = result.get( "row_filter" )

        if top_row_filter is not None:

            print( f"{BOLD}GetRowFilters:{RESET} " f"{top_row_filter}" )

            print()

        top_column_masks = result.get( "column_masks" )

        if top_column_masks:

            print( f"{BOLD}GetColumnMask:{RESET} " f"{top_column_masks}" )

            print()

        # -----------------------------------------------------
        # Actions
        # -----------------------------------------------------

        for action_name, action_data in actions.items():

            if not isinstance( action_data, dict):
                continue

            required_permissions = action_data.get( "requiredPermissions", [] )

            if not isinstance( required_permissions, list):
                required_permissions = []

            permission_details = action_data.get( "permissionDetails", {} )

            if not isinstance( permission_details, dict):
                permission_details = {}

            allowed = action_data.get( "allowed", False )

            decision = ( "ALLOW" if allowed else "DENY" )

            print()

            print( f"{BOLD}Action:{RESET} " f"{action_name} " f"→ {_color_status(decision)}" )

            print( f"{BOLD}Required permissions:{RESET} " f"{', '.join(required_permissions)}" )

            print()

            for permission in required_permissions:

                # -------------------------------------------------
                # GetRowFilters / GetColumnMask
                #
                # Do NOT print them as hierarchical permissions.
                # -------------------------------------------------

                if permission in OBLIGATION_PERMISSIONS:

                    _print_filter_permission( permission=permission, action_data=action_data)

                    continue

                # -------------------------------------------------
                # Normal permission
                # -------------------------------------------------

                permission_detail = ( permission_details.get( permission, {} ) )

                _print_permission_tree( permission=permission, permission_detail=permission_detail, nodes=nodes)
