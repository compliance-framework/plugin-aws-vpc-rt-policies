package compliance_framework.deny_unapproved_vpc_peering_routes

vpc_peering_route[route] if {
	route := object.get(input.route_table_context, "route_summaries", [])[_]
	object.get(route, "target_type", "") == "vpc_peering_connection"
}

approved_vpc_peering_route(route) if {
	approved_id := data.approved_route_table_vpc_peering_connection_ids[_]
	object.get(route, "target_id", "") == approved_id
}

unapproved_vpc_peering_route[route] if {
	route := object.get(input.route_table_context, "route_summaries", [])[_]
	object.get(route, "target_type", "") == "vpc_peering_connection"
	not approved_vpc_peering_route(route)
}

violation[{}] if {
	count(unapproved_vpc_peering_route) > 0
}

skip_reason := "Route table has no VPC peering routes" if {
	count(vpc_peering_route) == 0
}

title := "Route table VPC peering routes should target approved peering connections" if {
	count(vpc_peering_route) > 0
}

description := sprintf("Route tables that provide cross-VPC access through peering should only target approved VPC peering connection IDs: %s", [concat(", ", data.approved_route_table_vpc_peering_connection_ids)]) if {
	count(vpc_peering_route) > 0
}
