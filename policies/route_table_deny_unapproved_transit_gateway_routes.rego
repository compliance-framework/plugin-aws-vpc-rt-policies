package compliance_framework.deny_unapproved_transit_gateway_routes

transit_gateway_route[route] if {
	route := object.get(input.route_table_context, "route_summaries", [])[_]
	object.get(route, "target_type", "") == "transit_gateway"
}

approved_transit_gateway_route(route) if {
	approved_id := data.approved_route_table_transit_gateway_ids[_]
	object.get(route, "target_id", "") == approved_id
}

unapproved_transit_gateway_route[route] if {
	route := object.get(input.route_table_context, "route_summaries", [])[_]
	object.get(route, "target_type", "") == "transit_gateway"
	not approved_transit_gateway_route(route)
}

violation[{}] if {
	count(unapproved_transit_gateway_route) > 0
}

skip_reason := "Route table has no transit gateway routes" if {
	count(transit_gateway_route) == 0
}

title := "Route table transit gateway routes should target approved transit gateways" if {
	count(transit_gateway_route) > 0
}

description := sprintf("Route tables that provide cross-network access through transit gateways should only target approved transit gateway IDs: %s", [concat(", ", data.approved_route_table_transit_gateway_ids)]) if {
	count(transit_gateway_route) > 0
}
