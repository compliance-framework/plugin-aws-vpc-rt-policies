package compliance_framework.deny_default_transit_gateway_routes

current := object.get(input.route_table_context, "current", {})

has_default_transit_gateway_route if {
	object.get(current, "has_default_route_to_transit_gateway", false)
}

violation[{}] if {
	has_default_transit_gateway_route
	not data.allow_route_table_default_transit_gateway_routes
}

skip_reason := "Route table has no default route to a transit gateway" if {
	not has_default_transit_gateway_route
}

title := "Route table should not route default traffic to a transit gateway" if {
	has_default_transit_gateway_route
}

description := "Route tables should not send default IPv4 or IPv6 traffic to a transit gateway unless explicitly allowed, because default TGW routes can create broad cross-network access paths"
