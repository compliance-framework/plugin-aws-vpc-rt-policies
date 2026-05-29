package compliance_framework.deny_non_main_direct_public_routes

current := object.get(input.route_table_context, "current", {})

non_main_route_table if {
	not object.get(current, "is_main", false)
}

has_direct_public_internet_route if {
	object.get(current, "has_default_route_to_internet_gateway", false)
}

violation[{}] if {
	non_main_route_table
	has_direct_public_internet_route
	not data.allow_non_main_route_table_direct_internet_gateway_routes
}

skip_reason := "Route table is the main route table" if {
	not non_main_route_table
}

title := "Route table direct public internet routes should be explicitly allowed" if {
	non_main_route_table
}

description := "Non-main route tables should not route default IPv4 or IPv6 traffic directly to an internet gateway unless explicitly allowed by policy data; NAT gateways, egress-only IPv6 gateways, gateway endpoints, and approved private connectivity paths are evaluated separately"
