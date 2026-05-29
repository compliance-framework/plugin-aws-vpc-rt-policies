package compliance_framework.deny_main_public_routes

current := object.get(input.route_table_context, "current", {})

main_route_table if {
	object.get(current, "is_main", false)
}

main_route_table_has_public_default_route if {
	main_route_table
	object.get(current, "has_default_route_to_internet_gateway", false)
}

violation[{}] if {
	main_route_table_has_public_default_route
	not data.allow_main_route_table_public_routes
}

skip_reason := "Route table is not the main route table" if {
	not main_route_table
}

title := "Main route table should not route default traffic directly to an internet gateway" if {
	main_route_table
}

description := "Main route tables should not contain default IPv4 or IPv6 routes directly to an internet gateway unless explicitly allowed, because implicitly associated subnets inherit those public routes" if {
	main_route_table
}
