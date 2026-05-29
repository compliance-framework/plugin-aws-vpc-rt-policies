package compliance_framework.deny_blackhole_routes

blackhole_route[route] if {
	route := object.get(input.route_table_context, "blackhole_routes", [])[_]
}

violation[{}] if {
	count(blackhole_route) > 0
}

title := "Route table should not contain blackhole routes"
description := "Route table routes should not be in blackhole state because affected traffic cannot reach the configured route target"
