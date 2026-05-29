package compliance_framework.deny_unknown_route_targets

unknown_route_target[route] if {
	route := object.get(input.route_table_context, "route_summaries", [])[_]
	object.get(route, "target_type", "") == "unknown"
}

violation[{}] if {
	count(unknown_route_target) > 0
}

skip_reason := "Route table has no unknown route targets" if {
	count(unknown_route_target) == 0
}

title := "Route table routes should have known target types" if {
	count(unknown_route_target) > 0
}

description := "Route table routes should resolve to known target types so route posture can be evaluated reliably"
