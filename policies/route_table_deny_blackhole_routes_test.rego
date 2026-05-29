package compliance_framework.deny_blackhole_routes

test_violation_when_blackhole_route_exists if {
	violation[_] with input as {
		"route_table_context": {
			"blackhole_routes": [{"destination": "10.20.0.0/16", "target_type": "transit_gateway", "state": "blackhole"}]
		}
	}
}

test_no_violation_when_no_blackhole_routes_exist if {
	count(violation) == 0 with input as {
		"route_table_context": {"blackhole_routes": []}
	}
}
