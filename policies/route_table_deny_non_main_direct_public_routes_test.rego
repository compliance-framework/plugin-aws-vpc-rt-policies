package compliance_framework.deny_non_main_direct_public_routes

test_violation_when_non_main_route_table_has_direct_public_default_route if {
	violation[_] with input as {
		"route_table_context": {
			"current": {
				"is_main": false,
				"has_default_route_to_internet_gateway": true
			}
		}
	} with data.allow_non_main_route_table_direct_internet_gateway_routes as false
}

test_no_violation_when_non_main_public_route_explicitly_allowed if {
	count(violation) == 0 with input as {
		"route_table_context": {
			"current": {
				"is_main": false,
				"has_default_route_to_internet_gateway": true
			}
		}
	} with data.allow_non_main_route_table_direct_internet_gateway_routes as true
}

test_no_violation_when_non_main_route_table_has_no_direct_public_default_route if {
	count(violation) == 0 with input as {
		"route_table_context": {
			"current": {
				"is_main": false,
				"has_default_route_to_internet_gateway": false
			}
		}
	} with data.allow_non_main_route_table_direct_internet_gateway_routes as false
}

test_no_violation_when_route_table_is_main if {
	count(violation) == 0 with input as {
		"route_table_context": {
			"current": {
				"is_main": true,
				"has_default_route_to_internet_gateway": true
			}
		}
	} with data.allow_non_main_route_table_direct_internet_gateway_routes as false
}
