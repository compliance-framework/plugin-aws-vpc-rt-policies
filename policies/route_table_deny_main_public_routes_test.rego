package compliance_framework.deny_main_public_routes

test_violation_when_main_route_table_has_public_default_route if {
	violation[_] with input as {
		"route_table_context": {
			"current": {
				"is_main": true,
				"has_default_route_to_internet_gateway": true
			}
		}
	} with data.allow_main_route_table_public_routes as false
}

test_no_violation_when_main_route_table_has_no_public_default_route if {
	count(violation) == 0 with input as {
		"route_table_context": {
			"current": {
				"is_main": true,
				"has_default_route_to_internet_gateway": false
			}
		}
	} with data.allow_main_route_table_public_routes as false
}

test_no_violation_when_public_main_route_table_explicitly_allowed if {
	count(violation) == 0 with input as {
		"route_table_context": {
			"current": {
				"is_main": true,
				"has_default_route_to_internet_gateway": true
			}
		}
	} with data.allow_main_route_table_public_routes as true
}

test_no_violation_when_route_table_is_not_main if {
	count(violation) == 0 with input as {
		"route_table_context": {
			"current": {
				"is_main": false,
				"has_default_route_to_internet_gateway": true
			}
		}
	} with data.allow_main_route_table_public_routes as false
}
