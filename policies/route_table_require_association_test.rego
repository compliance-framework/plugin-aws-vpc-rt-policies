package compliance_framework.require_association

test_violation_when_route_table_has_no_subnet_or_gateway_association if {
	violation[_] with input as {
		"route_table_context": {
			"current": {
				"effective_subnet_association_count": 0,
				"gateway_association_count": 0
			}
		}
	} with data.allow_unassociated_route_tables as false
}

test_no_violation_when_route_table_has_effective_subnet_association if {
	count(violation) == 0 with input as {
		"route_table_context": {
			"current": {
				"effective_subnet_association_count": 1,
				"gateway_association_count": 0
			}
		}
	} with data.allow_unassociated_route_tables as false
}

test_no_violation_when_route_table_has_gateway_association if {
	count(violation) == 0 with input as {
		"route_table_context": {
			"current": {
				"effective_subnet_association_count": 0,
				"gateway_association_count": 1
			}
		}
	} with data.allow_unassociated_route_tables as false
}

test_no_violation_when_unassociated_route_tables_are_allowed if {
	count(violation) == 0 with input as {
		"route_table_context": {
			"current": {
				"effective_subnet_association_count": 0,
				"gateway_association_count": 0
			}
		}
	} with data.allow_unassociated_route_tables as true
}
