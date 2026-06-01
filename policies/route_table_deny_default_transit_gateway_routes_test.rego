package compliance_framework.deny_default_transit_gateway_routes

test_violation_when_default_route_targets_transit_gateway if {
	violation[_] with input as {
		"route_table_context": {
			"route_summaries": [
				{"destination": "0.0.0.0/0", "target_type": "transit_gateway", "target_id": "tgw-123", "state": "active"}
			]
		}
	} with data.allow_route_table_default_transit_gateway_routes as false
}

test_no_violation_when_default_transit_gateway_route_is_allowed if {
	count(violation) == 0 with input as {
		"route_table_context": {
			"route_summaries": [
				{"destination": "0.0.0.0/0", "target_type": "transit_gateway", "target_id": "tgw-123", "state": "active"}
			]
		}
	} with data.allow_route_table_default_transit_gateway_routes as true
}

test_no_violation_when_no_default_transit_gateway_route_exists if {
	count(violation) == 0 with input as {
		"route_table_context": {
			"route_summaries": [
				{"destination": "10.0.0.0/16", "target_type": "nat_gateway", "target_id": "nat-123", "state": "active"}
			]
		}
	} with data.allow_route_table_default_transit_gateway_routes as false
}

test_no_violation_when_default_transit_gateway_route_is_blackhole if {
	count(violation) == 0 with input as {
		"route_table_context": {
			"route_summaries": [
				{"destination": "0.0.0.0/0", "target_type": "transit_gateway", "target_id": "tgw-123", "state": "blackhole"}
			]
		}
	} with data.allow_route_table_default_transit_gateway_routes as false
}
