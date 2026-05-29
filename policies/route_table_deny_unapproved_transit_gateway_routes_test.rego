package compliance_framework.deny_unapproved_transit_gateway_routes

test_violation_when_transit_gateway_route_is_not_approved if {
	violation[_] with input as {
		"route_table_context": {
			"route_summaries": [{"target_type": "transit_gateway", "target_id": "tgw-123"}]
		}
	} with data.approved_route_table_transit_gateway_ids as []
}

test_no_violation_when_transit_gateway_route_is_approved if {
	count(violation) == 0 with input as {
		"route_table_context": {
			"route_summaries": [{"target_type": "transit_gateway", "target_id": "tgw-123"}]
		}
	} with data.approved_route_table_transit_gateway_ids as ["tgw-123"]
}

test_no_violation_when_no_transit_gateway_routes_exist if {
	count(violation) == 0 with input as {
		"route_table_context": {
			"route_summaries": [{"target_type": "nat_gateway", "target_id": "nat-123"}]
		}
	} with data.approved_route_table_transit_gateway_ids as []
}
