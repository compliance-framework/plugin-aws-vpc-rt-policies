package compliance_framework.deny_unapproved_vpc_peering_routes

test_violation_when_vpc_peering_route_is_not_approved if {
	violation[_] with input as {
		"route_table_context": {
			"route_summaries": [{"target_type": "vpc_peering_connection", "target_id": "pcx-123"}]
		}
	} with data.approved_route_table_vpc_peering_connection_ids as []
}

test_no_violation_when_vpc_peering_route_is_approved if {
	count(violation) == 0 with input as {
		"route_table_context": {
			"route_summaries": [{"target_type": "vpc_peering_connection", "target_id": "pcx-123"}]
		}
	} with data.approved_route_table_vpc_peering_connection_ids as ["pcx-123"]
}

test_no_violation_when_no_vpc_peering_routes_exist if {
	count(violation) == 0 with input as {
		"route_table_context": {
			"route_summaries": [{"target_type": "nat_gateway", "target_id": "nat-123"}]
		}
	} with data.approved_route_table_vpc_peering_connection_ids as []
}
