package compliance_framework.deny_unknown_route_targets

test_violation_when_unknown_route_target_exists if {
	violation[_] with input as {
		"route_table_context": {
			"route_summaries": [{"destination": "10.0.0.0/16", "target_type": "unknown", "target_id": ""}]
		}
	}
}

test_no_violation_when_route_targets_are_known if {
	count(violation) == 0 with input as {
		"route_table_context": {
			"route_summaries": [
				{"destination": "10.0.0.0/16", "target_type": "gateway", "target_id": "local"},
				{"destination": "0.0.0.0/0", "target_type": "nat_gateway", "target_id": "nat-123"}
			]
		}
	}
}
