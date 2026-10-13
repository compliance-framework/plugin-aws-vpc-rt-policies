package compliance_framework.deny_main_public_routes

test_violation_when_main_route_table_has_public_default_route if {
	violation[_] with input as {"route_table_context": {
		"current": {"is_main": true},
		"route_summaries": [{"destination": "0.0.0.0/0", "target_type": "gateway", "target_id": "igw-123", "state": "active"}],
	}}
		with data.allow_main_route_table_public_routes as false # regal ignore:unresolved-reference
}

test_no_violation_when_main_route_table_has_no_public_default_route if {
	count(violation) == 0 with input as {"route_table_context": {"current": {"is_main": true}}}
		with data.allow_main_route_table_public_routes as false # regal ignore:unresolved-reference
}

test_no_violation_when_public_main_route_table_explicitly_allowed if {
	count(violation) == 0 with input as {"route_table_context": {
		"current": {"is_main": true},
		"route_summaries": [{"destination": "0.0.0.0/0", "target_type": "gateway", "target_id": "igw-123", "state": "active"}],
	}}
		with data.allow_main_route_table_public_routes as true # regal ignore:unresolved-reference
}

test_no_violation_when_main_route_table_has_blackhole_public_default_route if {
	count(violation) == 0 with input as {"route_table_context": {
		"current": {"is_main": true},
		"route_summaries": [{"destination": "0.0.0.0/0", "target_type": "gateway", "target_id": "igw-123", "state": "blackhole"}],
	}}
		with data.allow_main_route_table_public_routes as false # regal ignore:unresolved-reference
}

test_no_violation_when_route_table_is_not_main if {
	count(violation) == 0 with input as {"route_table_context": {
		"current": {"is_main": false},
		"route_summaries": [{"destination": "0.0.0.0/0", "target_type": "gateway", "target_id": "igw-123", "state": "active"}],
	}}
		with data.allow_main_route_table_public_routes as false # regal ignore:unresolved-reference
}
