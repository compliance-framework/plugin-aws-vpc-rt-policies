package compliance_framework.require_tags

test_violation_when_required_tags_missing if {
	violation[_] with input as {
		"route_table": {"Tags": [{"Key": "Owner", "Value": "platform"}]}
	} with data.required_route_table_tags as ["Owner", "Environment"]
}

test_no_violation_when_required_tags_present if {
	count(violation) == 0 with input as {
		"route_table": {"Tags": [
			{"Key": "Owner", "Value": "platform"},
			{"Key": "Environment", "Value": "prod"}
		]}
	} with data.required_route_table_tags as ["Owner", "Environment"]
}
