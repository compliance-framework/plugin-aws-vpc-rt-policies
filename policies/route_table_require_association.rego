package compliance_framework.require_association

current := object.get(input.route_table_context, "current", {})

effectively_associated if {
	object.get(current, "effective_subnet_association_count", 0) > 0
}

gateway_associated if {
	object.get(current, "gateway_association_count", 0) > 0
}

associated if {
	effectively_associated
}

associated if {
	gateway_associated
}

violation[{}] if {
	not associated
	not data.allow_unassociated_route_tables
}

title := "Route table should be associated with at least one subnet or gateway"
description := "Route tables should have an effective subnet association or gateway association unless explicitly allowed, because unassociated route tables are unused routing configuration and can hide stale network intent"
