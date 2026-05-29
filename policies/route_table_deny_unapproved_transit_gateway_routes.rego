package compliance_framework.deny_unapproved_transit_gateway_routes

risk_templates := [{
	"name": "Route table targets unapproved transit gateway",
	"title": "Unapproved Cross-Network Route Through Transit Gateway",
	"statement": "Routes to unapproved transit gateways can connect associated subnets to network domains that have not been accepted as valid transfer or access paths. This can expose resources to unintended actors or routes outside the expected control boundary.",
	"likelihood_hint": "medium",
	"impact_hint": "high",
	"violation_ids": ["route_table_unapproved_transit_gateway_route"],
	"threat_refs": [
		{
			"system": "https://cwe.mitre.org",
			"external_id": "CWE-668",
			"title": "Exposure of Resource to Wrong Sphere",
			"url": "https://cwe.mitre.org/data/definitions/668.html"
		},
		{
			"system": "https://cwe.mitre.org",
			"external_id": "CWE-284",
			"title": "Improper Access Control",
			"url": "https://cwe.mitre.org/data/definitions/284.html"
		}
	],
	"remediation": {
		"title": "Restrict transit gateway route targets",
		"description": "Limit route-table transit gateway targets to approved transit gateways and remove or approve unexpected cross-network routes.",
		"tasks": [
			{"title": "Identify route entries targeting unapproved transit gateway IDs"},
			{"title": "Confirm whether each transit gateway route is required and approved"},
			{"title": "Remove routes to unapproved transit gateways"},
			{"title": "Add approved transit gateway IDs to policy data only after architectural review"},
			{"title": "Validate connected network segmentation and route propagation after changes"}
		]
	}
}]

transit_gateway_route[route] if {
	route := object.get(input.route_table_context, "route_summaries", [])[_]
	object.get(route, "target_type", "") == "transit_gateway"
}

approved_transit_gateway_route(route) if {
	approved_id := data.approved_route_table_transit_gateway_ids[_]
	object.get(route, "target_id", "") == approved_id
}

unapproved_transit_gateway_route[route] if {
	route := object.get(input.route_table_context, "route_summaries", [])[_]
	object.get(route, "target_type", "") == "transit_gateway"
	not approved_transit_gateway_route(route)
}

violation[{"id": "route_table_unapproved_transit_gateway_route"}] if {
	count(unapproved_transit_gateway_route) > 0
}

skip_reason := "Route table has no transit gateway routes" if {
	count(transit_gateway_route) == 0
}

title := "Route table transit gateway routes should target approved transit gateways" if {
	count(transit_gateway_route) > 0
}

description := sprintf("Route tables that provide cross-network access through transit gateways should only target approved transit gateway IDs: %s", [concat(", ", data.approved_route_table_transit_gateway_ids)]) if {
	count(transit_gateway_route) > 0
}
