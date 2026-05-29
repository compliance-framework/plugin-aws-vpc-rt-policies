package compliance_framework.deny_unapproved_vpc_peering_routes

risk_templates := [{
	"name": "Route table targets unapproved VPC peering connection",
	"title": "Unapproved Cross-VPC Route Through Peering",
	"statement": "Routes to unapproved VPC peering connections can connect associated subnets to peer VPCs that have not been accepted as valid access or transfer paths. This can expose resources to unintended network domains outside the expected control boundary.",
	"likelihood_hint": "medium",
	"impact_hint": "high",
	"violation_ids": ["route_table_unapproved_vpc_peering_route"],
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
		"title": "Restrict VPC peering route targets",
		"description": "Limit route-table peering targets to approved VPC peering connections and remove or approve unexpected cross-VPC routes.",
		"tasks": [
			{"title": "Identify route entries targeting unapproved VPC peering connection IDs"},
			{"title": "Confirm whether each peering route is required and approved"},
			{"title": "Remove routes to unapproved peering connections"},
			{"title": "Add approved peering connection IDs to policy data only after architectural review"},
			{"title": "Validate peer VPC security groups, NACLs, and route tables after changes"}
		]
	}
}]

vpc_peering_route[route] if {
	route := object.get(input.route_table_context, "route_summaries", [])[_]
	object.get(route, "target_type", "") == "vpc_peering_connection"
}

approved_vpc_peering_route(route) if {
	approved_id := data.approved_route_table_vpc_peering_connection_ids[_]
	object.get(route, "target_id", "") == approved_id
}

unapproved_vpc_peering_route[route] if {
	route := object.get(input.route_table_context, "route_summaries", [])[_]
	object.get(route, "target_type", "") == "vpc_peering_connection"
	not approved_vpc_peering_route(route)
}

violation[{"id": "route_table_unapproved_vpc_peering_route"}] if {
	count(unapproved_vpc_peering_route) > 0
}

skip_reason := "Route table has no VPC peering routes" if {
	count(vpc_peering_route) == 0
}

title := "Route table VPC peering routes should target approved peering connections" if {
	count(vpc_peering_route) > 0
}

description := sprintf("Route tables that provide cross-VPC access through peering should only target approved VPC peering connection IDs: %s", [concat(", ", data.approved_route_table_vpc_peering_connection_ids)]) if {
	count(vpc_peering_route) > 0
}
