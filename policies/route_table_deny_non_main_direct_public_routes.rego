package compliance_framework.deny_non_main_direct_public_routes

risk_templates := [{
	"name": "Route table has direct public internet default route",
	"title": "Direct Public Network Exposure Through Route Table",
	"statement": "A route table with a default route directly to an internet gateway gives associated subnets direct public internet routing. If this route is not explicitly intended and controlled, workloads using the route table may be exposed outside their expected network boundary.",
	"likelihood_hint": "medium",
	"impact_hint": "high",
	"violation_ids": ["route_table_direct_public_route"],
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
		"title": "Restrict direct public internet routing",
		"description": "Remove direct internet-gateway default routes from route tables that are not approved for public subnet routing.",
		"tasks": [
			{"title": "Confirm whether the route table is intended to serve public subnets"},
			{"title": "Remove default routes to internet gateways where direct public routing is not required"},
			{"title": "Use NAT gateways, VPC endpoints, or private connectivity for outbound-only access patterns"},
			{"title": "Explicitly approve route tables that must retain direct public internet routes"},
			{"title": "Validate associated subnets and workloads for public exposure after route changes"}
		]
	}
}]

current := object.get(input.route_table_context, "current", {})

non_main_route_table if {
	not object.get(current, "is_main", false)
}

has_direct_public_internet_route if {
	object.get(current, "has_default_route_to_internet_gateway", false)
}

violation[{"id": "route_table_direct_public_route"}] if {
	non_main_route_table
	has_direct_public_internet_route
	not data.allow_non_main_route_table_direct_internet_gateway_routes
}

skip_reason := "Route table is the main route table" if {
	not non_main_route_table
}

title := "Route table direct public internet routes should be explicitly allowed" if {
	non_main_route_table
}

description := "Non-main route tables should not route default IPv4 or IPv6 traffic directly to an internet gateway unless explicitly allowed by policy data; NAT gateways, egress-only IPv6 gateways, gateway endpoints, and approved private connectivity paths are evaluated separately"
