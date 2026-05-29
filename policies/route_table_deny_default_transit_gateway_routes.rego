package compliance_framework.deny_default_transit_gateway_routes

risk_templates := [{
	"name": "Route table has default route to transit gateway",
	"title": "Broad Cross-Network Access Through Transit Gateway Default Route",
	"statement": "A default route to a transit gateway can send all unmatched subnet traffic into a wider routed network. If not explicitly approved, this can create broad cross-network access paths that place resources into an unintended control sphere.",
	"likelihood_hint": "medium",
	"impact_hint": "high",
	"violation_ids": ["route_table_default_transit_gateway_route"],
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
		"title": "Constrain transit gateway default routing",
		"description": "Avoid routing default traffic to transit gateways unless the route is part of an approved network architecture and the destination network controls are understood.",
		"tasks": [
			{"title": "Review default routes that target transit gateways"},
			{"title": "Replace broad default TGW routes with specific destination CIDR routes where possible"},
			{"title": "Confirm the transit gateway and downstream route tables are approved for the associated subnet traffic"},
			{"title": "Validate segmentation controls in connected VPCs or on-premises networks"},
			{"title": "Document any exception that permits default routing through a transit gateway"}
		]
	}
}]

current := object.get(input.route_table_context, "current", {})

has_default_transit_gateway_route if {
	object.get(current, "has_default_route_to_transit_gateway", false)
}

violation[{"id": "route_table_default_transit_gateway_route"}] if {
	has_default_transit_gateway_route
	not data.allow_route_table_default_transit_gateway_routes
}

skip_reason := "Route table has no default route to a transit gateway" if {
	not has_default_transit_gateway_route
}

title := "Route table should not route default traffic to a transit gateway" if {
	has_default_transit_gateway_route
}

description := "Route tables should not send default IPv4 or IPv6 traffic to a transit gateway unless explicitly allowed, because default TGW routes can create broad cross-network access paths"
