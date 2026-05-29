package compliance_framework.deny_main_public_routes

risk_templates := [{
	"name": "Main route table has direct public internet default route",
	"title": "Implicit Public Network Exposure Through Main Route Table",
	"statement": "When a VPC main route table sends default IPv4 or IPv6 traffic directly to an internet gateway, any subnet without an explicit route-table association can inherit public internet routing. This can expose workloads to an unintended network control sphere and increase the chance of unauthorized access paths if other boundary controls are incomplete or misconfigured.",
	"likelihood_hint": "medium",
	"impact_hint": "high",
	"violation_ids": ["route_table_main_public_route"],
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
		"title": "Remove implicit public routing from the main route table",
		"description": "Keep the VPC main route table minimal and avoid direct internet-gateway default routes unless this is an explicitly approved design.",
		"tasks": [
			{"title": "Review the main route table for default routes to internet gateways"},
			{"title": "Move public default routes to explicitly associated public-subnet route tables"},
			{"title": "Explicitly associate subnets with the intended route tables to avoid inheriting main-table routes"},
			{"title": "Validate security groups and NACLs for any subnet that remains internet-routed"},
			{"title": "Document and approve any exception that keeps public routing on the main route table"}
		]
	}
}]

current := object.get(input.route_table_context, "current", {})

main_route_table if {
	object.get(current, "is_main", false)
}

main_route_table_has_public_default_route if {
	main_route_table
	object.get(current, "has_default_route_to_internet_gateway", false)
}

violation[{"id": "route_table_main_public_route"}] if {
	main_route_table_has_public_default_route
	not data.allow_main_route_table_public_routes
}

skip_reason := "Route table is not the main route table" if {
	not main_route_table
}

title := "Main route table should not route default traffic directly to an internet gateway" if {
	main_route_table
}

description := "Main route tables should not contain default IPv4 or IPv6 routes directly to an internet gateway unless explicitly allowed, because implicitly associated subnets inherit those public routes" if {
	main_route_table
}
