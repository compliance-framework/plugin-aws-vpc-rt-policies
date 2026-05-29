# AWS VPC route table policies

Standalone OPA/Rego policy bundle for route table evidence emitted by the `plugin-aws-vpc` collector.

## Input schema

Each policy evaluates one route table at a time using:

- `input.route_table`
- `input.route_table_context`

Current route-table context includes the parent VPC, subnets in the VPC, explicit and implicit subnet associations, effective subnet associations, internet gateways, VPC endpoints, transit gateway attachments, route summaries, and blackhole routes.

## Current coverage

This bundle currently checks route-table posture such as:

- required route-table tags
- route-table association presence
- blackhole routes
- unknown route targets
- main route table public default routes
- non-main route table direct public routes
- default routes to transit gateways
- approved transit gateway route targets
- approved VPC peering route targets

## Policy data

Default baselines live in `policies/data.json` and can be overridden by agent-supplied policy data. Current settings cover required tags, whether unassociated route tables are allowed, whether certain default-route patterns are allowed, and approved transit gateway or VPC peering targets.

## Testing

Run local checks with:

```shell
opa check policies
opa test policies
```

Or use the Makefile wrappers:

```shell
make validate
make test
```

## Bundling

Build the distributable bundle with:

```shell
make build
```

This writes `dist/bundle.tar.gz`.
