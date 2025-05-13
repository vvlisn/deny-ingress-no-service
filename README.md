[![Stable](https://img.shields.io/badge/status-stable-brightgreen?style=for-the-badge)](https://github.com/kubewarden/community/blob/main/REPOSITORIES.md#stable)

# deny-ingress-no-service

This policy helps ensure that Kubernetes Ingress resources only reference existing Services.

## Introduction

This repository contains a Kubewarden policy written in Go. The policy validates Kubernetes Ingress resources by checking if the referenced backend Services exist in the specified namespace.

The policy is configurable via runtime settings. By default, the policy will check for Service existence and caching is enabled for host calls.

You can configure the policy using a JSON structure. When using `kwctl run --settings-json`, the settings should be nested under a `signatures` key:

```json
{
  "signatures": [
    {
      "enforce_service_exists": true,
      "disable_cache": false
    }
  ]
}
```

When deploying the policy to a Kubewarden cluster, the settings are typically provided directly without the `signatures` nesting:

```json
{
  "enforce_service_exists": true,
  "disable_cache": false
}
```

The available settings are:
- `enforce_service_exists` (boolean, default: `true`): Controls whether the policy should validate Service existence.
  - `true`: Reject Ingress if any referenced Service does not exist.
  - `false`: Skip Service existence validation, all Ingress resources will be accepted.
- `disable_cache` (boolean, default: `false`): Controls whether the policy should disable caching for Host Capabilities `get_resource` calls.
  - `true`: Caching is disabled.
  - `false`: Caching is enabled.

## Code organization

The code is organized as follows:
- `settings.go`: Handles policy settings and their validation
- `validate.go`: Contains the main validation logic that checks Service existence
- `main.go`: Registers policy entry points with the Kubewarden runtime

## Implementation details

> **DISCLAIMER:** WebAssembly is a constantly evolving area.
> This document describes the status of the Go ecosystem as of 2024.

This policy utilizes several key concepts in its implementation:

1. Service Validation
   - Uses Kubewarden's host capabilities to check if referenced Services exist
   - Handles all Service backend references in Ingress:
     - Default backend
     - Path-based rules
   - Deduplicates Service references for efficient validation

2. Configuration Management
   - Default configuration enforces Service existence checking
   - Settings can be overridden via policy configuration
   - Validates settings at policy load time

3. Technical Considerations
   - Built with TinyGo for WebAssembly compatibility
   - Uses Kubewarden's TinyGo-compatible Kubernetes types
   - Implements Kubewarden policy interface:
     - validate: Main entry point for Ingress validation
     - validate_settings: Entry point for settings validation

See the [Kubewarden Policy SDK](https://github.com/kubewarden/policy-sdk-go) documentation for more details on policy development.

## Testing

The policy includes comprehensive unit tests that verify:

1. Settings validation:
   - Default settings (enforce_service_exists = true)
   - Explicit settings override
   - Settings validation

2. Ingress validation:
   - Accept when validation is disabled
   - Accept when all Services exist
   - Reject when Service does not exist
   - Proper handling of Ingress with multiple backend Services

The unit tests can be run via:

```console
make test
```

The policy also includes end-to-end tests that verify the WebAssembly module behavior using the `kwctl` CLI. These tests validate:

1. Default behavior (enforce_service_exists = true):
   - Reject Ingress with non-existent Services
   - Accept Ingress with existing Services

2. Disabled validation (enforce_service_exists = false):
   - Accept all Ingress resources regardless of Service existence

The e2e tests are implemented in `e2e.bats` and can be run via:

```console
make e2e-tests
```

## Automation

This project has the following [GitHub Actions](https://docs.github.com/en/actions):

- `e2e-tests`: this action builds the WebAssembly policy,
installs the `bats` utility and then runs the end-to-end test.
- `unit-tests`: this action runs the Go unit tests.
- `release`: this action builds the WebAssembly policy and pushes it to a user defined OCI registry
([ghcr](https://ghcr.io) is a good candidate).
