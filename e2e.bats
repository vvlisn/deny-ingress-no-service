#!/usr/bin/env bats

#git clone https://github.com/bats-core/bats-support.git test_helper/bats-support
#git clone https://github.com/bats-core/bats-assert.git test_helper/bats-assert

load 'test_helper/bats-support/load'
load 'test_helper/bats-assert/load'

@test "allow existing service (validation enabled by default)" {
  run env RUST_BACKTRACE=1 kwctl run --allow-context-aware --replay-host-capabilities-interactions test_data/replay-session-with-service.yml \
        -r "test_data/ingress-with-service.json" \
        --settings-json '{"enforce_service_exists": true}' \
        "annotated-policy.wasm"

  echo "output = ${output}"
  assert_success
  assert_output --partial '"allowed":true'
}

@test "reject missing service (validation enabled by default)" {
  run env RUST_BACKTRACE=1 kwctl run --allow-context-aware --replay-host-capabilities-interactions test_data/replay-session-no-service.yml \
        -r "test_data/ingress-no-service.json" \
        --settings-json '{"enforce_service_exists": true}' \
        "annotated-policy.wasm"

  echo "output = ${output}"
  assert_success
  assert_output --partial '"allowed":false'
  assert_output --partial "Service 'non-existent-service': host call failed"
}

@test "allow when validation disabled (skip service check)" {
  run env RUST_BACKTRACE=1 kwctl run --allow-context-aware --replay-host-capabilities-interactions test_data/replay-session-with-service.yml \
        -r "test_data/ingress-no-service.json" \
        --settings-json '{"enforce_service_exists": false}' \
        "annotated-policy.wasm"

  echo "output = ${output}"
  assert_success
  assert_output --partial '"allowed":true'
}

@test "allow empty ingress (no service reference)" {
  run env RUST_BACKTRACE=1 kwctl run --allow-context-aware --replay-host-capabilities-interactions test_data/replay-session-with-service.yml.yml \
        -r "test_data/ingress-empty.json" \
        "annotated-policy.wasm"

  echo "output = ${output}"
  assert_success
  assert_output --partial '"allowed":true'
}
