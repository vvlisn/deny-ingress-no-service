#!/usr/bin/env bats


@test "allow existing service (validation enabled by default)" {
  run env RUST_BACKTRACE=1 kwctl run --allow-context-aware --replay-host-capabilities-interactions test_data/replay-session-with-service.yml \
        -r "test_data/ingress-with-service.json" \
        --settings-json '{"enforce_service_exists": true}' \
        "annotated-policy.wasm"

  echo "output = ${output}"
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
}

@test "reject missing service (validation enabled by default)" {
  run env RUST_BACKTRACE=1 kwctl run --allow-context-aware --replay-host-capabilities-interactions test_data/replay-session-no-service.yml \
        -r "test_data/ingress-no-service.json" \
        --settings-json '{"enforce_service_exists": true}' \
        "annotated-policy.wasm"

  echo "output = ${output}"
  [ "$status" -eq 0 ]
  [ $(echo "${output}" | grep -q "Service 'non-existent-service': host call failed"; echo $?) -eq 0 ]
}

@test "allow when validation disabled (skip service check)" {
  run env RUST_BACKTRACE=1 kwctl run --allow-context-aware --replay-host-capabilities-interactions test_data/replay-session-with-service.yml \
        -r "test_data/ingress-no-service.json" \
        --settings-json '{"enforce_service_exists": false}' \
        "annotated-policy.wasm"

  echo "output = ${output}"
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
}

@test "allow empty ingress (no service reference)" {
  run env RUST_BACKTRACE=1 kwctl run --allow-context-aware --replay-host-capabilities-interactions test_data/replay-session-with-service.yml \
        -r "test_data/ingress-empty.json" \
        "annotated-policy.wasm"

  echo "output = ${output}"
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
}
