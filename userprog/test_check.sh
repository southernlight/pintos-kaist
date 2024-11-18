#!/bin/bash

# make check 실행하고 pass와 FAIL 라인만 추출
test_output=$(make check | grep -E "^(pass|FAIL)")

# pass와 FAIL 개수 세기
pass_count=$(echo "$test_output" | grep -c "pass")
fail_count=$(echo "$test_output" | grep -c "FAIL")

# 전체 테스트 개수 출력
total_count=$((pass_count + fail_count))

# 결과 출력
echo "$test_output"
echo "$pass_count/$total_count"

