# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Authors of KubeArmor
#
# Builds and signs kubearmor-es-helper, the native Apple Endpoint Security client
# for KubeArmor's macOS host enforcer. macOS only.

BIN        := kubearmor-es-helper
SRC        := esclient.c
ENTITLE    := es.entitlements
MIN_MACOS  := 13.0   # inverted target-path muting (es_invert_muting) is 13.0+

# Signing identity. Default: ad-hoc (works only on a SIP+AMFI-disabled dev box).
# Release: SIGN_ID="Developer ID Application: Your Org (TEAMID)"
SIGN_ID    ?= -

CFLAGS     := -mmacosx-version-min=$(MIN_MACOS) -O2 -Wall -Wextra -Wno-unused-parameter
LDLIBS     := -lEndpointSecurity -lbsm

.PHONY: all clean verify

all: $(BIN)

$(BIN): $(SRC) $(ENTITLE)
	clang $(CFLAGS) -o $@ $(SRC) $(LDLIBS)
	codesign --force --options runtime --timestamp=none \
		--entitlements $(ENTITLE) --sign "$(SIGN_ID)" $@
	@echo "signed $(BIN) with identity: $(SIGN_ID)"

verify: $(BIN)
	codesign -dvvv --entitlements :- $(BIN)

clean:
	rm -f $(BIN)
