# To download/extract nightly tests, run:
# CONSENSUS_SPECS_TEST_VERSION=nightly make
CONSENSUS_SPECS_TEST_VERSION ?= v1.7.0-alpha.11
REPO_NAME := consensus-spec-tests
OUTPUT_DIR := ./$(REPO_NAME)

BLS_TEST_REPO_NAME := bls12-381-tests
BLS_TEST_VERSION := v0.1.1
BLS_TEST = bls_tests_yaml
BLS_OUTPUT_DIR := $(OUTPUT_DIR)/$(BLS_TEST_REPO_NAME)
BLS_BASE_URL := https://github.com/ethereum/$(BLS_TEST_REPO_NAME)/releases/download/$(BLS_TEST_VERSION)

.PHONY: all clean comptests

all: clean $(OUTPUT_DIR) $(BLS_OUTPUT_DIR) comptests

# Fork choice compliance tests. Releases of consensus-specs since v1.7.0-alpha.9 include a
# `comptests.tar.gz` asset; `nightly` versions are not supported here.
comptests:
	mkdir -p $(OUTPUT_DIR)
	curl --progress-bar --location --remote-name --show-error --retry 3 --retry-all-errors --fail \
		https://github.com/ethereum/consensus-specs/releases/download/$(CONSENSUS_SPECS_TEST_VERSION)/comptests.tar.gz
	# The tarball also packages the generator's python sources; only extract the vectors.
	tar -xzf comptests.tar.gz -C $(OUTPUT_DIR) tests/minimal
	rm -f comptests.tar.gz

clean:
	rm -rf *.tar.gz $(OUTPUT_DIR) $(BLS_OUTPUT_DIR)

$(OUTPUT_DIR):
	mkdir -p $(OUTPUT_DIR)
	./download_test_vectors.sh $(CONSENSUS_SPECS_TEST_VERSION)
	for test_tarball in *.tar.gz; do \
		tar -xzf $$test_tarball -C $(OUTPUT_DIR); \
		rm -f $$test_tarball; \
	done

$(BLS_OUTPUT_DIR):
	mkdir -p $(BLS_OUTPUT_DIR)
	curl --progress-bar --location --remote-name --show-error --retry 3 --retry-all-errors --fail \
		$(BLS_BASE_URL)/$(BLS_TEST).tar.gz
	tar -xzf *.tar.gz -C $(BLS_OUTPUT_DIR)
	rm -f *.tar.gz
