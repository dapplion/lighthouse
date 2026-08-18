# Runs the ethereum-package with two mock EIP-8025 proof engines alongside it.
#
# The engines are Kurtosis services rather than containers attached to the enclave network by
# hand: Kurtosis allocates enclave IPs itself, and an outside container joining the network takes
# an address it had reserved.
#
# `mock-proof-seeder` holds a validator key and so produces signed proofs; `mock-proof-engine` has
# no key and only verifies. That is the whole difference between a seeding node and a gated one:
# the beacon nodes are given the same flag, pointed at different engines.
ethereum_package = import_module("github.com/ethpandaops/ethereum-package/main.star")

MOCK_PROOF_ENGINE_IMAGE = "mock-proof-engine:local"
PORTS = {"http": PortSpec(number = 8025, transport_protocol = "TCP")}

# Validator 0 of the ethereum-package mnemonic. Consumers reject proofs from validators that are
# not active, so this has to be a real key: see scripts/tests/derive_validator_key.py.
SEEDER_SECRET_KEY = "0dce41fa73ae9f6bdfd51df4d422d75eee174553dba5fd450c4437e4ed3fc903"

def run(plan, args):
    plan.add_service(
        name = "mock-proof-engine",
        config = ServiceConfig(
            image = MOCK_PROOF_ENGINE_IMAGE,
            ports = PORTS,
            cmd = ["--listen-address", "0.0.0.0:8025", "--proof-dir", "/proofs"],
        ),
    )
    plan.add_service(
        name = "mock-proof-seeder",
        config = ServiceConfig(
            image = MOCK_PROOF_ENGINE_IMAGE,
            ports = PORTS,
            cmd = [
                "--listen-address",
                "0.0.0.0:8025",
                "--secret-key",
                SEEDER_SECRET_KEY,
                "--validator-index",
                "0",
                "--proof-types",
                "0,1",
                "--proof-dir",
                "/proofs",
            ],
        ),
    )
    return ethereum_package.run(plan, args)
