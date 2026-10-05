# Runs the ethereum-package with two EIP-8025 proof relays alongside it.
#
# The relays are Kurtosis services rather than containers attached to the enclave network by
# hand: Kurtosis allocates enclave IPs itself, and an outside container joining the network takes
# an address it had reserved.
#
# They start after the package, because a relay reads the spec from its beacon node before it can
# sign anything.
#
# `proof-seeder` holds a validator key, so it signs proofs and submits them to its node, which
# gossips them. `proof-verifier` has no key and only answers verification, which is what a node
# that consumes proofs without seeding them needs. That is the whole difference between a seeding
# node and a gated one: the beacon nodes are given the same flag, pointed at different relays.
ethereum_package = import_module("github.com/ethpandaops/ethereum-package/main.star")

PROOF_SEEDER_IMAGE = "proof-seeder:local"
PORTS = {"http": PortSpec(number = 8025, transport_protocol = "TCP")}

# Validator 0 of the ethereum-package mnemonic. Consumers reject proofs from validators that are
# not in the registry, so this has to be a real key: see scripts/tests/derive_validator_key.py.
SEEDER_SECRET_KEY = "0dce41fa73ae9f6bdfd51df4d422d75eee174553dba5fd450c4437e4ed3fc903"

def run(plan, args):
    output = ethereum_package.run(plan, args)

    plan.add_service(
        name = "proof-verifier",
        config = ServiceConfig(
            image = PROOF_SEEDER_IMAGE,
            ports = PORTS,
            cmd = [
                "--listen-address",
                "0.0.0.0:8025",
                "--beacon-node",
                "http://cl-3-lighthouse-geth:4000",
                "--source",
                "fixture",
            ],
        ),
    )
    plan.add_service(
        name = "proof-seeder",
        config = ServiceConfig(
            image = PROOF_SEEDER_IMAGE,
            ports = PORTS,
            cmd = [
                "--listen-address",
                "0.0.0.0:8025",
                "--beacon-node",
                "http://cl-5-lighthouse-geth:4000",
                "--secret-key",
                SEEDER_SECRET_KEY,
                "--validator-index",
                "0",
                "--source",
                "fixture",
            ],
        ),
    )
    return output
