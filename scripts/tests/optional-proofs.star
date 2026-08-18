# Runs the ethereum-package with a mock EIP-8025 proof engine alongside it.
#
# The engine is a Kurtosis service rather than a container attached to the enclave network by
# hand: Kurtosis allocates enclave IPs itself, and an outside container joining the network takes
# an address it had reserved.
ethereum_package = import_module("github.com/ethpandaops/ethereum-package/main.star")

def run(plan, args):
    plan.add_service(
        name = "mock-proof-engine",
        config = ServiceConfig(
            image = "mock-proof-engine:local",
            ports = {"http": PortSpec(number = 8025, transport_protocol = "TCP")},
            cmd = ["--listen-address", "0.0.0.0:8025"],
        ),
    )
    return ethereum_package.run(plan, args)
