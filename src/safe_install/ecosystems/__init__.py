from .pip_eco import PipEcosystem
from .npm_eco import NpmEcosystem
from .cargo_eco import CargoEcosystem
from .go_eco import GoEcosystem
from .gem_eco import GemEcosystem
from .docker_eco import DockerEcosystem

ECOSYSTEMS = {
    'pip': PipEcosystem,
    'npm': NpmEcosystem,
    'cargo': CargoEcosystem,
    'go': GoEcosystem,
    'gem': GemEcosystem,
    'docker': DockerEcosystem,
}
