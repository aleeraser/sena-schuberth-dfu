"""Back-compat shim: simulators now live in the package."""
from schuberth_dfu.sim import FakeAiroha, FakeSc2

__all__ = ["FakeAiroha", "FakeSc2"]
