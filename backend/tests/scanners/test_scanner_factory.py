
from app.core.enums import ScannerType
from app.scanners.adapters.nmap_adapter import NmapAdapter
from app.scanners.scanner_factory import ScannerFactory
from app.scanners.scanner_registry import ScannerRegistry


def test_scanner_factory_default_registry():
    """Verify factory initializes its Nmap default."""
    factory = ScannerFactory()

    nmap_adapter = factory.get_adapter(ScannerType.NMAP)
    assert isinstance(nmap_adapter, NmapAdapter)


def test_scanner_factory_custom_registry():
    """Verify factory accepts and uses a custom registry."""
    registry = ScannerRegistry()
    mock_adapter = NmapAdapter()
    registry.register(ScannerType.NMAP, mock_adapter)

    factory = ScannerFactory(registry=registry)
    assert factory.get_adapter(ScannerType.NMAP) is mock_adapter
