"""schuberth-dfu: Linux firmware updater for SCHUBERTH/SENA headsets.

Protocol constants and device data are reverse-engineered from the SCHUBERTH
Bluetooth Device Manager v1.6 macOS/Windows apps; evidence references live in
docs/analysis/findings.md.
"""

__version__ = "0.1.0"

# All SCHUBERTH/SENA devices enumerate with this USB vendor id (Airoha
# Technology) regardless of the SoC family inside the headset.
USB_VID = 0x092B
