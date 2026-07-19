import json

from openvino import Core


core = Core()
devices: dict[str, object] = {"available_devices": core.available_devices}
for device in core.available_devices:
    if device.startswith("GPU"):
        devices[device] = {
            "name": str(core.get_property(device, "FULL_DEVICE_NAME")),
            "type": str(core.get_property(device, "DEVICE_TYPE")),
            "architecture": str(core.get_property(device, "DEVICE_ARCHITECTURE")),
            "capabilities": [str(value) for value in core.get_property(device, "OPTIMIZATION_CAPABILITIES")],
        }
print(json.dumps(devices, ensure_ascii=False, indent=2))
