"""Shared entity base."""

from __future__ import annotations

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, MANUFACTURER
from .coordinator import NavienRecircCoordinator


class NavienRecircEntity(CoordinatorEntity[NavienRecircCoordinator]):
    """An entity on the heater's device."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: NavienRecircCoordinator, key: str) -> None:
        """Initialize."""
        super().__init__(coordinator)
        self._attr_translation_key = key
        self._attr_unique_id = f"{coordinator.mac}_{key}"
        info = coordinator.device_info_raw
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, coordinator.mac)},
            manufacturer=MANUFACTURER,
            model=str(info.get("deviceName") or "NaviLink heater"),
            name=f"{coordinator.device_name} Recirc Boost",
        )

    @property
    def available(self) -> bool:
        """Available while connected to NaviLink."""
        return self.coordinator.client.connected
