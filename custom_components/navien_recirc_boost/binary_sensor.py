"""Boost running and NaviLink connection sensors."""

from __future__ import annotations

from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .coordinator import NavienRecircConfigEntry
from .entity import NavienRecircEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: NavienRecircConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Add the binary sensors."""
    coordinator = entry.runtime_data
    async_add_entities(
        [BoostRunningSensor(coordinator, "boost_running"), ConnectedSensor(coordinator, "connected")]
    )


class BoostRunningSensor(NavienRecircEntity, BinarySensorEntity):
    """On while a boost is running."""

    _attr_device_class = BinarySensorDeviceClass.RUNNING

    @property
    def available(self) -> bool:
        """Always available so automations can see it."""
        return True

    @property
    def is_on(self) -> bool:
        """Return True during a boost."""
        return self.coordinator.boost.running

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Phase, stop temperature and last result."""
        return self.coordinator.boost.attributes


class ConnectedSensor(NavienRecircEntity, BinarySensorEntity):
    """On while connected to the NaviLink cloud."""

    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def available(self) -> bool:
        """Always available (it reports the connection itself)."""
        return True

    @property
    def is_on(self) -> bool:
        """Return True when connected."""
        return self.coordinator.client.connected
