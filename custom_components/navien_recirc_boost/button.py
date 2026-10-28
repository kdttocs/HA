"""Boost and Stop boost buttons."""

from __future__ import annotations

from homeassistant.components.button import ButtonEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .coordinator import NavienRecircConfigEntry
from .entity import NavienRecircEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: NavienRecircConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Add the buttons."""
    coordinator = entry.runtime_data
    async_add_entities([BoostButton(coordinator, "boost"), StopBoostButton(coordinator, "stop_boost")])


class BoostButton(NavienRecircEntity, ButtonEntity):
    """Start a hot water boost."""

    async def async_press(self) -> None:
        """Start the boost."""
        self.coordinator.boost.async_start()


class StopBoostButton(NavienRecircEntity, ButtonEntity):
    """Finish a boost early (the schedule is still put back)."""

    async def async_press(self) -> None:
        """Stop the boost."""
        self.coordinator.boost.async_request_stop()
