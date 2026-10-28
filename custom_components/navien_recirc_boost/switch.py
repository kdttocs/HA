"""Weekly schedule on/off switch."""

from __future__ import annotations

from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import WEEKLY_OFF, WEEKLY_ON
from .coordinator import NavienRecircConfigEntry
from .entity import NavienRecircEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: NavienRecircConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Add the switch."""
    async_add_entities([WeeklyScheduleSwitch(entry.runtime_data, "weekly_schedule")])


class WeeklyScheduleSwitch(NavienRecircEntity, SwitchEntity):
    """The heater's own weekly recirculation schedule (on = follow it)."""

    @property
    def is_on(self) -> bool | None:
        """Return True when the schedule is on."""
        value = self.coordinator.weekly_control
        if value == WEEKLY_ON:
            return True
        if value == WEEKLY_OFF:
            return False
        return None

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn the schedule on (its windows are kept)."""
        await self.coordinator.async_set_weekly(True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn the schedule off (the pump runs continuously)."""
        await self.coordinator.async_set_weekly(False)
