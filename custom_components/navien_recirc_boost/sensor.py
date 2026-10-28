"""Schedule, boost counters and water temperature sensors."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.const import UnitOfTemperature
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import WEEKLY_OFF, WEEKLY_ON
from .coordinator import NavienRecircConfigEntry, NavienRecircCoordinator
from .entity import NavienRecircEntity
from .schedule import describe


async def async_setup_entry(
    hass: HomeAssistant,
    entry: NavienRecircConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Add the sensors."""
    c = entry.runtime_data
    async_add_entities(
        [
            ScheduleSensor(c, "schedule"),
            BoostsTodaySensor(c, "boosts_today"),
            BoostsTotalSensor(c, "boosts_total"),
            LastBoostSensor(c, "last_boost"),
            WaterTempSensor(c, "return_temperature", lambda co: co.inlet_temp),
            WaterTempSensor(c, "outlet_temperature", lambda co: co.outlet_temp),
        ]
    )


class ScheduleSensor(NavienRecircEntity, SensorEntity):
    """The heater's weekly schedule; one attribute per day."""

    _attr_device_class = SensorDeviceClass.ENUM
    _attr_options = ["on", "off"]

    @property
    def available(self) -> bool:
        """Available once a schedule has been read (or remembered)."""
        return self.coordinator.schedule is not None

    @property
    def native_value(self) -> str | None:
        """'on' when the schedule is active, 'off' when it is off."""
        value = self.coordinator.weekly_control
        if value == WEEKLY_ON:
            return "on"
        if value == WEEKLY_OFF:
            return "off"
        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Per-day windows plus the raw schedule."""
        c = self.coordinator
        attrs: dict[str, Any] = describe(c.schedule or [])
        attrs["last_read"] = c.schedule_read_at.isoformat() if c.schedule_read_at else None
        attrs["schedule"] = c.schedule
        return attrs


class _CounterBase(NavienRecircEntity, SensorEntity):
    """Counters come from saved state, so they never go unavailable."""

    @property
    def available(self) -> bool:
        """Always available."""
        return True


class BoostsTodaySensor(_CounterBase):
    """Boosts started today (resets at midnight)."""

    _attr_native_unit_of_measurement = "boosts"

    @property
    def native_value(self) -> int:
        """Today's count."""
        self.coordinator._roll_day()  # noqa: SLF001 — cheap date check
        return int(self.coordinator.saved.get("boosts_today", 0))


class BoostsTotalSensor(_CounterBase):
    """All boosts since the integration was set up."""

    _attr_native_unit_of_measurement = "boosts"
    _attr_state_class = SensorStateClass.TOTAL_INCREASING

    @property
    def native_value(self) -> int:
        """Total count."""
        return int(self.coordinator.saved.get("boosts_total", 0))


class LastBoostSensor(_CounterBase):
    """When the last boost started."""

    _attr_device_class = SensorDeviceClass.TIMESTAMP

    @property
    def native_value(self) -> datetime | None:
        """Start time of the last boost."""
        return self.coordinator.last_boost


class WaterTempSensor(NavienRecircEntity, SensorEntity):
    """A water temperature reported by the heater."""

    _attr_device_class = SensorDeviceClass.TEMPERATURE
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, coordinator: NavienRecircCoordinator, key: str, value_fn) -> None:
        """Initialize."""
        super().__init__(coordinator, key)
        self._value_fn = value_fn

    @property
    def native_unit_of_measurement(self) -> str:
        """Follow the heater's unit setting."""
        if self.coordinator.is_fahrenheit:
            return UnitOfTemperature.FAHRENHEIT
        return UnitOfTemperature.CELSIUS

    @property
    def native_value(self) -> float | None:
        """Current reading."""
        return self._value_fn(self.coordinator)
