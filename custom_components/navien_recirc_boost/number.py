"""Heater target temperature."""

from __future__ import annotations

from homeassistant.components.number import NumberDeviceClass, NumberEntity, NumberMode
from homeassistant.const import UnitOfTemperature
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .coordinator import NavienRecircConfigEntry
from .entity import NavienRecircEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: NavienRecircConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Add the number."""
    async_add_entities([TargetTemperature(entry.runtime_data, "target_temperature")])


class TargetTemperature(NavienRecircEntity, NumberEntity):
    """The temperature the heater heats water to."""

    _attr_device_class = NumberDeviceClass.TEMPERATURE
    _attr_mode = NumberMode.BOX

    @property
    def native_unit_of_measurement(self) -> str:
        """Follow the heater's own unit setting."""
        if self.coordinator.is_fahrenheit:
            return UnitOfTemperature.FAHRENHEIT
        return UnitOfTemperature.CELSIUS

    @property
    def native_step(self) -> float:
        """Whole degrees in Fahrenheit, half degrees in Celsius."""
        return 1 if self.coordinator.is_fahrenheit else 0.5

    @property
    def native_min_value(self) -> float:
        """Lowest the heater allows."""
        return float(self.coordinator.info.get("setupDHWTempMin") or (97 if self.coordinator.is_fahrenheit else 36))

    @property
    def native_max_value(self) -> float:
        """Highest the heater allows."""
        return float(self.coordinator.info.get("setupDHWTempMax") or (140 if self.coordinator.is_fahrenheit else 60))

    @property
    def native_value(self) -> float | None:
        """Current target."""
        return self.coordinator.target_temp

    async def async_set_native_value(self, value: float) -> None:
        """Set a new target."""
        await self.coordinator.async_set_target(value)
