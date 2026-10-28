"""Navien Recirc Boost: boost recirculation on a scheduled Navien heater."""

from __future__ import annotations

import logging

import voluptuous as vol

from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.typing import ConfigType

from .boost import BoostController
from .const import (
    CONF_EXTRA_MINUTES,
    CONF_MAX_MINUTES,
    CONF_STOP_OFFSET,
    DOMAIN,
    SERVICE_BOOST,
    SERVICE_REFRESH_SCHEDULE,
    SERVICE_SET_DAY_SCHEDULE,
    SERVICE_STOP_BOOST,
)
from .coordinator import NavienRecircConfigEntry, NavienRecircCoordinator
from .schedule import ScheduleError, build_day, day_number, parse_windows

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [
    Platform.BINARY_SENSOR,
    Platform.BUTTON,
    Platform.NUMBER,
    Platform.SENSOR,
    Platform.SWITCH,
]

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)

ATTR_CONFIG_ENTRY = "config_entry_id"
ATTR_DAY = "day"
ATTR_WINDOWS = "windows"

_ENTRY = {vol.Optional(ATTR_CONFIG_ENTRY): cv.string}
BOOST_SCHEMA = vol.Schema(
    {
        **_ENTRY,
        vol.Optional(CONF_STOP_OFFSET): vol.All(vol.Coerce(float), vol.Range(min=0, max=30)),
        vol.Optional(CONF_EXTRA_MINUTES): vol.All(vol.Coerce(float), vol.Range(min=0, max=15)),
        vol.Optional(CONF_MAX_MINUTES): vol.All(vol.Coerce(float), vol.Range(min=1, max=60)),
    }
)
ENTRY_ONLY_SCHEMA = vol.Schema(_ENTRY)
SET_DAY_SCHEMA = vol.Schema(
    {**_ENTRY, vol.Required(ATTR_DAY): cv.string, vol.Required(ATTR_WINDOWS): cv.string}
)


def _coordinator(hass: HomeAssistant, call: ServiceCall) -> NavienRecircCoordinator:
    entries = [
        e for e in hass.config_entries.async_entries(DOMAIN)
        if e.state is ConfigEntryState.LOADED
        and ATTR_CONFIG_ENTRY not in call.data or e.entry_id == call.data[ATTR_CONFIG_ENTRY]
    ]
    if not entries:
        raise ServiceValidationError("No loaded Navien Recirc Boost heater found")
    if len(entries) > 1:
        raise ServiceValidationError("Several heaters are set up; pass config_entry_id")
    return entries[0].runtime_data


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Register the integration's actions (services)."""

    async def boost(call: ServiceCall) -> None:
        coord = _coordinator(hass, call)
        coord.boost.async_start(
            call.data.get(CONF_STOP_OFFSET),
            call.data.get(CONF_EXTRA_MINUTES),
            call.data.get(CONF_MAX_MINUTES),
        )

    async def stop_boost(call: ServiceCall) -> None:
        _coordinator(hass, call).boost.async_request_stop()

    async def refresh_schedule(call: ServiceCall) -> None:
        if not await _coordinator(hass, call).async_refresh_schedule():
            raise HomeAssistantError("The heater did not answer the schedule request")

    async def set_day_schedule(call: ServiceCall) -> None:
        coord = _coordinator(hass, call)
        try:
            day = build_day(day_number(call.data[ATTR_DAY]), parse_windows(call.data[ATTR_WINDOWS]))
        except ScheduleError as err:
            raise ServiceValidationError(str(err)) from err
        await coord.async_set_day(day)

    hass.services.async_register(DOMAIN, SERVICE_BOOST, boost, schema=BOOST_SCHEMA)
    hass.services.async_register(DOMAIN, SERVICE_STOP_BOOST, stop_boost, schema=ENTRY_ONLY_SCHEMA)
    hass.services.async_register(
        DOMAIN, SERVICE_REFRESH_SCHEDULE, refresh_schedule, schema=ENTRY_ONLY_SCHEMA
    )
    hass.services.async_register(
        DOMAIN, SERVICE_SET_DAY_SCHEDULE, set_day_schedule, schema=SET_DAY_SCHEMA
    )
    return True


async def async_setup_entry(hass: HomeAssistant, entry: NavienRecircConfigEntry) -> bool:
    """Connect to NaviLink and set up the entities."""
    coordinator = NavienRecircCoordinator(hass, entry)
    await coordinator.async_load_saved()
    coordinator.boost = BoostController(coordinator)
    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = coordinator

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    coordinator.async_start_timers()
    entry.async_on_unload(entry.add_update_listener(_async_options_updated))

    async def _after_start() -> None:
        await coordinator.boost.async_recover_after_restart()
        await coordinator.async_refresh_schedule()

    entry.async_create_background_task(hass, _after_start(), f"{DOMAIN} startup")
    return True


async def async_unload_entry(hass: HomeAssistant, entry: NavienRecircConfigEntry) -> bool:
    """Unload: finish any boost (restoring the schedule), then disconnect."""
    coordinator = entry.runtime_data
    await coordinator.boost.async_shutdown()
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        await coordinator.async_save_now()
        await coordinator.async_shutdown_connection()
    return unload_ok


async def _async_options_updated(hass: HomeAssistant, entry: NavienRecircConfigEntry) -> None:
    """Boost settings are read when a boost starts, so no reload is needed."""
    coordinator = entry.runtime_data
    coordinator.async_update_listeners()
