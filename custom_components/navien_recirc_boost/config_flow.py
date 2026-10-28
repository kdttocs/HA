"""Sign-in (config flow) and settings / schedule editor (options flow)."""

from __future__ import annotations

from collections.abc import Mapping
import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import (
    ConfigEntry,
    ConfigEntryState,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.core import callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import selector
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.util import dt as dt_util

from .const import (
    CONF_DEVICE_INDEX,
    CONF_EXTRA_MINUTES,
    CONF_MAX_MINUTES,
    CONF_PASSWORD,
    CONF_STOP_OFFSET,
    CONF_USERNAME,
    DAY_NAMES,
    WEEKLY_OFF,
    DEFAULT_EXTRA_MINUTES,
    DEFAULT_MAX_MINUTES,
    DEFAULT_STOP_OFFSET,
    DOMAIN,
)
from .navilink import AuthenticationError, NavilinkClient, NavilinkError, NoDevicesError
from .schedule import ScheduleError, build_day, describe, parse_windows

_LOGGER = logging.getLogger(__name__)

USER_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_USERNAME): selector.TextSelector(
            selector.TextSelectorConfig(type=selector.TextSelectorType.EMAIL, autocomplete="username")
        ),
        vol.Required(CONF_PASSWORD): selector.TextSelector(
            selector.TextSelectorConfig(
                type=selector.TextSelectorType.PASSWORD, autocomplete="current-password"
            )
        ),
    }
)


async def _login(hass, username: str, password: str) -> list[dict[str, Any]]:
    client = NavilinkClient(username, password, session=async_get_clientsession(hass))
    return await client.async_login()


def _mac(device: dict[str, Any]) -> str:
    return device.get("deviceInfo", {}).get("macAddress", "unknown")


def _name(device: dict[str, Any]) -> str:
    return device.get("deviceInfo", {}).get("deviceName") or "Navien"


class NavienRecircConfigFlow(ConfigFlow, domain=DOMAIN):
    """Sign in to NaviLink and pick the heater."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialize."""
        self._username = ""
        self._password = ""
        self._devices: list[dict[str, Any]] = []

    async def _try_login(self, user_input: dict[str, Any], errors: dict[str, str]) -> bool:
        try:
            self._devices = await _login(
                self.hass, user_input[CONF_USERNAME], user_input[CONF_PASSWORD]
            )
        except AuthenticationError:
            errors["base"] = "invalid_auth"
        except NoDevicesError:
            errors["base"] = "no_devices"
        except NavilinkError:
            errors["base"] = "cannot_connect"
        except Exception:  # noqa: BLE001
            _LOGGER.exception("Unexpected error signing in to NaviLink")
            errors["base"] = "unknown"
        else:
            self._username = user_input[CONF_USERNAME]
            self._password = user_input[CONF_PASSWORD]
            return True
        return False

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Ask for the NaviLink email and password."""
        errors: dict[str, str] = {}
        if user_input is not None and await self._try_login(user_input, errors):
            if len(self._devices) == 1:
                return await self._create(0)
            return await self.async_step_pick_device()
        return self.async_show_form(
            step_id="user",
            data_schema=self.add_suggested_values_to_schema(USER_SCHEMA, user_input or {}),
            errors=errors,
        )

    async def async_step_pick_device(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Choose which heater, when the account has several."""
        if user_input is not None:
            return await self._create(int(user_input[CONF_DEVICE_INDEX]))
        options = [
            selector.SelectOptionDict(value=str(i), label=f"{_name(d)} ({_mac(d)})")
            for i, d in enumerate(self._devices)
        ]
        return self.async_show_form(
            step_id="pick_device",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_DEVICE_INDEX, default="0"): selector.SelectSelector(
                        selector.SelectSelectorConfig(options=options)
                    )
                }
            ),
        )

    async def _create(self, index: int) -> ConfigFlowResult:
        device = self._devices[index]
        await self.async_set_unique_id(_mac(device))
        self._abort_if_unique_id_configured()
        return self.async_create_entry(
            title=f"{_name(device)} Recirc Boost",
            data={
                CONF_USERNAME: self._username,
                CONF_PASSWORD: self._password,
                CONF_DEVICE_INDEX: index,
            },
            options={
                CONF_STOP_OFFSET: DEFAULT_STOP_OFFSET,
                CONF_EXTRA_MINUTES: DEFAULT_EXTRA_MINUTES,
                CONF_MAX_MINUTES: DEFAULT_MAX_MINUTES,
            },
        )

    async def async_step_reauth(self, entry_data: Mapping[str, Any]) -> ConfigFlowResult:
        """NaviLink refused the saved password."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask for the password again."""
        entry = self._get_reauth_entry()
        errors: dict[str, str] = {}
        if user_input is not None:
            data = {CONF_USERNAME: entry.data[CONF_USERNAME], CONF_PASSWORD: user_input[CONF_PASSWORD]}
            if await self._try_login(data, errors):
                return self.async_update_reload_and_abort(
                    entry, data_updates={CONF_PASSWORD: user_input[CONF_PASSWORD]}
                )
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_PASSWORD): selector.TextSelector(
                        selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
                    )
                }
            ),
            description_placeholders={"username": entry.data[CONF_USERNAME]},
            errors=errors,
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        """Return the options flow."""
        return NavienRecircOptionsFlow()


def _minutes(minimum: int, maximum: int) -> selector.NumberSelector:
    return selector.NumberSelector(
        selector.NumberSelectorConfig(
            min=minimum, max=maximum, step=1, mode=selector.NumberSelectorMode.BOX,
            unit_of_measurement="min",
        )
    )


class NavienRecircOptionsFlow(OptionsFlow):
    """Boost settings and the schedule editor."""

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Choose what to change."""
        return self.async_show_menu(step_id="init", menu_options=["schedule", "boost_settings"])

    async def async_step_boost_settings(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Stop offset, extra minutes and safety cap."""
        if user_input is not None:
            return self.async_create_entry(
                data={**self.config_entry.options, **{k: int(v) for k, v in user_input.items()}}
            )
        opts = self.config_entry.options
        schema = vol.Schema(
            {
                vol.Required(
                    CONF_STOP_OFFSET, default=opts.get(CONF_STOP_OFFSET, DEFAULT_STOP_OFFSET)
                ): selector.NumberSelector(
                    selector.NumberSelectorConfig(
                        min=1, max=20, step=1, mode=selector.NumberSelectorMode.BOX,
                        unit_of_measurement="degrees",
                    )
                ),
                vol.Required(
                    CONF_EXTRA_MINUTES, default=opts.get(CONF_EXTRA_MINUTES, DEFAULT_EXTRA_MINUTES)
                ): _minutes(0, 15),
                vol.Required(
                    CONF_MAX_MINUTES, default=opts.get(CONF_MAX_MINUTES, DEFAULT_MAX_MINUTES)
                ): _minutes(1, 60),
            }
        )
        return self.async_show_form(step_id="boost_settings", data_schema=schema)

    def _coordinator(self):
        entry = self.config_entry
        if entry.state is not ConfigEntryState.LOADED:
            return None
        return entry.runtime_data

    async def async_step_schedule(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Show the whole weekly schedule and edit any day on one screen."""
        coord = self._coordinator()
        if coord is None:
            return self.async_abort(reason="not_loaded")
        if coord.boost.running:
            return self.async_abort(reason="boost_running")
        errors: dict[str, str] = {}
        placeholders = {"error": "", "read": ""}
        if user_input is None:
            await coord.async_refresh_schedule()
        if not coord.schedule:
            return self.async_abort(reason="no_schedule")
        current = describe(coord.schedule)
        enabled_now = coord.weekly_control != WEEKLY_OFF
        if user_input is not None:
            changed: list[dict[str, Any]] = []
            for num, name in DAY_NAMES.items():
                text = user_input.get(name, "")
                try:
                    windows = parse_windows(text)
                except ScheduleError as err:
                    errors[name] = "bad_windows"
                    placeholders["error"] = f"{name.title()}: {err}"
                    continue
                if build_day(num, windows) != build_day(num, parse_windows(current[name])):
                    changed.append(build_day(num, windows))
            enabled = bool(user_input.get("enabled", enabled_now))
            if not errors:
                if changed or enabled != enabled_now:
                    try:
                        await coord.async_set_week(enabled, changed)
                    except HomeAssistantError as err:
                        errors["base"] = "write_failed"
                        placeholders["error"] = str(err)
                if not errors:
                    return self.async_create_entry(data=dict(self.config_entry.options))
            values = user_input
        else:
            values = {"enabled": enabled_now, **current}
        if coord.schedule_read_at:
            placeholders["read"] = dt_util.as_local(coord.schedule_read_at).strftime("%-I:%M %p")
        schema: dict[Any, Any] = {
            vol.Required("enabled", default=values.get("enabled", enabled_now)): selector.BooleanSelector()
        }
        for name in DAY_NAMES.values():
            schema[vol.Required(name, default=values.get(name, current[name]))] = selector.TextSelector()
        return self.async_show_form(
            step_id="schedule",
            data_schema=vol.Schema(schema),
            description_placeholders=placeholders,
            errors=errors,
        )
