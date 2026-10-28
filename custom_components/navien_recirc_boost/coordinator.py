"""Coordinator: owns the NaviLink connection, the schedule, and saved state."""

from __future__ import annotations

from datetime import datetime, timedelta
import logging
from typing import Any

from homeassistant.components import persistent_notification
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import (
    ConfigEntryAuthFailed,
    HomeAssistantError,
)
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.event import async_track_time_change, async_track_time_interval
from homeassistant.helpers.storage import Store
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from .const import (
    CONF_DEVICE_INDEX,
    CONF_PASSWORD,
    CONF_USERNAME,
    DOMAIN,
    POLL_INTERVAL,
    SCHEDULE_REFRESH_HOURS,
    STORAGE_VERSION,
    WEEKLY_OFF,
    WEEKLY_ON,
)
from .navilink import AuthenticationError, NavilinkClient, NavilinkError

_LOGGER = logging.getLogger(__name__)

type NavienRecircConfigEntry = ConfigEntry[NavienRecircCoordinator]


class NavienRecircCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Keeps one NaviLink session and pushes updates to the entities."""

    config_entry: NavienRecircConfigEntry

    def __init__(self, hass: HomeAssistant, entry: NavienRecircConfigEntry) -> None:
        """Set up (no network yet)."""
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            config_entry=entry,
            update_interval=None,  # the client pushes updates
        )
        self.client = NavilinkClient(
            entry.data[CONF_USERNAME],
            entry.data[CONF_PASSWORD],
            session=async_get_clientsession(hass),
            device_index=entry.data.get(CONF_DEVICE_INDEX, 0),
            poll_interval=POLL_INTERVAL,
        )
        self.client.on_update = self._handle_client_update
        self._store: Store[dict[str, Any]] = Store(
            hass, STORAGE_VERSION, f"{DOMAIN}.{entry.entry_id}"
        )
        self.saved: dict[str, Any] = {}
        self.schedule: list[dict[str, Any]] | None = None
        self.schedule_weekly_control: int | None = None
        self.schedule_read_at: datetime | None = None
        self.boost = None  # set in __init__.py (BoostController)
        self._unsubs: list = []

    # ----- startup / shutdown -----

    async def async_load_saved(self) -> None:
        """Load counters and the last known schedule from disk."""
        self.saved = await self._store.async_load() or {}
        self.saved.setdefault("boosts_total", 0)
        self.saved.setdefault("boosts_today", 0)
        self.saved.setdefault("today", dt_util.now().date().isoformat())
        self.saved.setdefault("last_boost", None)
        self.saved.setdefault("last_schedule", None)
        self.saved.setdefault("last_weekly_control", None)
        self.saved.setdefault("boost_in_progress", False)
        if self.saved["last_schedule"] and self.schedule is None:
            self.schedule = self.saved["last_schedule"]
            self.schedule_weekly_control = self.saved["last_weekly_control"]
        self._roll_day()

    def save(self) -> None:
        """Write saved state to disk soon."""
        self._store.async_delay_save(lambda: dict(self.saved), 1)

    async def async_save_now(self) -> None:
        """Write saved state to disk now."""
        await self._store.async_save(dict(self.saved))

    async def _async_update_data(self) -> dict[str, Any]:
        """First refresh: sign in and connect."""
        if not self.client.connected:
            try:
                await self.client.async_connect()
            except AuthenticationError as err:
                raise ConfigEntryAuthFailed(str(err)) from err
            except NavilinkError as err:
                raise UpdateFailed(f"Could not connect to NaviLink: {err}") from err
        return self._snapshot()

    @callback
    def async_start_timers(self) -> None:
        """Start the hourly schedule refresh and the midnight counter reset."""
        self._unsubs.append(
            async_track_time_interval(
                self.hass,
                self._async_hourly,
                timedelta(hours=SCHEDULE_REFRESH_HOURS),
                name=f"{DOMAIN} schedule refresh",
            )
        )
        self._unsubs.append(
            async_track_time_change(self.hass, self._midnight, hour=0, minute=0, second=1)
        )

    async def _async_hourly(self, _now: datetime) -> None:
        await self.async_refresh_schedule()

    @callback
    def _midnight(self, _now: datetime) -> None:
        if self._roll_day():
            self.save()
            self.async_update_listeners()

    async def async_shutdown_connection(self) -> None:
        """Stop timers and disconnect."""
        for unsub in self._unsubs:
            unsub()
        self._unsubs.clear()
        await self.client.async_disconnect()

    # ----- client pushes -----

    @callback
    def _handle_client_update(self) -> None:
        reply = self.client.weekly.get(self.channel_number)
        if reply and reply.get("received") != getattr(self, "_weekly_seen", None):
            self._weekly_seen = reply.get("received")
            self._apply_schedule_reply(reply)
        self.async_set_updated_data(self._snapshot())

    def _snapshot(self) -> dict[str, Any]:
        return {"connected": self.client.connected}

    # ----- device / channel helpers -----

    @property
    def device_info_raw(self) -> dict[str, Any]:
        """Return the NaviLink deviceInfo block."""
        return (self.client.device_info or {}).get("deviceInfo", {})

    @property
    def mac(self) -> str:
        """Return the heater's MAC address."""
        return self.device_info_raw.get("macAddress", "unknown")

    @property
    def device_name(self) -> str:
        """Return the heater's name in NaviLink."""
        return self.device_info_raw.get("deviceName", "Navien")

    @property
    def channel_number(self) -> int:
        """Return the heating channel to control (lowest number, usually 1)."""
        return min(self.client.channels) if self.client.channels else 1

    @property
    def channel(self):
        """Return the NaviLink channel object, or None."""
        return self.client.channels.get(self.channel_number)

    @property
    def status(self) -> dict[str, Any]:
        """Return the channel's latest status."""
        return self.channel.status if self.channel else {}

    @property
    def info(self) -> dict[str, Any]:
        """Return the channel's info (limits, units)."""
        return self.channel.info if self.channel else {}

    @property
    def is_fahrenheit(self) -> bool:
        """Return True when the heater reports Fahrenheit."""
        return self.info.get("temperatureType") == 2

    def _unit(self) -> dict[str, Any]:
        units = self.status.get("unitInfo", {}).get("unitStatusList", [])
        return units[0] if units else {}

    @property
    def inlet_temp(self) -> float | None:
        """Return the water coming back into the heater (return line)."""
        value = self._unit().get("currentInletTemp", self.status.get("avgInletTemp"))
        return float(value) if value is not None else None

    @property
    def outlet_temp(self) -> float | None:
        """Return the hot water leaving the heater."""
        value = self._unit().get("currentOutletTemp", self.status.get("avgOutletTemp"))
        return float(value) if value is not None else None

    @property
    def target_temp(self) -> float | None:
        """Return the heater's set temperature."""
        value = self.status.get("DHWSettingTemp")
        return float(value) if value is not None else None

    @property
    def weekly_control(self) -> int | None:
        """Return 1 (schedule on) or 2 (off), newest source first."""
        value = self.status.get("weeklyControl")
        if value in (WEEKLY_ON, WEEKLY_OFF):
            return value
        return self.schedule_weekly_control

    # ----- schedule -----

    def _apply_schedule_reply(self, reply: dict[str, Any]) -> None:
        self.schedule = reply["schedule"]
        self.schedule_weekly_control = reply.get("weekly_control")
        self.schedule_read_at = dt_util.utcnow()
        if not self.saved.get("boost_in_progress"):
            # During a boost the schedule reads "off"; keep the pre-boost copy.
            self.saved["last_schedule"] = self.schedule
            self.saved["last_weekly_control"] = self.schedule_weekly_control
            self.save()

    async def async_refresh_schedule(self) -> bool:
        """Ask the heater for its schedule. Returns True if it answered."""
        if not self.client.connected:
            return False
        try:
            reply = await self.client.async_read_schedule(self.channel_number)
        except NavilinkError as err:
            _LOGGER.warning("Schedule read failed: %s", err)
            return False
        if reply is None:
            _LOGGER.warning("The heater did not answer the schedule request")
            return False
        if reply.get("received") != getattr(self, "_weekly_seen", None):
            self._weekly_seen = reply.get("received")
            self._apply_schedule_reply(reply)
        self.async_update_listeners()
        return True

    async def async_live_schedule(self) -> list[dict[str, Any]]:
        """Return the heater's schedule, read fresh when possible."""
        await self.async_refresh_schedule()
        if not self.schedule:
            raise HomeAssistantError(
                "The heater's schedule is unknown (no answer from NaviLink), so it is "
                "not safe to change it"
            )
        return self.schedule

    async def async_set_weekly(self, enabled: bool) -> None:
        """Turn the heater's weekly schedule on or off (keeping its windows)."""
        schedule = await self.async_live_schedule()
        await self._write(enabled, schedule)

    async def async_set_day(self, day: dict[str, Any]) -> None:
        """Replace one day's windows, keeping the schedule on/off as it is."""
        await self.async_live_schedule()
        enabled = self.weekly_control != WEEKLY_OFF
        await self._write(enabled, [day])
        await self.async_refresh_schedule()

    async def _write(self, enabled: bool, schedule: list[dict[str, Any]]) -> None:
        try:
            await self.client.async_write_schedule(self.channel_number, enabled, schedule)
        except NavilinkError as err:
            raise HomeAssistantError(f"NaviLink rejected the schedule change: {err}") from err
        self.async_update_listeners()

    # ----- target temperature -----

    async def async_set_target(self, value: float) -> None:
        """Set the heater's target temperature (in the heater's units)."""
        if self.channel is None:
            raise HomeAssistantError("Heater not connected")
        raw = round(value) if self.is_fahrenheit else round(2 * value)
        try:
            await self.channel.set_temperature(raw)
        except NavilinkError as err:
            raise HomeAssistantError(f"NaviLink rejected the temperature: {err}") from err

    # ----- counters -----

    def _roll_day(self) -> bool:
        today = dt_util.now().date().isoformat()
        if self.saved.get("today") != today:
            self.saved["today"] = today
            self.saved["boosts_today"] = 0
            return True
        return False

    def count_boost(self) -> None:
        """Record that a boost started."""
        self._roll_day()
        self.saved["boosts_today"] += 1
        self.saved["boosts_total"] += 1
        self.saved["last_boost"] = dt_util.utcnow().isoformat()
        self.save()

    @property
    def last_boost(self) -> datetime | None:
        """Return when the last boost started."""
        value = self.saved.get("last_boost")
        return dt_util.parse_datetime(value) if value else None

    def notify(self, message: str) -> None:
        """Show a persistent notification in Home Assistant."""
        persistent_notification.async_create(
            self.hass, message, title="Navien Recirc Boost",
            notification_id=f"{DOMAIN}_{self.config_entry.entry_id}",
        )
