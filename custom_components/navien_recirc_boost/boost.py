"""The boost: briefly turn the schedule off so the pump heats the loop.

In schedule mode a Navien NPE-2 ignores the Hot Button command. Turning the
weekly schedule off makes the recirculation pump run and the burner heat the
loop, so the boost does this:

1. Read the heater's live schedule (so it can be put back exactly).
2. Turn the schedule off. The pump starts.
3. Watch the water returning to the heater (inlet temperature) until it reaches
   the heater's target minus the stop offset (default 5 degrees).
4. Keep going for the extra minutes (default 2), within the safety cap
   (default 15 minutes in total).
5. Turn the schedule back to how it was, retrying up to 4 times, with a
   notification if that fails. If Home Assistant restarts mid-boost, the
   schedule is restored at the next startup.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
import logging
from typing import TYPE_CHECKING, Any

from homeassistant.core import callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.util import dt as dt_util

from .const import (
    BOOST_CHECK_SECONDS,
    CONF_EXTRA_MINUTES,
    CONF_MAX_MINUTES,
    CONF_STOP_OFFSET,
    DEFAULT_EXTRA_MINUTES,
    DEFAULT_MAX_MINUTES,
    DEFAULT_STOP_OFFSET,
    FALLBACK_STOP_TEMP_F,
    RESTORE_ATTEMPTS,
    RESTORE_RETRY_SECONDS,
    WEEKLY_OFF,
    WEEKLY_ON,
)
from .navilink import NavilinkError

if TYPE_CHECKING:
    from .coordinator import NavienRecircCoordinator

_LOGGER = logging.getLogger(__name__)

PHASE_IDLE = "idle"
PHASE_STARTING = "starting"
PHASE_HEATING = "heating"
PHASE_EXTRA = "extra_run"
PHASE_RESTORING = "restoring"


class BoostController:
    """Runs one boost at a time."""

    def __init__(self, coordinator: NavienRecircCoordinator) -> None:
        """Initialize."""
        self.coordinator = coordinator
        self.hass = coordinator.hass
        self.phase = PHASE_IDLE
        self.started_at: datetime | None = None
        self.stop_temp: float | None = None
        self.result: str | None = None
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()

    @property
    def running(self) -> bool:
        """Return True while a boost is in progress."""
        return self._task is not None and not self._task.done()

    @property
    def attributes(self) -> dict[str, Any]:
        """Extra details for the boost-running sensor."""
        return {
            "phase": self.phase,
            "started": self.started_at.isoformat() if self.started_at else None,
            "stop_temperature": self.stop_temp,
            "last_result": self.result,
        }

    def _option(self, key: str, default: float) -> float:
        return float(self.coordinator.config_entry.options.get(key, default))

    @callback
    def async_start(
        self,
        stop_offset: float | None = None,
        extra_minutes: float | None = None,
        max_minutes: float | None = None,
    ) -> None:
        """Start a boost in the background (error if one is running)."""
        if self.running:
            raise HomeAssistantError("A boost is already running")
        if not self.coordinator.client.connected:
            raise HomeAssistantError("Not connected to NaviLink")
        offset = self._option(CONF_STOP_OFFSET, DEFAULT_STOP_OFFSET) if stop_offset is None else float(stop_offset)
        extra = self._option(CONF_EXTRA_MINUTES, DEFAULT_EXTRA_MINUTES) if extra_minutes is None else float(extra_minutes)
        cap = self._option(CONF_MAX_MINUTES, DEFAULT_MAX_MINUTES) if max_minutes is None else float(max_minutes)
        self._stop.clear()
        self.phase = PHASE_STARTING
        self.started_at = dt_util.utcnow()
        self.stop_temp = None
        self._task = self.coordinator.config_entry.async_create_background_task(
            self.hass, self._run(offset, extra, cap), "navien_recirc_boost"
        )
        self.coordinator.async_update_listeners()

    @callback
    def async_request_stop(self) -> None:
        """Finish the boost early (the schedule is still restored)."""
        self._stop.set()

    async def async_shutdown(self) -> None:
        """Stop a running boost and wait for the schedule to be restored."""
        if self.running and self._task:
            self._stop.set()
            try:
                await asyncio.wait_for(asyncio.shield(self._task), 120)
            except (TimeoutError, Exception):  # noqa: BLE001
                _LOGGER.warning("Boost did not finish cleanly during unload")

    async def _wait(self, seconds: float) -> bool:
        """Sleep up to ``seconds``; return True if a stop was requested."""
        if seconds <= 0:
            return self._stop.is_set()
        try:
            await asyncio.wait_for(self._stop.wait(), seconds)
        except TimeoutError:
            return False
        return True

    async def _run(self, offset: float, extra_min: float, cap_min: float) -> None:
        coord = self.coordinator
        restore_enabled = True
        schedule: list[dict[str, Any]] | None = None
        try:
            schedule = await coord.async_live_schedule()
            prior = coord.weekly_control
            restore_enabled = prior != WEEKLY_OFF
            coord.saved.update(
                boost_in_progress=True,
                boost_schedule=schedule,
                boost_restore_enabled=restore_enabled,
            )
            await coord.async_save_now()
            coord.count_boost()

            await coord.client.async_write_schedule(coord.channel_number, False, schedule)

            target = coord.target_temp
            self.stop_temp = (target - offset) if target else FALLBACK_STOP_TEMP_F
            self.phase = PHASE_HEATING
            coord.async_update_listeners()

            cap = cap_min * 60
            waited = 0.0
            reached = False
            stopped = False
            while waited < cap:
                step = min(BOOST_CHECK_SECONDS, cap - waited)
                if await self._wait(step):
                    stopped = True
                    break
                waited += step
                await coord.client.async_poll()
                temp = coord.inlet_temp
                if temp is not None and temp >= self.stop_temp:
                    reached = True
                    break

            if stopped:
                self.result = "stopped early"
            elif reached:
                extra = min(extra_min * 60, max(cap - waited, 0))
                _LOGGER.info(
                    "Return water reached %s after %ss; running %ss more",
                    self.stop_temp, int(waited), int(extra),
                )
                self.phase = PHASE_EXTRA
                coord.async_update_listeners()
                await self._wait(extra)
                self.result = "reached temperature"
            else:
                _LOGGER.warning("Boost hit the %s minute cap before reaching %s", cap_min, self.stop_temp)
                self.result = "hit safety cap"
        except HomeAssistantError as err:
            self.result = f"failed: {err}"
            _LOGGER.error("Boost failed: %s", err)
            if schedule is None:
                coord.notify(f"The hot water boost did not start: {err}")
        except NavilinkError as err:
            self.result = f"failed: {err}"
            _LOGGER.error("Boost failed: %s", err)
        finally:
            if schedule is not None:
                self.phase = PHASE_RESTORING
                coord.async_update_listeners()
                await self.async_restore(schedule, restore_enabled)
            self.phase = PHASE_IDLE
            coord.async_update_listeners()

    async def async_restore(self, schedule: list[dict[str, Any]], enabled: bool) -> bool:
        """Put the schedule back; retry, then notify on failure."""
        coord = self.coordinator
        want = WEEKLY_ON if enabled else WEEKLY_OFF
        for attempt in range(1, RESTORE_ATTEMPTS + 1):
            try:
                await coord.client.async_write_schedule(coord.channel_number, enabled, schedule)
                await asyncio.sleep(3)
                await coord.client.async_poll()
                if coord.status.get("weeklyControl") not in (WEEKLY_ON, WEEKLY_OFF):
                    await coord.async_refresh_schedule()
                if coord.weekly_control == want:
                    coord.saved["boost_in_progress"] = False
                    coord.saved.pop("boost_schedule", None)
                    coord.saved.pop("boost_restore_enabled", None)
                    await coord.async_save_now()
                    return True
            except NavilinkError as err:
                _LOGGER.warning("Restore attempt %s failed: %s", attempt, err)
            if attempt < RESTORE_ATTEMPTS:
                await asyncio.sleep(RESTORE_RETRY_SECONDS)
        _LOGGER.error("Could not turn the weekly schedule back on")
        coord.notify(
            "The hot water boost could not turn the heater's weekly schedule back "
            "on. Check it in the NaviLink app (it will also be retried the next "
            "time Home Assistant starts)."
        )
        return False

    async def async_recover_after_restart(self) -> None:
        """If Home Assistant stopped mid-boost, put the schedule back."""
        coord = self.coordinator
        if not coord.saved.get("boost_in_progress"):
            return
        schedule = coord.saved.get("boost_schedule") or coord.saved.get("last_schedule")
        if not schedule:
            coord.saved["boost_in_progress"] = False
            coord.save()
            return
        _LOGGER.warning("Home Assistant stopped during a boost; restoring the schedule")
        await self.async_restore(schedule, coord.saved.get("boost_restore_enabled", True))
