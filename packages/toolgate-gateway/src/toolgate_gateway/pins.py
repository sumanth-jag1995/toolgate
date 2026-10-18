"""PinSource: hot-reloaded pins from the git-committed lockfile.

The file is re-read only when its ``(ino, mtime_ns, ctime_ns, size)``
changes. A missing lockfile means no pins (every tool unpinned). A corrupt or unreadable one
keeps the last good pins until they have been unconfirmed for longer than
``stale_after_s``; after that (or with no good pins at all) the source
returns None and the gateway lists nothing.
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable
from pathlib import Path

from toolgate_pin import InMemoryStore, LockfileError, LockfileStore, Pinner, PinSet

log = logging.getLogger(__name__)

PIN_STALE_SECONDS = 300.0

_MISSING = ("missing",)


class PinSource:
    def __init__(
        self,
        path: Path | str | os.PathLike[str],
        *,
        stale_after_s: float = PIN_STALE_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._path = Path(path)
        self._store = LockfileStore(self._path)
        self._stale_after = stale_after_s
        self._clock = clock
        self._sig: tuple[object, ...] | None = None  # last signature read
        self._pins: PinSet | None = None  # last good
        self._pinner: Pinner | None = None
        self._failing_since: float | None = None  # first failed read

    def current(self) -> PinSet | None:
        state = self.state()
        return state[0] if state else None

    def pinner(self) -> Pinner | None:
        state = self.state()
        return state[1] if state else None

    def state(self) -> tuple[PinSet, Pinner] | None:
        """The current pins and their Pinner together (one consistent read),
        or None when no usable pins exist."""
        self._maybe_reload()
        if self._pins is None or self._pinner is None:
            return None
        if self._failing_since is not None and (
            self._clock() - self._failing_since > self._stale_after
        ):
            return None
        return self._pins, self._pinner

    def _signature(self) -> tuple[object, ...] | None:
        try:
            st = self._path.stat()
        except FileNotFoundError:
            return _MISSING
        except OSError:
            return None  # cannot stat: always attempt (and fail) a read
        # The inode (file id on Windows) changes on every atomic replace, so
        # a same-size rewrite with a preserved mtime is still detected.
        return (st.st_ino, st.st_mtime_ns, st.st_ctime_ns, st.st_size)

    def _maybe_reload(self) -> None:
        sig = self._signature()
        if sig is not None and sig == self._sig:
            return
        try:
            pins = self._store.load()
        except LockfileError as exc:
            if self._failing_since is None:
                self._failing_since = self._clock()
                log.warning(
                    "lockfile %s is unusable (%s); keeping last good pins for "
                    "at most %.0f s",
                    self._path,
                    type(exc.__cause__ or exc).__name__,
                    self._stale_after,
                )
            self._sig = sig
            return
        self._sig = sig
        self._pins = pins
        self._pinner = Pinner(InMemoryStore(pins))
        if self._failing_since is not None:
            log.info("lockfile %s is readable again", self._path)
        self._failing_since = None
