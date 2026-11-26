"""Background collector (issue #19): samples the lab on a schedule, whether or not anyone has the
dashboard open, and hands every confirmed state change to a handler.

Pure Python, no Docker: what to sample and what to do with the result are passed in.
    sample()                 -> list of (device dict, sample dict); raises if the lab cannot be read
    handle(transitions)      -> called after every successful round (transitions may be empty)
    metrics()                -> optional, {device_id: {"cpu": %, "mem": %}}; slow, so it runs on its
                                own, longer schedule and the latest values are merged into samples

A round that fails (for example the Docker daemon is not reachable) changes nothing: the error is
kept for /api/health and no device is marked down because NetMind itself could not look.
"""
import threading
import time

from health import HealthTracker


class Collector:
    def __init__(self, sample, handle, *, interval=5.0, confirm=2, metrics=None,
                 metrics_interval=30.0, tracker=None, clock=time.time):
        self._sample = sample
        self._handle = handle
        self._metrics = metrics
        self.interval = float(interval)
        self.metrics_interval = float(metrics_interval)
        self.tracker = tracker or HealthTracker(confirm=confirm, clock=clock)
        self._clock = clock
        self._stop = threading.Event()
        self._threads = []
        self._lock = threading.Lock()   # one round at a time
        self._latest_metrics = {}
        self.rounds = 0
        self.last_run = None
        self.last_error = None
        self.last_duration = None

    # -- one round -----------------------------------------------------------------------
    def run_once(self):
        """Sample every device once and pass the confirmed changes on. Returns the transitions
        (an empty list when nothing changed or the round failed)."""
        with self._lock:
            started = time.monotonic()
            try:
                samples = self._sample()
            except Exception as e:   # the lab could not be read: keep the last known states
                self.last_error = f"{type(e).__name__}: {e}"
                return []
            metrics = self._latest_metrics
            for device, sample in samples:
                sample.update(metrics.get(device["id"], {}))
            transitions = self.tracker.observe(samples)
            self.rounds += 1
            self.last_run = int(self._clock() * 1000)
            self.last_error = None
            self.last_duration = round(time.monotonic() - started, 3)
        try:
            self._handle(transitions)
        except Exception as e:   # a handler bug must not stop the collector
            self.last_error = f"handler: {type(e).__name__}: {e}"
        return transitions

    def refresh_metrics(self):
        if self._metrics is None:
            return
        try:
            self._latest_metrics = self._metrics() or {}
        except Exception:
            self._latest_metrics = {}

    # -- background threads --------------------------------------------------------------
    @property
    def running(self):
        return any(t.is_alive() for t in self._threads)

    def _loop(self, work, every):
        while not self._stop.is_set():
            work()
            self._stop.wait(every)

    def start(self):
        if self.running:
            return
        self._stop.clear()
        self._threads = [threading.Thread(target=self._loop, args=(self.run_once, self.interval),
                                          name="netmind-collector", daemon=True)]
        if self._metrics is not None:
            self._threads.append(threading.Thread(target=self._loop,
                                                  args=(self.refresh_metrics, self.metrics_interval),
                                                  name="netmind-metrics", daemon=True))
        for t in self._threads:
            t.start()

    def stop(self, timeout=5.0):
        self._stop.set()
        for t in self._threads:
            t.join(timeout)
        self._threads = []

    def status(self):
        return {"running": self.running, "interval_seconds": self.interval,
                "confirm_samples": self.tracker.confirm, "rounds": self.rounds,
                "last_run": self.last_run, "last_duration_seconds": self.last_duration,
                "last_error": self.last_error}
