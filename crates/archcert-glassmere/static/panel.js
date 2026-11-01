/* Progressive freshness only. Release decisions are produced by the backend. */
"use strict";

const observation = document.querySelector("[data-readiness]");
if (observation) {
  const label = observation.querySelector(".freshness");
  let generation = 0;
  let deadline = 0;
  let lastConfirmed = 0;

  function invalidate(message) {
    generation += 1;
    deadline = 0;
    observation.classList.remove("confirmed");
    label.textContent = message;
  }

  async function checkRevision() {
    if (document.hidden) return;
    const requestGeneration = ++generation;
    const started = performance.now();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2500);
    try {
      const response = await fetch(observation.dataset.checkUrl, {
        credentials: "same-origin",
        cache: "no-store",
        signal: controller.signal,
        headers: { Accept: "application/json" },
      });
      if (!response.ok) throw new Error("query unavailable");
      const value = await response.json();
      if (requestGeneration !== generation || document.hidden) return;
      if (value.schema !== 1 || value.revision !== observation.dataset.revision) {
        invalidate("STALE — authoritative revision changed. Refresh this page.");
        return;
      }
      // This validates observation freshness only; state/blockers are never
      // recomputed in JavaScript. The conservative budget starts before fetch.
      deadline = started + 6000;
      lastConfirmed = performance.now();
      observation.classList.add("confirmed");
      label.textContent = "SNAPSHOT REVISION CONFIRMED — exact selected identity; refresh required after any change";
    } catch {
      if (requestGeneration === generation) {
        invalidate("STALE / DEGRADED — backend confirmation unavailable. No current release authorization displayed.");
      }
    } finally {
      clearTimeout(timeout);
    }
  }

  setInterval(() => {
    if (deadline && performance.now() >= deadline) {
      invalidate("STALE — observation freshness budget expired. Refresh authoritative state.");
    }
    if (performance.now() - lastConfirmed > 2000 && !deadline) {
      observation.classList.remove("confirmed");
    }
  }, 250);
  setInterval(checkRevision, 3000);
  document.addEventListener("visibilitychange", () => {
    invalidate("STALE — tab visibility changed; rechecking authoritative revision.");
    if (!document.hidden) checkRevision();
  });
  window.addEventListener("pagehide", () => invalidate("STALE — historical page snapshot."));
  window.addEventListener("pageshow", () => {
    invalidate("STALE — restored page requires a fresh revision check.");
    checkRevision();
  });
  checkRevision();
}
