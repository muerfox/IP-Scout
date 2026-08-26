/* Interactive world map (spec sections 28-29). All data comes from
 * /api/v1/map/, which does the aggregation server-side - this file only
 * renders whatever points it's given. */
(function () {
  "use strict";

  const container = document.getElementById("map-container");
  if (!container) return;

  const ipDetailBase = container.dataset.ipDetailBase; // e.g. "/ips/0/"
  function ipDetailUrl(id) {
    return ipDetailBase.replace("0", id);
  }

  const map = L.map(container, { worldCopyJump: true }).setView([20, 0], 2);

  L.tileLayer("https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png", {
    attribution: "&copy; OpenStreetMap contributors &copy; CARTO",
    maxZoom: 19,
  }).addTo(map);

  const markers = L.layerGroup().addTo(map);
  let currentStatus = "503";
  let currentPeriod = "24h";

  function colorFor(point) {
    if (point.address) {
      return point.is_iran ? "#e8433a" : "#3ecf5b";
    }
    return point.iran_count > 0 ? "#e8433a" : "#3ecf5b";
  }

  function radiusFor(point) {
    if (point.count <= 1) return 6;
    return Math.min(28, 6 + Math.sqrt(point.count) * 2);
  }

  function popupFor(point) {
    if (point.address) {
      const lines = [
        `<strong>${point.address}</strong>`,
        point.country_code ? `Country: ${point.country_code}` : "",
        point.asn ? `ASN: ${point.asn}` : "",
        point.organization ? `Org: ${point.organization}` : "",
        `503 count: ${point.event_count}`,
        point.last_seen_at ? `Last seen: ${point.last_seen_at}` : "",
        `Iran: ${point.is_iran ? "yes" : "no"}`,
        `<a href="${ipDetailUrl(point.ip_id)}">View IP</a>`,
      ];
      return lines.filter(Boolean).join("<br>");
    }
    return `<strong>${point.count} IPs</strong><br>Iranian: ${point.iran_count}`;
  }

  function render(points) {
    markers.clearLayers();
    points.forEach((point) => {
      L.circleMarker([point.lat, point.lon], {
        radius: radiusFor(point),
        color: colorFor(point),
        fillColor: colorFor(point),
        fillOpacity: 0.6,
        weight: 1,
      })
        .bindPopup(popupFor(point))
        .addTo(markers);
    });
  }

  function getCsrfToken() {
    const match = document.cookie.match(/(?:^|; )csrftoken=([^;]*)/);
    return match ? decodeURIComponent(match[1]) : "";
  }

  function load() {
    const zoom = map.getZoom();
    const params = new URLSearchParams({ status: currentStatus, period: currentPeriod, zoom });
    fetch(`/api/v1/map/?${params.toString()}`, { headers: { "X-CSRFToken": getCsrfToken() } })
      .then((r) => r.json())
      .then((data) => render(data.points))
      .catch((err) => console.error("map: failed to load points", err));
  }

  map.on("moveend zoomend", load);

  document.getElementById("map-status-selector").addEventListener("click", function (event) {
    const button = event.target.closest("button[data-status]");
    if (!button) return;
    this.querySelectorAll("button").forEach((b) => b.classList.remove("active"));
    button.classList.add("active");
    currentStatus = button.dataset.status;
    load();
  });

  document.getElementById("map-period-selector").addEventListener("click", function (event) {
    const button = event.target.closest("button[data-period]");
    if (!button) return;
    this.querySelectorAll("button").forEach((b) => b.classList.remove("active"));
    button.classList.add("active");
    currentPeriod = button.dataset.period;
    load();
  });

  load();
})();
