/* Dashboard charts (spec section 27). Black/white/gray NOC palette -
 * red is reserved for Iran/503-specific series, everything else is
 * shades of gray, matching the rest of the UI. */
(function () {
  "use strict";

  const COLORS = {
    text: "#f2f2f2",
    dim: "#9a9a9a",
    faint: "#5c5c5c",
    border: "#2a2a2a",
    green: "#3ecf5b",
    red: "#e8433a",
    grays: ["#d8d8d8", "#b0b0b0", "#8c8c8c", "#6e6e6e", "#555555"],
  };

  Chart.defaults.color = COLORS.dim;
  Chart.defaults.borderColor = COLORS.border;
  Chart.defaults.font.family = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif";

  const charts = {};

  function grayShade(i) {
    return COLORS.grays[i % COLORS.grays.length];
  }

  function destroyIfExists(id) {
    if (charts[id]) {
      charts[id].destroy();
    }
  }

  function lineChart(id, labels, data, color) {
    destroyIfExists(id);
    const ctx = document.getElementById(id);
    if (!ctx) return;
    charts[id] = new Chart(ctx, {
      type: "line",
      data: {
        labels,
        datasets: [
          {
            data,
            borderColor: color,
            backgroundColor: color + "22",
            fill: true,
            tension: 0.25,
            pointRadius: 0,
          },
        ],
      },
      options: {
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { maxRotation: 0, autoSkip: true } },
          y: { beginAtZero: true },
        },
      },
    });
  }

  function barChart(id, labels, data, color) {
    destroyIfExists(id);
    const ctx = document.getElementById(id);
    if (!ctx) return;
    charts[id] = new Chart(ctx, {
      type: "bar",
      data: { labels, datasets: [{ data, backgroundColor: color }] },
      options: {
        indexAxis: "y",
        plugins: { legend: { display: false } },
        scales: { x: { beginAtZero: true } },
      },
    });
  }

  function pieChart(id, labels, data, colors) {
    destroyIfExists(id);
    const ctx = document.getElementById(id);
    if (!ctx) return;
    charts[id] = new Chart(ctx, {
      type: "doughnut",
      data: { labels, datasets: [{ data, backgroundColor: colors, borderColor: "#141414", borderWidth: 2 }] },
      options: { plugins: { legend: { position: "right", labels: { boxWidth: 10 } } } },
    });
  }

  function renderAll(data) {
    lineChart(
      "chart-requests-over-time",
      data.requests_over_time.map((r) => r.bucket),
      data.requests_over_time.map((r) => r.count),
      COLORS.red
    );
    lineChart(
      "chart-unique-ips-over-time",
      data.unique_ips_over_time.map((r) => r.bucket),
      data.unique_ips_over_time.map((r) => r.count),
      COLORS.text
    );
    pieChart(
      "chart-iran-split",
      ["Iran", "Other", "Unknown"],
      [data.iran_split.iran, data.iran_split.other, data.iran_split.unknown],
      [COLORS.red, COLORS.dim, COLORS.faint]
    );
    pieChart(
      "chart-countries",
      data.countries.map((c) => c.country_code),
      data.countries.map((c) => c.count),
      data.countries.map((_, i) => grayShade(i))
    );
    barChart(
      "chart-top-iranian-ips",
      data.top_iranian_ips.map((r) => r.address),
      data.top_iranian_ips.map((r) => r.count),
      COLORS.red
    );
    barChart(
      "chart-top-iranian-cidrs",
      data.top_iranian_cidrs.map((r) => r.cidr),
      data.top_iranian_cidrs.map((r) => r.count),
      COLORS.red
    );
    barChart(
      "chart-top-countries",
      data.top_countries.map((c) => c.country_code),
      data.top_countries.map((c) => c.count),
      COLORS.text
    );
  }

  function getCsrfToken() {
    const match = document.cookie.match(/(?:^|; )csrftoken=([^;]*)/);
    return match ? decodeURIComponent(match[1]) : "";
  }

  function loadPeriod(period) {
    fetch(`/api/v1/dashboard/?period=${encodeURIComponent(period)}`, {
      headers: { "X-CSRFToken": getCsrfToken() },
    })
      .then((r) => r.json())
      .then(renderAll)
      .catch((err) => console.error("dashboard: failed to load chart data", err));
  }

  document.addEventListener("DOMContentLoaded", function () {
    const selector = document.getElementById("period-selector");
    if (!selector) return;

    selector.addEventListener("click", function (event) {
      const button = event.target.closest("button[data-period]");
      if (!button) return;
      selector.querySelectorAll("button").forEach((b) => b.classList.remove("active"));
      button.classList.add("active");
      loadPeriod(button.dataset.period);
    });

    loadPeriod("24h");
  });
})();
