/* ============================================================= *
 *  COWTAIL // shared Chart.js styling helpers
 * ============================================================= */

export const chartGrid = { color: "rgba(120,170,190,0.08)" };

export function gradient(canvas, c1, c2) {
  const ctx = canvas.getContext("2d");
  const g = ctx.createLinearGradient(0, 0, 0, canvas.height || 200);
  g.addColorStop(0, c1);
  g.addColorStop(1, c2);
  return g;
}

export function barOpts(max) {
  return {
    indexAxis: "y",
    responsive: true,
    maintainAspectRatio: false,
    animation: { duration: 350 },
    plugins: { legend: { display: false } },
    scales: {
      x: { grid: chartGrid, ticks: { precision: 0, color: "#3d5361" }, beginAtZero: true, suggestedMax: max },
      y: { grid: { display: false }, ticks: { color: "#69808f" } },
    },
  };
}
