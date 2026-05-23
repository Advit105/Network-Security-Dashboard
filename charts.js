// ── Chart Defaults ─────────────────────────────────
Chart.defaults.color = '#7d8fa3';
Chart.defaults.borderColor = '#1e2a38';
Chart.defaults.font.family = "'JetBrains Mono', monospace";
Chart.defaults.font.size = 11;

let chartsInitialised = false;

function initCharts() {
    if (chartsInitialised) return;
    chartsInitialised = true;

    buildTrafficChart();
    buildPortChart();
    buildThreatChart();
    buildWeeklyChart();
}

// ── 1. Traffic Line Chart (24h) ────────────────────
function buildTrafficChart() {
    const hours = [
        '00:00', '02:00', '04:00', '06:00', '08:00', '10:00',
        '12:00', '14:00', '16:00', '18:00', '20:00', '22:00'
    ];
    const inbound = [12, 8, 5, 3, 18, 45, 72, 68, 55, 80, 42, 30];
    const suspicious = [2, 1, 0, 1, 5, 12, 8, 15, 6, 18, 9, 4];

    new Chart(document.getElementById('trafficChart'), {
        type: 'line',
        data: {
            labels: hours,
            datasets: [
                {
                    label: 'Inbound',
                    data: inbound,
                    borderColor: '#388bfd',
                    backgroundColor: 'rgba(56,139,253,0.08)',
                    borderWidth: 2,
                    pointRadius: 3,
                    pointBackgroundColor: '#388bfd',
                    fill: true,
                    tension: 0.4,
                },
                {
                    label: 'Suspicious',
                    data: suspicious,
                    borderColor: '#f85149',
                    backgroundColor: 'rgba(248,81,73,0.08)',
                    borderWidth: 2,
                    pointRadius: 3,
                    pointBackgroundColor: '#f85149',
                    fill: true,
                    tension: 0.4,
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { mode: 'index', intersect: false },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: '#111720',
                    borderColor: '#1e2a38',
                    borderWidth: 1,
                    padding: 10,
                    titleColor: '#e6edf3',
                    bodyColor: '#7d8fa3',
                }
            },
            scales: {
                x: { grid: { display: false } },
                y: {
                    grid: { color: '#1e2a38' },
                    ticks: { callback: v => v + ' MB' }
                }
            }
        }
    });
}

// ── 2. Port Activity Bar Chart ─────────────────────
function buildPortChart() {
    const ports = ['22 SSH', '21 FTP', '3306 MySQL', '80 HTTP', '8080 Alt', '443 HTTPS'];
    const counts = [312, 188, 97, 74, 41, 15];
    const colors = [
        '#f85149', '#f85149', '#d29922',
        '#d29922', '#d29922', '#3fb950'
    ];

    new Chart(document.getElementById('portChart'), {
        type: 'bar',
        data: {
            labels: ports,
            datasets: [{
                label: 'Hits',
                data: counts,
                backgroundColor: colors,
                borderRadius: 4,
                borderSkipped: false,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: '#111720',
                    borderColor: '#1e2a38',
                    borderWidth: 1,
                    padding: 10,
                    titleColor: '#e6edf3',
                    bodyColor: '#7d8fa3',
                }
            },
            scales: {
                x: { grid: { display: false } },
                y: { grid: { color: '#1e2a38' } }
            }
        }
    });
}

// ── 3. Threat Breakdown Doughnut ───────────────────
function buildThreatChart() {
    new Chart(document.getElementById('threatChart'), {
        type: 'doughnut',
        data: {
            labels: ['Brute Force', 'Port Scan', 'Malware', 'Phishing', 'Other'],
            datasets: [{
                data: [18, 10, 6, 5, 3],
                backgroundColor: [
                    '#f85149', '#d29922', '#388bfd', '#3fb950', '#3d4f63'
                ],
                borderWidth: 0,
                hoverOffset: 6,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '72%',
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        padding: 14,
                        usePointStyle: true,
                        pointStyleWidth: 8,
                        color: '#7d8fa3',
                    }
                },
                tooltip: {
                    backgroundColor: '#111720',
                    borderColor: '#1e2a38',
                    borderWidth: 1,
                    padding: 10,
                    titleColor: '#e6edf3',
                    bodyColor: '#7d8fa3',
                }
            }
        },
        plugins: [{
            id: 'doughnutCenter',
            afterDraw: (chart) => {
                const meta = chart.getDatasetMeta(0);
                if (meta && meta.data[0]) {
                    const x = meta.data[0].x;
                    const y = meta.data[0].y;
                    const centerEl = chart.canvas.parentNode.querySelector('.doughnut-center');
                    if (centerEl) {
                        centerEl.style.left = `${x}px`;
                        centerEl.style.top = `${y}px`;
                        centerEl.style.position = 'absolute';
                        centerEl.style.transform = 'translate(-50%, -50%)';
                    }
                }
            }
        }]
    });
}

// ── 4. Weekly Summary Bar Chart ────────────────────
function buildWeeklyChart() {
    const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    const critical = [3, 5, 2, 8, 4, 1, 3];
    const warnings = [7, 9, 5, 12, 6, 2, 7];

    new Chart(document.getElementById('weeklyChart'), {
        type: 'bar',
        data: {
            labels: days,
            datasets: [
                {
                    label: 'Critical',
                    data: critical,
                    backgroundColor: '#f85149',
                    borderRadius: 4,
                    borderSkipped: false,
                },
                {
                    label: 'Warnings',
                    data: warnings,
                    backgroundColor: '#d29922',
                    borderRadius: 4,
                    borderSkipped: false,
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { mode: 'index', intersect: false },
            plugins: {
                legend: {
                    labels: {
                        usePointStyle: true,
                        pointStyleWidth: 8,
                        color: '#7d8fa3',
                        padding: 16,
                    }
                },
                tooltip: {
                    backgroundColor: '#111720',
                    borderColor: '#1e2a38',
                    borderWidth: 1,
                    padding: 10,
                    titleColor: '#e6edf3',
                    bodyColor: '#7d8fa3',
                }
            },
            scales: {
                x: { grid: { display: false }, stacked: false },
                y: { grid: { color: '#1e2a38' } }
            }
        }
    });
}