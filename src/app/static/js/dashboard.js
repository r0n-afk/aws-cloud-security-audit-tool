document.addEventListener('DOMContentLoaded', function() {
    fetch('/api/dashboard/charts')
    .then(r => r.json())
    .then(data => {
        const ink = '#111418';
        const muted = '#5c6168';
        const accent = '#c8102e';
        const rule = '#d9d4ca';
        const paper = '#f7f5f0';
        const isDark = document.documentElement.getAttribute('data-bs-theme') === 'dark';
        const gridColor = isDark ? '#2c313a' : '#d9d4ca';
        const tickColor = isDark ? '#9aa1ab' : '#5c6168';

        const severityColors = {
            'critical': '#c8102e',
            'high': '#b45309',
            'medium': '#a16207',
            'low': '#1d4ed8',
            'informational': '#5c6168'
        };

        const gridOpts = {
            color: gridColor,
            drawBorder: false
        };
        const tickOpts = {
            color: tickColor,
            font: { family: 'IBM Plex Mono', size: 10 }
        };

        if (data.score_trend && data.score_trend.dates.length > 0) {
            new Chart(document.getElementById('scoreTrendChart'), {
                type: 'line',
                data: {
                    labels: data.score_trend.dates,
                    datasets: [{
                        label: 'Security Score',
                        data: data.score_trend.scores,
                        borderColor: ink,
                        backgroundColor: 'rgba(17,20,24,0.06)',
                        borderWidth: 2,
                        pointRadius: 3,
                        pointBackgroundColor: accent,
                        pointBorderColor: accent,
                        pointHoverRadius: 5,
                        fill: true,
                        tension: 0.25
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: { beginAtZero: true, max: 100, grid: gridOpts, ticks: tickOpts },
                        x: { grid: { display: false }, ticks: tickOpts }
                    },
                    plugins: { legend: { display: false } }
                }
            });
        }

        const sevLabels = Object.keys(data.severity_distribution);
        const sevValues = Object.values(data.severity_distribution);
        if (sevValues.some(v => v > 0)) {
            new Chart(document.getElementById('severityChart'), {
                type: 'doughnut',
                data: {
                    labels: sevLabels.map(s => s.charAt(0).toUpperCase() + s.slice(1)),
                    datasets: [{
                        data: sevValues,
                        backgroundColor: sevLabels.map(s => severityColors[s]),
                        borderColor: paper,
                        borderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    cutout: '55%',
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                boxWidth: 10,
                                boxHeight: 10,
                                color: tickColor,
                                font: { family: 'IBM Plex Mono', size: 10 }
                            }
                        }
                    }
                }
            });
        }

        const catLabels = Object.keys(data.category_distribution);
        const catValues = Object.values(data.category_distribution);
        if (catLabels.length > 0) {
            new Chart(document.getElementById('categoryChart'), {
                type: 'bar',
                data: {
                    labels: catLabels.map(c => c.length > 20 ? c.substring(0, 20) + '...' : c),
                    datasets: [{
                        label: 'Findings',
                        data: catValues,
                        backgroundColor: catLabels.map((_, i) => i === 0 ? accent : ink),
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    indexAxis: 'y',
                    scales: {
                        x: { beginAtZero: true, grid: gridOpts, ticks: tickOpts },
                        y: { grid: { display: false }, ticks: tickOpts }
                    },
                    plugins: { legend: { display: false } }
                }
            });
        }

        const remLabels = Object.keys(data.remediation_status);
        const remValues = Object.values(data.remediation_status);
        const remColors = {
            'open': '#c8102e',
            'in_progress': '#b45309',
            'resolved': '#1b6b3a',
            'verified': '#1d4ed8'
        };
        if (remValues.some(v => v > 0)) {
            new Chart(document.getElementById('remediationChart'), {
                type: 'doughnut',
                data: {
                    labels: remLabels.map(s => s.charAt(0).toUpperCase() + s.slice(1).replace('_', ' ')),
                    datasets: [{
                        data: remValues,
                        backgroundColor: remLabels.map(s => remColors[s]),
                        borderColor: paper,
                        borderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    cutout: '55%',
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                boxWidth: 10,
                                boxHeight: 10,
                                color: tickColor,
                                font: { family: 'IBM Plex Mono', size: 10 }
                            }
                        }
                    }
                }
            });
        }
    });
});
