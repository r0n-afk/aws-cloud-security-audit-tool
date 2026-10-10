function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    sidebar.classList.toggle('show');
}

function toggleTheme() {
    const html = document.documentElement;
    const current = html.getAttribute('data-bs-theme');
    const next = current === 'light' ? 'dark' : 'light';

    html.setAttribute('data-bs-theme', next);
    updateThemeIcon(next);

    fetch('/settings/update-theme', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCsrfToken()
        },
        body: JSON.stringify({theme: next})
    });
}

function updateThemeIcon(theme) {
    const icon = document.getElementById('themeIcon');
    if (!icon) return;
    if (theme === 'dark') {
        icon.className = 'bi bi-sun-fill';
    } else {
        icon.className = 'bi bi-moon-fill';
    }
}

function getCsrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
}

function syncGatewayOptions() {
    const toggle = document.getElementById('aiEnabled');
    const panel = document.getElementById('gatewayOptions');
    if (!toggle || !panel) return;
    const open = toggle.checked;
    panel.classList.toggle('is-collapsed', !open);
    toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    panel.setAttribute('aria-hidden', open ? 'false' : 'true');
}

document.addEventListener('DOMContentLoaded', function() {
    const theme = document.documentElement.getAttribute('data-bs-theme');
    updateThemeIcon(theme);

    const aiToggle = document.getElementById('aiEnabled');
    if (aiToggle) {
        syncGatewayOptions();
        aiToggle.addEventListener('change', syncGatewayOptions);
    }

    document.querySelectorAll('.alert').forEach(function(alert) {
        if (alert.hasAttribute('data-permanent') || alert.classList.contains('alert-permanent')) {
            return;
        }
        setTimeout(function() {
            alert.classList.remove('show');
            alert.classList.add('fade');
        }, 5000);
    });
});
