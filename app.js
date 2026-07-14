const WORLD_SIZE = 1000;
const CARD_WIDTH = 46;
const CARD_HEIGHT = 54;
const CARD_MIN_PIXELS_PER_WORLD = 18;
const ENCRYPTED_DATA_URL = 'players.enc';
const DATA_AAD = 'server-2237-player-map';
const ALLIANCE_COLORS = [
    '#22d3ee', '#a78bfa', '#fb7185', '#fbbf24', '#34d399',
    '#60a5fa', '#f97316', '#e879f9', '#2dd4bf', '#a3e635',
    '#f472b6', '#38bdf8', '#c084fc', '#facc15', '#4ade80'
];

const state = {
    players: [],
    filtered: [],
    selectedUid: null,
    alliance: 'all',
    country: 'all',
    minLevel: null,
    maxLevel: null,
    query: '',
    colors: {},
    counts: {},
    view: { x: 0, y: 0, width: WORLD_SIZE, height: WORLD_SIZE },
    hitAreas: [],
    dragging: false,
    moved: false,
    dragStart: null,
    drawPending: false,
    metadata: null,
    password: null
};

const elements = {
    canvas: document.getElementById('world-map'),
    stage: document.getElementById('map-stage'),
    serverId: document.getElementById('server-id'),
    totalCount: document.getElementById('total-count'),
    visibleCount: document.getElementById('visible-count'),
    captureCount: document.getElementById('capture-count'),
    updateStatus: document.getElementById('update-status'),
    refreshData: document.getElementById('refresh-data'),
    search: document.getElementById('player-search'),
    allianceFilter: document.getElementById('alliance-filter'),
    countryFilter: document.getElementById('country-filter'),
    minLevelFilter: document.getElementById('min-level-filter'),
    maxLevelFilter: document.getElementById('max-level-filter'),
    legend: document.getElementById('alliance-legend'),
    selection: document.getElementById('player-selection'),
    results: document.getElementById('player-results'),
    resultCount: document.getElementById('result-count'),
    fitBases: document.getElementById('fit-bases'),
    fullMap: document.getElementById('full-map'),
    zoomIn: document.getElementById('zoom-in'),
    zoomOut: document.getElementById('zoom-out'),
    coordinates: document.getElementById('cursor-coordinates'),
    loading: document.getElementById('loading-overlay'),
    playerDialog: document.getElementById('player-dialog'),
    playerDialogContent: document.getElementById('player-dialog-content'),
    playerDialogClose: document.getElementById('player-dialog-close'),
    toast: document.getElementById('toast')
};

elements.mapApp = document.getElementById('map-app');
elements.authOverlay = document.getElementById('auth-overlay');
elements.authForm = document.getElementById('auth-form');
elements.authPassword = document.getElementById('auth-password');
elements.authSubmit = document.getElementById('auth-submit');
elements.authError = document.getElementById('auth-error');
elements.togglePassword = document.getElementById('toggle-password');

const context = elements.canvas.getContext('2d');

document.addEventListener('DOMContentLoaded', () => {
    bindEvents();
    bindAuthEvents();
    new ResizeObserver(() => resizeCanvas()).observe(elements.stage);
    if (document.fonts?.ready) document.fonts.ready.then(scheduleDraw);
});

function bindAuthEvents() {
    elements.authForm.addEventListener('submit', async event => {
        event.preventDefault();
        const password = elements.authPassword.value;
        if (!password) return;
        elements.authSubmit.disabled = true;
        elements.authError.textContent = '';
        try {
            const payload = await decryptPlayerData(password);
            state.password = password;
            loadPayload(payload);
            setLoading(false);
            elements.authPassword.value = '';
            elements.authOverlay.classList.add('hidden');
            elements.mapApp.classList.remove('locked');
            elements.mapApp.setAttribute('aria-hidden', 'false');
            requestAnimationFrame(() => {
                resizeCanvas();
                showFullMap();
            });
        } catch (error) {
            console.error(error);
            elements.authError.textContent = 'Incorrect password or invalid encrypted dataset.';
            elements.authPassword.select();
        } finally {
            elements.authSubmit.disabled = false;
        }
    });

    elements.togglePassword.addEventListener('click', () => {
        const showing = elements.authPassword.type === 'text';
        elements.authPassword.type = showing ? 'password' : 'text';
        elements.togglePassword.innerHTML = `<i class="fa-solid fa-${showing ? 'eye' : 'eye-slash'}"></i>`;
        elements.togglePassword.setAttribute('aria-label', showing ? 'Show password' : 'Hide password');
        elements.authPassword.focus();
    });
}

async function decryptPlayerData(password) {
    const response = await fetch(`${ENCRYPTED_DATA_URL}?cache=${Date.now()}`, { cache: 'no-store' });
    if (!response.ok) throw new Error(`Encrypted dataset HTTP ${response.status}`);
    const envelope = await response.json();
    if (envelope.version !== 1) throw new Error('Unsupported encrypted dataset version');

    const encoder = new TextEncoder();
    const passwordMaterial = await crypto.subtle.importKey(
        'raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']
    );
    const key = await crypto.subtle.deriveKey({
        name: 'PBKDF2',
        salt: base64ToBytes(envelope.salt),
        iterations: envelope.iterations,
        hash: 'SHA-256'
    }, passwordMaterial, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    const plaintext = await crypto.subtle.decrypt({
        name: 'AES-GCM',
        iv: base64ToBytes(envelope.iv),
        additionalData: encoder.encode(DATA_AAD)
    }, key, base64ToBytes(envelope.data));
    return JSON.parse(new TextDecoder().decode(plaintext));
}

async function reloadEncryptedData() {
    if (!state.password) return;
    setLoading(true, 'Reloading encrypted player data…');
    try {
        const payload = await decryptPlayerData(state.password);
        loadPayload(payload);
        showToast(`${formatNumber(state.players.length)} players loaded`);
    } catch (error) {
        console.error(error);
        showToast('Unable to reload the encrypted dataset');
    } finally {
        setLoading(false);
    }
}

function loadPayload(payload) {
    state.metadata = payload;
    state.players = (Array.isArray(payload) ? payload : payload.players || [])
        .filter(player => Number.isFinite(Number(player.x)) && Number.isFinite(Number(player.y)))
        .map(player => ({
            uid: String(player.uid),
            name: String(player.name || `Player ${String(player.uid).slice(-6)}`),
            alliance: String(player.alliance || 'No alliance'),
            level: Number(player.level) || null,
            country: String(player.country || '—'),
            server: Number(player.server) || null,
            x: Number(player.x),
            y: Number(player.y)
        }));

    buildAllianceData();
    populateFilters();
    applyFilters();
    renderMetadata();
}

function renderMetadata() {
    const servers = [...new Set(state.players.map(player => player.server).filter(Boolean))];
    elements.serverId.textContent = servers.join(', ') || '—';
    elements.totalCount.textContent = formatNumber(state.players.length);
    elements.captureCount.textContent = String(state.metadata?.captures?.length || 0);
    const generatedAt = state.metadata?.generated_at ? new Date(state.metadata.generated_at) : null;
    elements.updateStatus.textContent = generatedAt && !Number.isNaN(generatedAt.getTime())
        ? `Updated ${generatedAt.toLocaleString('en-US')}`
        : 'Data loaded';
}

function buildAllianceData() {
    state.counts = {};
    state.players.forEach(player => {
        state.counts[player.alliance] = (state.counts[player.alliance] || 0) + 1;
    });

    state.colors = {};
    Object.keys(state.counts)
        .sort((a, b) => state.counts[b] - state.counts[a] || a.localeCompare(b))
        .forEach((alliance, index) => {
            state.colors[alliance] = alliance === 'No alliance'
                ? '#64748b'
                : ALLIANCE_COLORS[index % ALLIANCE_COLORS.length];
        });
}

function populateFilters() {
    const alliances = Object.keys(state.counts)
        .sort((a, b) => state.counts[b] - state.counts[a] || a.localeCompare(b));

    elements.allianceFilter.innerHTML = '<option value="all">All alliances</option>' +
        alliances.map(alliance =>
            `<option value="${escapeHtml(alliance)}">${escapeHtml(alliance)} (${formatNumber(state.counts[alliance])})</option>`
        ).join('');
    elements.allianceFilter.value = alliances.includes(state.alliance) ? state.alliance : 'all';

    const countryCounts = {};
    state.players.forEach(player => {
        countryCounts[player.country] = (countryCounts[player.country] || 0) + 1;
    });
    const countries = Object.keys(countryCounts)
        .sort((a, b) => countryCounts[b] - countryCounts[a] || a.localeCompare(b));
    elements.countryFilter.innerHTML = '<option value="all">All countries</option>' +
        countries.map(country =>
            `<option value="${escapeHtml(country)}">${escapeHtml(country)} (${formatNumber(countryCounts[country])})</option>`
        ).join('');
    elements.countryFilter.value = countries.includes(state.country) ? state.country : 'all';

    const levels = [...new Set(state.players.map(player => player.level).filter(Number.isFinite))]
        .sort((a, b) => a - b);
    const levelOptions = levels.map(level => `<option value="${level}">Level ${level}</option>`).join('');
    elements.minLevelFilter.innerHTML = '<option value="all">Any</option>' + levelOptions;
    elements.maxLevelFilter.innerHTML = '<option value="all">Any</option>' + levelOptions;
    elements.minLevelFilter.value = state.minLevel !== null && levels.includes(state.minLevel)
        ? String(state.minLevel)
        : 'all';
    elements.maxLevelFilter.value = state.maxLevel !== null && levels.includes(state.maxLevel)
        ? String(state.maxLevel)
        : 'all';

    elements.legend.innerHTML = alliances.slice(0, 14).map(alliance => `
        <span class="legend-item">
            <span class="legend-dot" style="background:${state.colors[alliance]}"></span>
            ${escapeHtml(alliance)} · ${formatNumber(state.counts[alliance])}
        </span>
    `).join('');
}

function applyFilters() {
    const query = state.query.trim().toLocaleLowerCase('en-US');
    const coordinate = query.match(/^(\d{1,4})\s*[,x:]\s*(\d{1,4})$/i);

    state.filtered = state.players.filter(player => {
        if (state.alliance !== 'all' && player.alliance !== state.alliance) return false;
        if (state.country !== 'all' && player.country !== state.country) return false;
        if (state.minLevel !== null && (!Number.isFinite(player.level) || player.level < state.minLevel)) return false;
        if (state.maxLevel !== null && (!Number.isFinite(player.level) || player.level > state.maxLevel)) return false;
        if (!query) return true;
        if (coordinate) {
            return player.x === Number(coordinate[1]) && player.y === Number(coordinate[2]);
        }
        return [player.name, player.uid, player.alliance, player.country, `${player.x},${player.y}`]
            .some(value => String(value).toLocaleLowerCase('en-US').includes(query));
    });

    elements.visibleCount.textContent = formatNumber(state.filtered.length);
    elements.resultCount.textContent = formatNumber(state.filtered.length);
    renderResults();
    scheduleDraw();
}

function renderResults() {
    const limit = 120;
    elements.results.innerHTML = state.filtered.slice(0, limit).map(player => `
        <button class="result ${player.uid === state.selectedUid ? 'active' : ''}" data-uid="${escapeHtml(player.uid)}">
            <span class="result-dot" style="background:${state.colors[player.alliance]}"></span>
            <span class="result-name" title="${escapeHtml(player.name)}">${escapeHtml(player.name)}</span>
            <span class="result-meta">Lv.${player.level || '—'} · ${player.x},${player.y}</span>
        </button>
    `).join('') + (state.filtered.length > limit
        ? `<div class="results-more">+ ${formatNumber(state.filtered.length - limit)} players on the map</div>`
        : '');

    elements.results.querySelectorAll('.result').forEach(button => {
        button.addEventListener('click', () => selectPlayer(button.dataset.uid, true));
    });
}

function selectPlayer(uid, center) {
    const player = state.players.find(item => item.uid === uid);
    if (!player) return;
    state.selectedUid = uid;
    const color = state.colors[player.alliance];
    const detailsHtml = `
        <div class="player-title">
            <div class="player-name" title="${escapeHtml(player.name)}">${escapeHtml(player.name)}</div>
            <span class="alliance-badge" style="background:${color}">${escapeHtml(player.alliance)}</span>
        </div>
        <div class="player-data">
            <div><span>Coordinates</span><strong>${player.x}, ${player.y}</strong></div>
            <div><span>Level</span><strong>${player.level || '—'}</strong></div>
            <div><span>Country</span><strong>${escapeHtml(player.country)}</strong></div>
            <div><span>UID</span><strong title="${player.uid}">${escapeHtml(player.uid)}</strong></div>
        </div>
    `;
    elements.selection.innerHTML = detailsHtml;
    elements.playerDialogContent.innerHTML = detailsHtml;
    if (shouldUsePlayerDialog()) openPlayerDialog();
    if (center) centerAt(player.x, player.y, getDetailFocusWidth());
    renderResults();
    scheduleDraw();
}

function shouldUsePlayerDialog() {
    return window.matchMedia('(max-width: 700px), (max-height: 650px)').matches;
}

function openPlayerDialog() {
    elements.playerDialog.classList.add('open');
    elements.playerDialog.setAttribute('aria-hidden', 'false');
    requestAnimationFrame(() => elements.playerDialogClose.focus());
}

function closePlayerDialog() {
    elements.playerDialog.classList.remove('open');
    elements.playerDialog.setAttribute('aria-hidden', 'true');
}

function resizeCanvas() {
    const rect = elements.stage.getBoundingClientRect();
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const width = Math.max(1, Math.round(rect.width * dpr));
    const height = Math.max(1, Math.round(rect.height * dpr));
    if (elements.canvas.width !== width || elements.canvas.height !== height) {
        elements.canvas.width = width;
        elements.canvas.height = height;
        elements.canvas.style.width = `${rect.width}px`;
        elements.canvas.style.height = `${rect.height}px`;
        const view = state.view;
        setView(view.x, view.y, view.width, view.height);
    }
    scheduleDraw();
}

function setView(x, y, width, height) {
    const rect = elements.stage.getBoundingClientRect();
    const aspect = rect.width > 0 && rect.height > 0 ? rect.width / rect.height : 1;
    const centerX = x + width / 2;
    const centerY = y + height / 2;
    let nextWidth = Math.max(12, width);
    let nextHeight = Math.max(12 / aspect, height);

    if (nextWidth / nextHeight > aspect) nextHeight = nextWidth / aspect;
    else nextWidth = nextHeight * aspect;

    const maxWidth = aspect >= 1 ? WORLD_SIZE * aspect : WORLD_SIZE;
    const maxHeight = aspect >= 1 ? WORLD_SIZE : WORLD_SIZE / aspect;
    if (nextWidth > maxWidth || nextHeight > maxHeight) {
        nextWidth = maxWidth;
        nextHeight = maxHeight;
    }

    const minX = Math.min(0, WORLD_SIZE - nextWidth);
    const maxX = Math.max(0, WORLD_SIZE - nextWidth);
    const minY = Math.min(0, WORLD_SIZE - nextHeight);
    const maxY = Math.max(0, WORLD_SIZE - nextHeight);
    state.view = {
        x: clamp(centerX - nextWidth / 2, minX, maxX),
        y: clamp(centerY - nextHeight / 2, minY, maxY),
        width: nextWidth,
        height: nextHeight
    };
    scheduleDraw();
}

function showFullMap() {
    setView(0, 0, WORLD_SIZE, WORLD_SIZE);
}

function fitFiltered() {
    const players = state.filtered.length ? state.filtered : state.players;
    if (!players.length) return showFullMap();
    if (players.length === 1) {
        centerAt(players[0].x, players[0].y, getDetailFocusWidth());
        return;
    }
    const xs = players.map(player => player.x);
    const ys = players.map(player => player.y);
    const minX = Math.min(...xs);
    const maxX = Math.max(...xs);
    const minY = Math.min(...ys);
    const maxY = Math.max(...ys);
    const padding = players.length === 1 ? 28 : 18;
    setView(
        minX - padding,
        minY - padding,
        Math.max(38, maxX - minX + padding * 2),
        Math.max(38, maxY - minY + padding * 2)
    );
}

function centerAt(x, y, width) {
    const rect = elements.stage.getBoundingClientRect();
    const aspect = rect.width / rect.height || 1;
    const height = width / aspect;
    setView(x - width / 2, y - height / 2, width, height);
}

function isDetailedView(rect = elements.canvas.getBoundingClientRect()) {
    if (!rect.width || !rect.height) return false;
    const horizontalScale = rect.width / state.view.width;
    const verticalScale = rect.height / state.view.height;
    return Math.min(horizontalScale, verticalScale) >= CARD_MIN_PIXELS_PER_WORLD;
}

function getDetailFocusWidth() {
    const rect = elements.stage.getBoundingClientRect();
    const availableWidth = Math.max(1, rect.width);
    return Math.min(65, availableWidth / (CARD_MIN_PIXELS_PER_WORLD + 2));
}

function zoom(factor, clientX = null, clientY = null) {
    const rect = elements.canvas.getBoundingClientRect();
    const ratioX = clientX == null ? 0.5 : (clientX - rect.left) / rect.width;
    const ratioY = clientY == null ? 0.5 : (clientY - rect.top) / rect.height;
    const anchorX = state.view.x + state.view.width * ratioX;
    const anchorY = state.view.y + state.view.height * (1 - ratioY);
    const nextWidth = state.view.width * factor;
    const nextHeight = state.view.height * factor;
    setView(
        anchorX - nextWidth * ratioX,
        anchorY - nextHeight * (1 - ratioY),
        nextWidth,
        nextHeight
    );
}

function scheduleDraw() {
    if (state.drawPending) return;
    state.drawPending = true;
    requestAnimationFrame(() => {
        state.drawPending = false;
        drawMap();
    });
}

function drawMap() {
    const rect = elements.canvas.getBoundingClientRect();
    if (!rect.width || !rect.height) return;
    const dpr = elements.canvas.width / rect.width;
    context.setTransform(dpr, 0, 0, dpr, 0, 0);
    context.clearRect(0, 0, rect.width, rect.height);

    drawWorld(rect.width, rect.height);
    state.hitAreas = [];
    const detailed = isDetailedView(rect);
    const marginWorld = detailed ? CARD_HEIGHT / rect.height * state.view.height : 4;
    const visible = state.filtered.filter(player =>
        player.x >= state.view.x - marginWorld &&
        player.x <= state.view.x + state.view.width + marginWorld &&
        player.y >= state.view.y - marginWorld &&
        player.y <= state.view.y + state.view.height + marginWorld
    );
    visible.sort((a, b) => Number(a.uid === state.selectedUid) - Number(b.uid === state.selectedUid));

    if (detailed) visible.forEach(player => drawPlayerCard(player));
    else visible.forEach(player => drawPlayerDot(player));
}

function drawWorld(width, height) {
    const topLeft = worldToScreen(0, WORLD_SIZE);
    const bottomRight = worldToScreen(WORLD_SIZE, 0);
    context.fillStyle = '#060b15';
    context.fillRect(topLeft.x, topLeft.y, bottomRight.x - topLeft.x, bottomRight.y - topLeft.y);

    const minor = state.view.width < 350 ? 25 : 100;
    const major = 100;
    context.lineWidth = 1;

    for (let value = Math.max(0, Math.ceil(state.view.x / minor) * minor); value <= Math.min(WORLD_SIZE, state.view.x + state.view.width); value += minor) {
        const point = worldToScreen(value, 0);
        context.strokeStyle = value % major === 0 ? 'rgba(34,211,238,0.13)' : 'rgba(148,163,184,0.055)';
        context.beginPath(); context.moveTo(point.x, Math.max(0, topLeft.y)); context.lineTo(point.x, Math.min(height, bottomRight.y)); context.stroke();
    }
    for (let value = Math.max(0, Math.ceil(state.view.y / minor) * minor); value <= Math.min(WORLD_SIZE, state.view.y + state.view.height); value += minor) {
        const point = worldToScreen(0, value);
        context.strokeStyle = value % major === 0 ? 'rgba(34,211,238,0.13)' : 'rgba(148,163,184,0.055)';
        context.beginPath(); context.moveTo(Math.max(0, topLeft.x), point.y); context.lineTo(Math.min(width, bottomRight.x), point.y); context.stroke();
    }

    context.strokeStyle = 'rgba(34,211,238,0.3)';
    context.strokeRect(topLeft.x, topLeft.y, bottomRight.x - topLeft.x, bottomRight.y - topLeft.y);

    if (state.view.width < 500) {
        context.fillStyle = 'rgba(148,163,184,0.58)';
        context.font = '9px "Fira Code"';
        for (let value = Math.max(0, Math.ceil(state.view.x / major) * major); value <= Math.min(WORLD_SIZE, state.view.x + state.view.width); value += major) {
            const point = worldToScreen(value, 0);
            context.fillText(String(value), point.x + 4, Math.max(12, topLeft.y + 12));
        }
        for (let value = Math.max(0, Math.ceil(state.view.y / major) * major); value <= Math.min(WORLD_SIZE, state.view.y + state.view.height); value += major) {
            const point = worldToScreen(0, value);
            context.fillText(String(value), Math.max(4, topLeft.x + 4), point.y - 4);
        }
    }
}

function drawPlayerDot(player) {
    const point = worldToScreen(player.x, player.y);
    const selected = player.uid === state.selectedUid;
    const radius = selected ? 5 : 2.4;
    context.beginPath();
    context.arc(point.x, point.y, radius, 0, Math.PI * 2);
    context.fillStyle = state.colors[player.alliance];
    context.globalAlpha = player.alliance === 'No alliance' ? 0.62 : 0.88;
    context.fill();
    context.globalAlpha = 1;
    if (selected) {
        context.lineWidth = 2;
        context.strokeStyle = '#ffffff';
        context.stroke();
    }
    state.hitAreas.push({ uid: player.uid, type: 'dot', x: point.x, y: point.y, radius: Math.max(7, radius) });
}

function drawPlayerCard(player) {
    const anchor = worldToScreen(player.x, player.y);
    const left = Math.round(anchor.x - CARD_WIDTH / 2);
    const top = Math.round(anchor.y - CARD_HEIGHT - 3);
    const color = state.colors[player.alliance];
    const selected = player.uid === state.selectedUid;

    context.save();
    if (selected) {
        context.shadowColor = color;
        context.shadowBlur = 14;
    }
    roundedRect(context, left, top, CARD_WIDTH, CARD_HEIGHT, 5);
    context.fillStyle = 'rgba(7, 15, 27, 0.96)';
    context.fill();
    context.lineWidth = selected ? 2 : 1;
    context.strokeStyle = color;
    context.stroke();
    context.restore();

    roundedRect(context, left + 3, top + 3, CARD_WIDTH - 6, 13, 3);
    context.fillStyle = colorWithAlpha(color, 0.28);
    context.fill();
    context.fillStyle = '#f8fafc';
    context.font = '700 7px "Fira Code"';
    context.textAlign = 'center';
    context.textBaseline = 'middle';
    context.fillText(truncate(player.name, 10), left + CARD_WIDTH / 2, top + 9.5);

    context.beginPath();
    context.moveTo(left + 10, top + 34);
    context.lineTo(left + CARD_WIDTH / 2, top + 19);
    context.lineTo(left + CARD_WIDTH - 10, top + 34);
    context.lineTo(left + CARD_WIDTH - 14, top + 43);
    context.lineTo(left + 14, top + 43);
    context.closePath();
    context.fillStyle = '#1b293b';
    context.fill();
    context.lineWidth = 1.2;
    context.strokeStyle = '#70839a';
    context.stroke();

    roundedRect(context, left + 15, top + 26, CARD_WIDTH - 30, 13, 2);
    context.fillStyle = '#dce6f1';
    context.fill();
    context.strokeStyle = '#7a8da3';
    context.stroke();
    context.fillStyle = '#172033';
    context.font = '700 10px "Fira Code"';
    context.fillText(String(player.level || '?'), left + CARD_WIDTH / 2, top + 32.8);

    context.fillStyle = '#22d3ee';
    context.font = '700 7px "Fira Code"';
    context.fillText(`${player.x},${player.y}`, left + CARD_WIDTH / 2, top + 49);

    state.hitAreas.push({ uid: player.uid, type: 'card', left, top, width: CARD_WIDTH, height: CARD_HEIGHT });
}

function roundedRect(ctx, x, y, width, height, radius) {
    const r = Math.min(radius, width / 2, height / 2);
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.arcTo(x + width, y, x + width, y + height, r);
    ctx.arcTo(x + width, y + height, x, y + height, r);
    ctx.arcTo(x, y + height, x, y, r);
    ctx.arcTo(x, y, x + width, y, r);
    ctx.closePath();
}

function findPlayerAt(clientX, clientY) {
    const rect = elements.canvas.getBoundingClientRect();
    const x = clientX - rect.left;
    const y = clientY - rect.top;
    for (let index = state.hitAreas.length - 1; index >= 0; index--) {
        const hit = state.hitAreas[index];
        if (hit.type === 'card') {
            if (x >= hit.left && x <= hit.left + hit.width && y >= hit.top && y <= hit.top + hit.height) return hit.uid;
        } else if (Math.hypot(x - hit.x, y - hit.y) <= hit.radius) {
            return hit.uid;
        }
    }
    return null;
}

function worldToScreen(x, y) {
    const rect = elements.canvas.getBoundingClientRect();
    return {
        x: (x - state.view.x) / state.view.width * rect.width,
        y: (state.view.y + state.view.height - y) / state.view.height * rect.height
    };
}

function clientToWorld(clientX, clientY) {
    const rect = elements.canvas.getBoundingClientRect();
    return {
        x: state.view.x + (clientX - rect.left) / rect.width * state.view.width,
        y: state.view.y + (1 - (clientY - rect.top) / rect.height) * state.view.height
    };
}

function bindEvents() {
    elements.refreshData.addEventListener('click', reloadEncryptedData);
    elements.playerDialogClose.addEventListener('click', closePlayerDialog);
    elements.playerDialog.addEventListener('click', event => {
        if (event.target === elements.playerDialog) closePlayerDialog();
    });
    document.addEventListener('keydown', event => {
        if (event.key === 'Escape' && elements.playerDialog.classList.contains('open')) {
            closePlayerDialog();
        }
    });
    window.addEventListener('resize', () => {
        if (!shouldUsePlayerDialog()) closePlayerDialog();
    });
    elements.search.addEventListener('input', event => {
        state.query = event.target.value;
        applyFilters();
    });
    elements.allianceFilter.addEventListener('change', event => {
        state.alliance = event.target.value;
        applyFilters();
        fitFiltered();
    });
    elements.countryFilter.addEventListener('change', event => {
        state.country = event.target.value;
        applyFilters();
        fitFiltered();
    });
    elements.minLevelFilter.addEventListener('change', event => {
        state.minLevel = event.target.value === 'all' ? null : Number(event.target.value);
        if (state.minLevel !== null && state.maxLevel !== null && state.minLevel > state.maxLevel) {
            state.maxLevel = state.minLevel;
            elements.maxLevelFilter.value = String(state.maxLevel);
        }
        applyFilters();
    });
    elements.maxLevelFilter.addEventListener('change', event => {
        state.maxLevel = event.target.value === 'all' ? null : Number(event.target.value);
        if (state.minLevel !== null && state.maxLevel !== null && state.maxLevel < state.minLevel) {
            state.minLevel = state.maxLevel;
            elements.minLevelFilter.value = String(state.minLevel);
        }
        applyFilters();
    });
    elements.fitBases.addEventListener('click', fitFiltered);
    elements.fullMap.addEventListener('click', showFullMap);
    elements.zoomIn.addEventListener('click', () => zoom(0.72));
    elements.zoomOut.addEventListener('click', () => zoom(1.38));

    elements.canvas.addEventListener('wheel', event => {
        event.preventDefault();
        zoom(event.deltaY < 0 ? 0.82 : 1.22, event.clientX, event.clientY);
    }, { passive: false });

    elements.canvas.addEventListener('pointerdown', event => {
        if (event.button !== 0) return;
        state.dragging = true;
        state.moved = false;
        state.dragStart = {
            clientX: event.clientX,
            clientY: event.clientY,
            view: { ...state.view }
        };
        elements.stage.classList.add('dragging');
        elements.canvas.setPointerCapture(event.pointerId);
    });

    elements.canvas.addEventListener('pointermove', event => {
        const world = clientToWorld(event.clientX, event.clientY);
        elements.coordinates.textContent = `X ${Math.round(world.x)}   Y ${Math.round(world.y)}`;
        if (!state.dragging || !state.dragStart) return;
        const rect = elements.canvas.getBoundingClientRect();
        const start = state.dragStart;
        const dxPixels = event.clientX - start.clientX;
        const dyPixels = event.clientY - start.clientY;
        if (Math.hypot(dxPixels, dyPixels) > 3) state.moved = true;
        setView(
            start.view.x - dxPixels / rect.width * start.view.width,
            start.view.y + dyPixels / rect.height * start.view.height,
            start.view.width,
            start.view.height
        );
    });

    const finishPointer = event => {
        if (!state.dragging) return;
        const wasMoved = state.moved;
        state.dragging = false;
        state.dragStart = null;
        elements.stage.classList.remove('dragging');
        if (elements.canvas.hasPointerCapture(event.pointerId)) elements.canvas.releasePointerCapture(event.pointerId);
        if (!wasMoved) {
            const uid = findPlayerAt(event.clientX, event.clientY);
            if (uid) selectPlayer(uid, !isDetailedView());
        }
    };
    elements.canvas.addEventListener('pointerup', finishPointer);
    elements.canvas.addEventListener('pointercancel', finishPointer);
}

function setLoading(isLoading, message = '') {
    elements.refreshData.disabled = isLoading;
    elements.loading.classList.toggle('hidden', !isLoading);
    if (message) elements.loading.querySelector('span').textContent = message;
}

function showToast(message) {
    elements.toast.textContent = message;
    elements.toast.classList.add('show');
    clearTimeout(showToast.timeout);
    showToast.timeout = setTimeout(() => elements.toast.classList.remove('show'), 2400);
}

function colorWithAlpha(hex, alpha) {
    const value = hex.replace('#', '');
    const number = parseInt(value, 16);
    return `rgba(${(number >> 16) & 255},${(number >> 8) & 255},${number & 255},${alpha})`;
}

function base64ToBytes(value) {
    const binary = atob(value);
    return Uint8Array.from(binary, character => character.charCodeAt(0));
}

function truncate(value, length) {
    const characters = Array.from(String(value));
    return characters.length > length ? `${characters.slice(0, length - 1).join('')}…` : characters.join('');
}

function escapeHtml(value) {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function formatNumber(value) {
    return new Intl.NumberFormat('en-US').format(value || 0);
}

function clamp(value, minimum, maximum) {
    return Math.max(minimum, Math.min(maximum, value));
}
