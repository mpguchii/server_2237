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
const LAYER_COLORS = {
    resources: '#34d399',
    tasks: '#e879f9',
    trucks: '#f97316',
    marches: '#60a5fa',
    cities: '#fbbf24',
    marks: '#fb7185'
};
const RESOURCE_COLORS = {
    Coin: '#fbbf24',
    Iron: '#60a5fa',
    Food: '#34d399',
    Special: '#a78bfa'
};
const ITEM_NAMES = {
    '2270000': 'Universal UR Hero Shard',
    '200363': 'Pressure Pump I',
    '200364': 'Wind Drive I'
};
const UNIVERSAL_UR_SHARD_ID = '2270000';
const DETAIL_LAYERS = new Set(['players', 'resources', 'tasks', 'trucks']);

const state = {
    players: [],
    filtered: [],
    resources: [],
    tasks: [],
    trucks: [],
    marches: [],
    cities: [],
    marks: [],
    layers: { players: true, resources: false, tasks: true, trucks: true, marches: false, cities: true, marks: false },
    selected: null,
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
    activePointers: new Map(),
    pinching: false,
    pinchStart: null,
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
    truckLootResults: document.getElementById('truck-loot-results'),
    truckLootCount: document.getElementById('truck-loot-count'),
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

elements.dialogEyebrow = document.getElementById('player-dialog-eyebrow');
elements.dialogTitle = document.getElementById('player-dialog-title');
elements.layerInputs = [...document.querySelectorAll('[data-layer]')];
elements.layerCounts = Object.fromEntries(
    Object.keys(state.layers).map(layer => [layer, document.getElementById(`layer-count-${layer}`)])
);

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

    state.resources = normalizePoints(payload.resources, item => ({
        ...item,
        id: String(item.id ?? item.point_id ?? ''),
        category: normalizeResourceCategory(item.category, item.cfg_id),
        level: numericOrNull(item.level),
        occupied: Boolean(item.occupied),
        x: Number(item.x), y: Number(item.y)
    }));
    state.tasks = normalizePoints(payload.tasks, item => ({
        ...item,
        id: String(item.id ?? item.task_id ?? `${item.x}:${item.y}`),
        task_type: String(item.task_type || item.kind || 'Dispatch'),
        x: Number(item.x), y: Number(item.y)
    }));
    state.trucks = normalizePoints(payload.trucks, normalizeMarch);
    state.marches = normalizePoints(payload.marches, normalizeMarch);
    state.cities = normalizePoints(payload.cities, item => ({
        ...item,
        id: String(item.id ?? item.city_id ?? `${item.x}:${item.y}`),
        alliance: String(item.alliance || item.alliance_name || 'No alliance'),
        x: Number(item.x), y: Number(item.y)
    }));
    state.marks = normalizePoints(payload.marks, item => ({
        ...item,
        id: String(item.id ?? item.mark_id ?? `${item.x}:${item.y}`),
        x: Number(item.x), y: Number(item.y)
    }));

    buildAllianceData();
    populateFilters();
    applyFilters();
    renderBestTruckLoot();
    renderMetadata();
}

function normalizeResourceCategory(category, cfgId) {
    const legacyNames = { A: 'Coin', B: 'Iron', C: 'Food', D: 'Special' };
    const value = String(category || '');
    if (legacyNames[value]) return legacyNames[value];
    if (RESOURCE_COLORS[value]) return value;

    const baseId = Math.abs(Number(cfgId) || 0) % 1000;
    if (baseId >= 1 && baseId <= 10) return 'Coin';
    if (baseId >= 101 && baseId <= 110) return 'Iron';
    if (baseId >= 201 && baseId <= 210) return 'Food';
    if (baseId >= 301 && baseId <= 310) return 'Special';
    return 'Resource';
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
    for (const layer of Object.keys(state.layers)) {
        if (elements.layerCounts[layer]) elements.layerCounts[layer].textContent = formatNumber(layerItems(layer).length);
    }
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
        <button class="result ${isSelected('players', player.uid) ? 'active' : ''}" data-uid="${escapeHtml(player.uid)}">
            <span class="result-dot" style="background:${state.colors[player.alliance]}"></span>
            <span class="result-name" title="${escapeHtml(player.name)}">${escapeHtml(player.name)}</span>
            <span class="result-meta">Lv.${player.level || '—'} · ${player.x},${player.y}</span>
        </button>
    `).join('') + (state.filtered.length > limit
        ? `<div class="results-more">+ ${formatNumber(state.filtered.length - limit)} players on the map</div>`
        : '');

    elements.results.querySelectorAll('.result').forEach(button => {
        button.addEventListener('click', event => {
            selectEntity('players', button.dataset.uid, true, event.pointerType === 'touch');
        });
    });
}

function renderBestTruckLoot() {
    const ranked = state.trucks
        .map(truck => ({ truck, shards: universalUrShardCount(truck) }))
        .filter(entry => entry.shards > 0)
        .sort((a, b) => b.shards - a.shards ||
            (Number(b.truck.level) || 0) - (Number(a.truck.level) || 0) ||
            String(a.truck.name || '').localeCompare(String(b.truck.name || '')));
    const limit = 100;
    elements.truckLootCount.textContent = `${formatNumber(ranked.length)} trucks`;
    elements.truckLootResults.innerHTML = ranked.slice(0, limit).map((entry, index) => {
        const truck = entry.truck;
        const loot = formatGoods(truckGoods(truck));
        return `
            <button class="loot-result ${isSelected('trucks', truck.id) ? 'active' : ''}"
                    data-truck-id="${escapeHtml(truck.id)}" title="${escapeHtml(loot)}">
                <span class="loot-rank">#${index + 1}</span>
                <span class="loot-truck">
                    <strong>${escapeHtml(truck.name || `Truck ${truck.id}`)}</strong>
                    <small>Lv.${truck.level || '—'} · ${formatCoordinate(truck.x)},${formatCoordinate(truck.y)}</small>
                </span>
                <span class="ur-shard-badge"><i class="fa-solid fa-star"></i>${formatNumber(entry.shards)} UR</span>
            </button>`;
    }).join('') + (ranked.length > limit
        ? `<div class="results-more">+ ${formatNumber(ranked.length - limit)} trucks with UR shards</div>`
        : '');

    elements.truckLootResults.querySelectorAll('.loot-result').forEach(button => {
        button.addEventListener('click', event => {
            if (!state.layers.trucks) {
                state.layers.trucks = true;
                const input = elements.layerInputs.find(item => item.dataset.layer === 'trucks');
                if (input) input.checked = true;
            }
            selectEntity('trucks', button.dataset.truckId, true, event.pointerType === 'touch');
        });
    });
}

function selectEntity(layer, id, center, forceDialog = false) {
    if (!DETAIL_LAYERS.has(layer)) return;
    const item = findEntity(layer, id);
    if (!item) return;
    state.selected = { layer, id: entityId(layer, item) };
    const details = entityDetails(layer, item);
    const detailsHtml = `
        <div class="player-title">
            <div class="player-name" title="${escapeHtml(details.title)}">${escapeHtml(details.title)}</div>
            <span class="alliance-badge" style="background:${details.color}">${escapeHtml(details.badge)}</span>
        </div>
        <div class="player-data">${details.rows.map(row => detailRow(row[0], row[1], row[2])).join('')}</div>
        ${details.note ? `<p class="entity-note">${escapeHtml(details.note)}</p>` : ''}
    `;
    elements.selection.innerHTML = detailsHtml;
    elements.playerDialogContent.innerHTML = detailsHtml;
    elements.dialogEyebrow.textContent = details.eyebrow;
    elements.dialogTitle.textContent = details.dialogTitle;
    if (forceDialog || shouldUsePlayerDialog()) openPlayerDialog();
    if (center) centerAt(Number(item.x), Number(item.y), getDetailFocusWidth());
    renderResults();
    renderBestTruckLoot();
    scheduleDraw();
}

function entityDetails(layer, item) {
    const coordinates = `${formatCoordinate(item.x)}, ${formatCoordinate(item.y)}`;
    if (layer === 'players') return {
        title: item.name, badge: item.alliance, color: state.colors[item.alliance] || '#64748b',
        eyebrow: 'Selected base', dialogTitle: 'Player details',
        rows: [['Coordinates', coordinates], ['Level', item.level || '—'], ['Country', item.country], ['UID', item.uid]]
    };
    if (layer === 'resources') return {
        title: `${item.category} resource`, badge: item.occupied ? 'Occupied' : 'Free',
        color: RESOURCE_COLORS[item.category] || LAYER_COLORS.resources,
        eyebrow: 'Selected resource', dialogTitle: 'Resource details',
        rows: [['Coordinates', coordinates], ['Level', item.level || '—'], ['Status', item.occupied ? 'Occupied' : 'Available'],
            ['Gatherer', item.owner_name || item.gatherer_name || (item.occupied ? 'Unknown player' : 'Unoccupied'), true],
            ['Alliance', item.owner_alliance || item.alliance || '—'], ['Config ID', item.cfg_id || '—']]
    };
    if (layer === 'tasks') return {
        title: item.owner_name || item.player_name || 'Unassigned task', badge: item.task_type || 'Task', color: LAYER_COLORS.tasks,
        eyebrow: 'Selected task', dialogTitle: 'Task details',
        rows: [['Coordinates', coordinates], ['Type', item.task_type || 'Dispatch'], ['Config ID', item.cfg_id || '—'],
            ['Alliance', item.owner_alliance || item.alliance || '—'], ['Heroes', listCount(item.hero_ids || item.heroes)], ['Expires', formatTimestamp(item.expires_at)]],
        note: formatGoods(item.rewards || item.goods)
    };
    if (layer === 'trucks') return {
        title: item.name || item.owner_name || `Truck ${item.id}`, badge: 'Truck', color: LAYER_COLORS.trucks,
        eyebrow: 'Selected truck', dialogTitle: 'Truck details',
        rows: [['Current position', coordinates], ['Route', formatRoute(item)], ['Base level', item.level || item.base_level || '—'],
            ['Power', formatPower(item.power)], ['Alliance', item.alliance || '—'], ['Country', item.country || '—'],
            ['Heroes', listCount(item.heroes)], ['Arrives', formatTimestamp(item.arrive_at)], ['Owner UID', item.owner_uid || '—']],
        note: formatGoods(truckGoods(item))
    };
    return null;
}

function shouldUsePlayerDialog() {
    return navigator.maxTouchPoints > 0 ||
        window.matchMedia('(pointer: coarse)').matches ||
        window.matchMedia('(max-width: 700px), (max-height: 650px)').matches;
}

function openPlayerDialog() {
    elements.playerDialog.classList.add('open');
    // Keep the modal visible even if the browser temporarily reuses an older
    // stylesheet while GitHub Pages is rolling out a new deployment.
    elements.playerDialog.style.display = 'flex';
    elements.playerDialog.setAttribute('aria-hidden', 'false');
    requestAnimationFrame(() => elements.playerDialogClose.focus());
}

function closePlayerDialog() {
    elements.playerDialog.classList.remove('open');
    elements.playerDialog.style.removeProperty('display');
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

function fitVisibleLayers() {
    const points = [];
    for (const layer of Object.keys(state.layers)) {
        if (!state.layers[layer]) continue;
        const items = layer === 'players' ? state.filtered : layerItems(layer);
        items.forEach(item => {
            points.push({ x: Number(item.x), y: Number(item.y) });
            if (item.start && Number.isFinite(Number(item.start.x))) points.push({ x: Number(item.start.x), y: Number(item.start.y) });
            if (item.end && Number.isFinite(Number(item.end.x))) points.push({ x: Number(item.end.x), y: Number(item.end.y) });
        });
    }
    if (!points.length) return showFullMap();
    if (points.length === 1) {
        centerAt(points[0].x, points[0].y, getDetailFocusWidth());
        return;
    }
    const xs = points.map(point => point.x);
    const ys = points.map(point => point.y);
    const minX = Math.min(...xs);
    const maxX = Math.max(...xs);
    const minY = Math.min(...ys);
    const maxY = Math.max(...ys);
    const padding = 18;
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
    if (state.layers.resources) visibleItems('resources', marginWorld).forEach(item => drawResource(item, detailed));
    if (state.layers.cities) visibleItems('cities', marginWorld).forEach(item => drawCity(item, detailed));
    if (state.layers.marks) visibleItems('marks', marginWorld).forEach(item => drawMapMarker(item, 'marks', 'M', LAYER_COLORS.marks, detailed));
    if (state.layers.tasks) visibleItems('tasks', marginWorld).forEach(item => drawMapMarker(item, 'tasks', '!', LAYER_COLORS.tasks, detailed));
    if (state.layers.marches) visibleItems('marches', marginWorld).forEach(item => drawMovingEntity(item, 'marches', detailed));
    if (state.layers.trucks) visibleItems('trucks', marginWorld).forEach(item => drawMovingEntity(item, 'trucks', detailed));

    if (state.layers.players) {
        const visible = visibleItems('players', marginWorld);
        visible.sort((a, b) => Number(isSelected('players', a.uid)) - Number(isSelected('players', b.uid)));
        if (detailed) visible.forEach(player => drawPlayerCard(player));
        else visible.forEach(player => drawPlayerDot(player));
    }
}

function visibleItems(layer, marginWorld = 4) {
    const items = layer === 'players' ? state.filtered : layerItems(layer);
    return items.filter(item =>
        item.x >= state.view.x - marginWorld && item.x <= state.view.x + state.view.width + marginWorld &&
        item.y >= state.view.y - marginWorld && item.y <= state.view.y + state.view.height + marginWorld
    );
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
    const selected = isSelected('players', player.uid);
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
    state.hitAreas.push({ layer: 'players', id: player.uid, type: 'dot', x: point.x, y: point.y, radius: Math.max(7, radius) });
}

function drawPlayerCard(player) {
    const anchor = worldToScreen(player.x, player.y);
    const left = Math.round(anchor.x - CARD_WIDTH / 2);
    const top = Math.round(anchor.y - CARD_HEIGHT - 3);
    const color = state.colors[player.alliance];
    const selected = isSelected('players', player.uid);

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

    state.hitAreas.push({ layer: 'players', id: player.uid, type: 'card', left, top, width: CARD_WIDTH, height: CARD_HEIGHT });
}

function drawResource(item, detailed) {
    const color = RESOURCE_COLORS[item.category] || LAYER_COLORS.resources;
    const point = worldToScreen(item.x, item.y);
    const selected = isSelected('resources', item.id);
    const size = detailed ? 6 : 3;
    context.save();
    context.translate(point.x, point.y);
    context.rotate(Math.PI / 4);
    context.fillStyle = colorWithAlpha(color, item.occupied ? 0.95 : 0.62);
    context.fillRect(-size, -size, size * 2, size * 2);
    if (selected) {
        context.lineWidth = 2;
        context.strokeStyle = '#ffffff';
        context.strokeRect(-size - 1, -size - 1, size * 2 + 2, size * 2 + 2);
    }
    context.restore();
    if (detailed) drawMarkerLabel(point.x, point.y - 10, `${item.category}${item.level || ''}`, color);
    pushPointHit('resources', item.id, point, Math.max(8, size + 3));
}

function drawCity(item, detailed) {
    const color = state.colors[item.alliance] || LAYER_COLORS.cities;
    const point = worldToScreen(item.x, item.y);
    const selected = isSelected('cities', item.id);
    const radius = detailed ? 9 : 4.5;
    context.beginPath();
    for (let index = 0; index < 6; index++) {
        const angle = Math.PI / 6 + index * Math.PI / 3;
        const x = point.x + Math.cos(angle) * radius;
        const y = point.y + Math.sin(angle) * radius;
        index ? context.lineTo(x, y) : context.moveTo(x, y);
    }
    context.closePath();
    context.fillStyle = colorWithAlpha(color, 0.7);
    context.fill();
    context.lineWidth = selected ? 2.5 : 1;
    context.strokeStyle = selected ? '#ffffff' : color;
    context.stroke();
    if (detailed) drawMarkerLabel(point.x, point.y - 14, truncate(item.alliance || item.name || 'City', 10), color);
    pushPointHit('cities', item.id, point, Math.max(10, radius + 2));
}

function drawMapMarker(item, layer, glyph, color, detailed) {
    const point = worldToScreen(item.x, item.y);
    const selected = isSelected(layer, item.id);
    const radius = detailed ? 7 : 3.5;
    context.beginPath();
    context.arc(point.x, point.y, radius, 0, Math.PI * 2);
    context.fillStyle = colorWithAlpha(color, 0.78);
    context.fill();
    context.lineWidth = selected ? 2.5 : 1;
    context.strokeStyle = selected ? '#ffffff' : color;
    context.stroke();
    if (detailed) {
        context.fillStyle = '#07101c';
        context.font = '700 8px "Fira Code"';
        context.textAlign = 'center';
        context.textBaseline = 'middle';
        context.fillText(glyph, point.x, point.y + 0.5);
    }
    pushPointHit(layer, item.id, point, Math.max(8, radius + 2));
}

function drawMovingEntity(item, layer, detailed) {
    const color = LAYER_COLORS[layer];
    drawRoute(item, color);
    const point = worldToScreen(item.x, item.y);
    const selected = isSelected(layer, item.id);
    const width = detailed ? 13 : 7;
    const height = detailed ? 8 : 5;
    context.save();
    context.translate(point.x, point.y);
    const start = item.start || {};
    const end = item.end || {};
    if (Number.isFinite(Number(start.x)) && Number.isFinite(Number(end.x))) {
        const screenStart = worldToScreen(Number(start.x), Number(start.y));
        const screenEnd = worldToScreen(Number(end.x), Number(end.y));
        context.rotate(Math.atan2(screenEnd.y - screenStart.y, screenEnd.x - screenStart.x));
    }
    roundedRect(context, -width / 2, -height / 2, width, height, 2);
    context.fillStyle = colorWithAlpha(color, 0.9);
    context.fill();
    context.lineWidth = selected ? 2 : 1;
    context.strokeStyle = selected ? '#ffffff' : color;
    context.stroke();
    context.restore();
    if (detailed && layer === 'trucks') drawMarkerLabel(point.x, point.y - 10, truncate(item.name || item.owner_name || 'Truck', 9), color);
    pushPointHit(layer, item.id, point, Math.max(9, width / 2 + 2));
}

function drawRoute(item, color) {
    if (!item.start || !item.end) return;
    if (![item.start.x, item.start.y, item.end.x, item.end.y].every(value => Number.isFinite(Number(value)))) return;
    const start = worldToScreen(Number(item.start.x), Number(item.start.y));
    const end = worldToScreen(Number(item.end.x), Number(item.end.y));
    context.beginPath();
    context.moveTo(start.x, start.y);
    context.lineTo(end.x, end.y);
    context.strokeStyle = colorWithAlpha(color, 0.2);
    context.lineWidth = 1;
    context.stroke();
}

function drawMarkerLabel(x, y, text, color) {
    context.font = '700 7px "Fira Code"';
    context.textAlign = 'center';
    context.textBaseline = 'middle';
    const width = context.measureText(text).width + 6;
    roundedRect(context, x - width / 2, y - 5, width, 10, 2);
    context.fillStyle = 'rgba(7,15,27,0.9)';
    context.fill();
    context.strokeStyle = colorWithAlpha(color, 0.7);
    context.stroke();
    context.fillStyle = '#f8fafc';
    context.fillText(text, x, y);
}

function pushPointHit(layer, id, point, radius) {
    if (!DETAIL_LAYERS.has(layer)) return;
    state.hitAreas.push({ layer, id: String(id), type: 'dot', x: point.x, y: point.y, radius });
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

function findEntityAt(clientX, clientY) {
    const rect = elements.canvas.getBoundingClientRect();
    const x = clientX - rect.left;
    const y = clientY - rect.top;
    for (let index = state.hitAreas.length - 1; index >= 0; index--) {
        const hit = state.hitAreas[index];
        if (hit.type === 'card') {
            if (x >= hit.left && x <= hit.left + hit.width && y >= hit.top && y <= hit.top + hit.height) return hit;
        } else if (Math.hypot(x - hit.x, y - hit.y) <= hit.radius) {
            return hit;
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
    // Use pointerdown instead of click. On touch screens the canvas opens the
    // dialog on pointerup; a following synthetic click can otherwise land on
    // the newly shown backdrop and close it immediately.
    elements.playerDialog.addEventListener('pointerdown', event => {
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
    elements.layerInputs.forEach(input => {
        input.addEventListener('change', event => {
            const layer = event.target.dataset.layer;
            state.layers[layer] = event.target.checked;
            if (!state.layers[layer] && state.selected?.layer === layer) clearSelection();
            scheduleDraw();
        });
    });
    elements.search.addEventListener('input', event => {
        state.query = event.target.value;
        applyFilters();
    });
    elements.allianceFilter.addEventListener('change', event => {
        state.alliance = event.target.value;
        applyFilters();
        fitVisibleLayers();
    });
    elements.countryFilter.addEventListener('change', event => {
        state.country = event.target.value;
        applyFilters();
        fitVisibleLayers();
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
    elements.fitBases.addEventListener('click', fitVisibleLayers);
    elements.fullMap.addEventListener('click', showFullMap);
    elements.zoomIn.addEventListener('click', () => zoom(0.72));
    elements.zoomOut.addEventListener('click', () => zoom(1.38));

    elements.canvas.addEventListener('wheel', event => {
        event.preventDefault();
        zoom(event.deltaY < 0 ? 0.82 : 1.22, event.clientX, event.clientY);
    }, { passive: false });

    elements.canvas.addEventListener('pointerdown', event => {
        if (event.pointerType !== 'touch' && event.button !== 0) return;
        event.preventDefault();
        state.activePointers.set(event.pointerId, { x: event.clientX, y: event.clientY });
        elements.stage.classList.add('dragging');
        elements.canvas.setPointerCapture(event.pointerId);

        if (state.activePointers.size === 1) {
            state.dragging = true;
            state.moved = false;
            state.dragStart = {
                clientX: event.clientX,
                clientY: event.clientY,
                view: { ...state.view }
            };
        } else if (state.activePointers.size === 2) {
            startPinchGesture();
        }
    });

    elements.canvas.addEventListener('pointermove', event => {
        const world = clientToWorld(event.clientX, event.clientY);
        elements.coordinates.textContent = `X ${Math.round(world.x)}   Y ${Math.round(world.y)}`;
        if (state.activePointers.has(event.pointerId)) {
            event.preventDefault();
            state.activePointers.set(event.pointerId, { x: event.clientX, y: event.clientY });
        }

        if (state.pinching && state.activePointers.size >= 2 && state.pinchStart) {
            const [first, second] = [...state.activePointers.values()];
            const distance = Math.max(1, Math.hypot(second.x - first.x, second.y - first.y));
            const centerX = (first.x + second.x) / 2;
            const centerY = (first.y + second.y) / 2;
            const rect = elements.canvas.getBoundingClientRect();
            const ratioX = (centerX - rect.left) / rect.width;
            const ratioY = (centerY - rect.top) / rect.height;
            const factor = state.pinchStart.distance / distance;
            const nextWidth = state.pinchStart.view.width * factor;
            const nextHeight = state.pinchStart.view.height * factor;
            setView(
                state.pinchStart.anchor.x - nextWidth * ratioX,
                state.pinchStart.anchor.y - nextHeight * (1 - ratioY),
                nextWidth,
                nextHeight
            );
            return;
        }

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

    const finishPointer = (event, cancelled = false) => {
        if (!state.activePointers.has(event.pointerId)) return;
        const wasMoved = state.moved;
        state.activePointers.delete(event.pointerId);
        if (elements.canvas.hasPointerCapture(event.pointerId)) elements.canvas.releasePointerCapture(event.pointerId);

        if (state.pinching) {
            if (state.activePointers.size >= 2) {
                startPinchGesture();
            } else if (state.activePointers.size === 1) {
                const [remaining] = state.activePointers.values();
                state.pinching = false;
                state.pinchStart = null;
                state.dragging = true;
                state.moved = true;
                state.dragStart = {
                    clientX: remaining.x,
                    clientY: remaining.y,
                    view: { ...state.view }
                };
            } else {
                state.pinching = false;
                state.pinchStart = null;
                state.dragging = false;
                state.dragStart = null;
                elements.stage.classList.remove('dragging');
            }
            return;
        }

        if (state.activePointers.size === 0) {
            state.dragging = false;
            state.dragStart = null;
            elements.stage.classList.remove('dragging');
        }
        if (!cancelled && !wasMoved && state.activePointers.size === 0) {
            const hit = findEntityAt(event.clientX, event.clientY);
            if (hit) selectEntity(hit.layer, hit.id, !isDetailedView(), event.pointerType === 'touch');
        }
    };
    elements.canvas.addEventListener('pointerup', finishPointer);
    elements.canvas.addEventListener('pointercancel', event => finishPointer(event, true));
}

function startPinchGesture() {
    const [first, second] = [...state.activePointers.values()];
    if (!first || !second) return;
    const centerX = (first.x + second.x) / 2;
    const centerY = (first.y + second.y) / 2;
    state.pinching = true;
    state.dragging = false;
    state.moved = true;
    state.dragStart = null;
    state.pinchStart = {
        distance: Math.max(1, Math.hypot(second.x - first.x, second.y - first.y)),
        anchor: clientToWorld(centerX, centerY),
        view: { ...state.view }
    };
}

function normalizePoints(items, mapper) {
    return (Array.isArray(items) ? items : [])
        .filter(item => item && Number.isFinite(Number(item.x)) && Number.isFinite(Number(item.y)))
        .map(mapper);
}

function normalizeMarch(item) {
    return {
        ...item,
        id: String(item.id ?? item.uuid ?? `${item.x}:${item.y}`),
        x: Number(item.x), y: Number(item.y),
        start: Number.isFinite(Number(item.start_x)) && Number.isFinite(Number(item.start_y))
            ? { x: Number(item.start_x), y: Number(item.start_y) }
            : item.start,
        end: Number.isFinite(Number(item.end_x)) && Number.isFinite(Number(item.end_y))
            ? { x: Number(item.end_x), y: Number(item.end_y) }
            : item.end
    };
}

function layerItems(layer) {
    return Array.isArray(state[layer]) ? state[layer] : [];
}

function totalMapItems() {
    return Object.keys(state.layers).reduce((total, layer) => total + layerItems(layer).length, 0);
}

function entityId(layer, item) {
    return String(layer === 'players' ? item.uid : item.id);
}

function isSelected(layer, id) {
    return state.selected?.layer === layer && state.selected.id === String(id);
}

function findEntity(layer, id) {
    return layerItems(layer).find(item => entityId(layer, item) === String(id));
}

function clearSelection() {
    state.selected = null;
    closePlayerDialog();
    elements.selection.innerHTML = `
        <div class="selection-empty">
            <i class="fa-solid fa-location-crosshairs"></i>
            <strong>Nothing selected</strong>
            <p>Click a map item or choose a player from the list.</p>
        </div>`;
    renderResults();
    renderBestTruckLoot();
}

function detailRow(label, value, wide = false) {
    const text = value === null || value === undefined || value === '' ? '—' : String(value);
    return `<div class="${wide ? 'wide' : ''}"><span>${escapeHtml(label)}</span><strong title="${escapeHtml(text)}">${escapeHtml(text)}</strong></div>`;
}

function numericOrNull(value) {
    const number = Number(value);
    return Number.isFinite(number) ? number : null;
}

function formatCoordinate(value) {
    const number = Number(value);
    return Number.isInteger(number) ? String(number) : number.toFixed(1).replace(/\.0$/, '');
}

function formatTimestamp(value) {
    const number = Number(value);
    if (!Number.isFinite(number) || number <= 0) return '—';
    const date = new Date(number);
    return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString('en-US');
}

function formatPower(value) {
    const number = Number(value);
    if (!Number.isFinite(number) || number <= 0) return '—';
    if (number >= 1_000_000_000) return `${(number / 1_000_000_000).toFixed(2)}B`;
    if (number >= 1_000_000) return `${(number / 1_000_000).toFixed(2)}M`;
    if (number >= 1_000) return `${(number / 1_000).toFixed(1)}K`;
    return formatNumber(number);
}

function formatRoute(item) {
    if (!item.start || !item.end) return '—';
    return `${formatCoordinate(item.start.x)},${formatCoordinate(item.start.y)} → ${formatCoordinate(item.end.x)},${formatCoordinate(item.end.y)}`;
}

function listCount(value) {
    if (!Array.isArray(value) || !value.length) return '—';
    return formatNumber(value.length);
}

function formatGoods(goods) {
    const items = aggregateGoods(goods).sort((a, b) => {
        const aUr = String(a.item_id || '') === UNIVERSAL_UR_SHARD_ID ? 1 : 0;
        const bUr = String(b.item_id || '') === UNIVERSAL_UR_SHARD_ID ? 1 : 0;
        return bUr - aUr || Number(Boolean(b.item_id)) - Number(Boolean(a.item_id));
    });
    if (!items.length) return '';
    const summary = items.slice(0, 6).map(item => {
        const itemId = item.item_id ? String(item.item_id) : '';
        const label = itemId ? (ITEM_NAMES[itemId] || `Item ${itemId}`) : `Reward ${item.type ?? '?'}`;
        return `${label} × ${formatNumber(item.amount)}`;
    });
    if (items.length > 6) summary.push(`+ ${items.length - 6} more`);
    return `Rewards: ${summary.join(' · ')}`;
}

function aggregateGoods(goods) {
    const grouped = new Map();
    for (const item of Array.isArray(goods) ? goods : []) {
        if (!item) continue;
        const itemId = item.item_id === null || item.item_id === undefined ? '' : String(item.item_id);
        const key = itemId ? `item:${itemId}` : `reward:${item.type ?? '?'}`;
        const current = grouped.get(key) || { ...item, item_id: itemId || null, amount: 0 };
        current.amount += Number(item.amount) || 0;
        grouped.set(key, current);
    }
    return [...grouped.values()];
}

function truckGoods(truck) {
    return [...(truck.base_goods || []), ...(truck.extra_goods || [])];
}

function universalUrShardCount(truck) {
    return aggregateGoods(truckGoods(truck))
        .filter(item => String(item.item_id || '') === UNIVERSAL_UR_SHARD_ID)
        .reduce((total, item) => total + (Number(item.amount) || 0), 0);
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
