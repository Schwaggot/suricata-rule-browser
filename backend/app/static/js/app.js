// Suricata Rule Browser - Frontend JavaScript

const API_BASE = '/api/v1';
let currentPage = 1;
let currentFilters = {};
let totalRules = 0;

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    initializeEventListeners();
    loadStats();
    loadRules();
});

// Set up event listeners
function initializeEventListeners() {
    // Search
    document.getElementById('search-btn').addEventListener('click', handleSearch);
    document.getElementById('search-input').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') handleSearch();
    });
    document.getElementById('clear-btn').addEventListener('click', clearFilters);

    // Filters
    document.getElementById('action-filter').addEventListener('change', handleFilterChange);
    document.getElementById('protocol-filter').addEventListener('change', handleFilterChange);
    document.getElementById('classtype-filter').addEventListener('change', handleFilterChange);
    document.getElementById('priority-filter').addEventListener('change', handleFilterChange);
    document.getElementById('source-filter').addEventListener('change', handleFilterChange);
    document.getElementById('sort-by').addEventListener('change', handleFilterChange);
    document.getElementById('sort-order').addEventListener('change', handleFilterChange);

    // Pagination
    document.getElementById('prev-page').addEventListener('click', () => changePage(-1));
    document.getElementById('next-page').addEventListener('click', () => changePage(1));

    // Modal
    const modal = document.getElementById('rule-modal');
    const closeBtn = document.querySelector('.close');
    closeBtn.addEventListener('click', () => {
        modal.style.display = 'none';
    });
    window.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.style.display = 'none';
        }
    });
}

// Load statistics
async function loadStats() {
    try {
        const response = await fetch(`${API_BASE}/stats`);
        const data = await response.json();

        document.getElementById('total-rules').textContent = data.total_rules;

        // Populate filter dropdowns
        populateProtocolFilter(data.protocols);
        populateClasstypeFilter(data.classtypes);
        populatePriorityFilter(data.priorities);
        populateSourceFilter(data.sources);
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

// Populate protocol filter dropdown
function populateProtocolFilter(protocols) {
    const select = document.getElementById('protocol-filter');
    const sortedProtocols = Object.keys(protocols).sort();

    sortedProtocols.forEach(protocol => {
        const option = document.createElement('option');
        option.value = protocol;
        option.textContent = `${protocol} (${protocols[protocol]})`;
        select.appendChild(option);
    });
}

// Populate classtype filter dropdown
function populateClasstypeFilter(classtypes) {
    const select = document.getElementById('classtype-filter');
    const sortedClasstypes = Object.keys(classtypes).sort();

    sortedClasstypes.forEach(classtype => {
        const option = document.createElement('option');
        option.value = classtype;
        option.textContent = `${classtype} (${classtypes[classtype]})`;
        select.appendChild(option);
    });
}

// Populate priority filter dropdown
function populatePriorityFilter(priorities) {
    const select = document.getElementById('priority-filter');
    const sortedPriorities = Object.keys(priorities).sort((a, b) => a - b);

    sortedPriorities.forEach(priority => {
        const option = document.createElement('option');
        option.value = priority;
        option.textContent = `Priority ${priority} (${priorities[priority]})`;
        select.appendChild(option);
    });
}

// Populate source filter dropdown
function populateSourceFilter(sources) {
    const select = document.getElementById('source-filter');
    const sortedSources = Object.keys(sources).sort();

    sortedSources.forEach(source => {
        const option = document.createElement('option');
        option.value = source;
        option.textContent = `${source} (${sources[source]})`;
        select.appendChild(option);
    });
}

// Handle search
function handleSearch() {
    currentPage = 1;
    loadRules();
}

// Handle filter changes
function handleFilterChange() {
    currentPage = 1;
    loadRules();
}

// Clear all filters
function clearFilters() {
    document.getElementById('search-input').value = '';
    document.getElementById('action-filter').value = '';
    document.getElementById('protocol-filter').value = '';
    document.getElementById('classtype-filter').value = '';
    document.getElementById('priority-filter').value = '';
    document.getElementById('source-filter').value = '';
    document.getElementById('sort-by').value = 'sid';
    document.getElementById('sort-order').value = 'asc';
    currentPage = 1;
    currentFilters = {};
    loadRules();
}

// Build query parameters from filters
function buildQueryParams() {
    const params = new URLSearchParams();

    params.append('page', currentPage);
    params.append('page_size', 50);

    const search = document.getElementById('search-input').value.trim();
    if (search) params.append('search', search);

    const action = document.getElementById('action-filter').value;
    if (action) params.append('action', action);

    const protocol = document.getElementById('protocol-filter').value;
    if (protocol) params.append('protocol', protocol);

    const classtype = document.getElementById('classtype-filter').value;
    if (classtype) params.append('classtype', classtype);

    const priority = document.getElementById('priority-filter').value;
    if (priority) params.append('priority', priority);

    const source = document.getElementById('source-filter').value;
    if (source) params.append('source', source);

    const sortBy = document.getElementById('sort-by').value;
    params.append('sort_by', sortBy);

    const sortOrder = document.getElementById('sort-order').value;
    params.append('sort_order', sortOrder);

    return params;
}

// Load rules from API
async function loadRules() {
    showLoading();
    hideError();

    try {
        const params = buildQueryParams();
        const response = await fetch(`${API_BASE}/rules?${params}`);

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        displayRules(data);
        updatePagination(data);
        document.getElementById('filtered-rules').textContent = data.total;
    } catch (error) {
        console.error('Error loading rules:', error);
        showError('Failed to load rules. Please try again.');
    } finally {
        hideLoading();
    }
}

// Display rules
function displayRules(data) {
    const rulesList = document.getElementById('rules-list');
    rulesList.innerHTML = '';

    if (data.rules.length === 0) {
        rulesList.innerHTML = '<div class="rule-card"><p>No rules found matching your criteria.</p></div>';
        return;
    }

    data.rules.forEach(rule => {
        const ruleCard = createRuleCard(rule);
        rulesList.appendChild(ruleCard);
    });
}

// Create a rule card element
function createRuleCard(rule) {
    const card = document.createElement('div');
    card.className = 'rule-card';
    card.addEventListener('click', () => showRuleDetail(rule));

    // Title: Rule message
    const title = document.createElement('div');
    title.className = 'rule-title';
    title.textContent = rule.msg || 'No message';

    // Header: Badges and SID
    const header = document.createElement('div');
    header.className = 'rule-header';

    const badges = document.createElement('div');
    badges.className = 'rule-badges';

    // Add SID as a badge
    const sidBadge = document.createElement('span');
    sidBadge.className = 'badge badge-sid';
    sidBadge.textContent = `SID: ${rule.id || 'N/A'}`;
    badges.appendChild(sidBadge);

    const actionBadge = document.createElement('span');
    actionBadge.className = `badge badge-action ${rule.action}`;
    actionBadge.textContent = rule.action.toUpperCase();
    badges.appendChild(actionBadge);

    const protocolBadge = document.createElement('span');
    protocolBadge.className = 'badge badge-protocol';
    protocolBadge.textContent = rule.protocol.toUpperCase();
    badges.appendChild(protocolBadge);

    if (rule.priority !== null) {
        const priorityBadge = document.createElement('span');
        priorityBadge.className = 'badge badge-priority';
        priorityBadge.textContent = `P${rule.priority}`;
        badges.appendChild(priorityBadge);
    }

    if (rule.source) {
        const sourceBadge = document.createElement('span');
        sourceBadge.className = 'badge badge-source';
        sourceBadge.textContent = rule.source.toUpperCase();
        badges.appendChild(sourceBadge);
    }

    header.appendChild(badges);

    const meta = document.createElement('div');
    meta.className = 'rule-meta';

    // Create network info with truncation
    const networkText = `${rule.src_ip}:${rule.src_port} ${rule.direction} ${rule.dst_ip}:${rule.dst_port}`;
    const networkContainer = createTruncatedText(networkText, 80);
    meta.appendChild(networkContainer);

    if (rule.classtype) {
        const classtype = document.createElement('span');
        classtype.textContent = `Class: ${rule.classtype}`;
        meta.appendChild(classtype);
    }

    card.appendChild(title);
    card.appendChild(header);
    card.appendChild(meta);

    return card;
}

// Create truncated text with expand button
function createTruncatedText(text, maxLength) {
    const container = document.createElement('span');
    container.className = 'truncatable-text';

    if (text.length <= maxLength) {
        container.textContent = text;
        return container;
    }

    // Create truncated version
    const truncated = document.createElement('span');
    truncated.className = 'truncated-content';
    truncated.textContent = text.substring(0, maxLength);

    // Create expand button
    const expandBtn = document.createElement('button');
    expandBtn.className = 'expand-btn';
    expandBtn.textContent = '...';
    expandBtn.title = 'Click to expand';

    // Create full content (hidden initially)
    const fullContent = document.createElement('span');
    fullContent.className = 'full-content';
    fullContent.style.display = 'none';
    fullContent.textContent = text;

    // Create collapse button
    const collapseBtn = document.createElement('button');
    collapseBtn.className = 'collapse-btn';
    collapseBtn.textContent = ' [show less]';
    collapseBtn.title = 'Click to collapse';
    collapseBtn.style.display = 'none';

    // Toggle functionality
    expandBtn.addEventListener('click', (e) => {
        e.stopPropagation(); // Prevent card click
        truncated.style.display = 'none';
        expandBtn.style.display = 'none';
        fullContent.style.display = 'inline';
        collapseBtn.style.display = 'inline';
    });

    collapseBtn.addEventListener('click', (e) => {
        e.stopPropagation(); // Prevent card click
        truncated.style.display = 'inline';
        expandBtn.style.display = 'inline';
        fullContent.style.display = 'none';
        collapseBtn.style.display = 'none';
    });

    container.appendChild(truncated);
    container.appendChild(expandBtn);
    container.appendChild(fullContent);
    container.appendChild(collapseBtn);

    return container;
}

// Show rule detail in modal
function showRuleDetail(rule) {
    const modal = document.getElementById('rule-modal');
    const detailDiv = document.getElementById('rule-detail');

    let html = `
        <div class="detail-section">
            <h2>Rule Details - SID: ${rule.id || 'N/A'}</h2>
        </div>

        <div class="detail-section">
            <h3>Basic Information</h3>
            <div class="detail-grid">
                <div class="detail-label">Action:</div>
                <div class="detail-value"><span class="badge badge-action ${rule.action}">${rule.action.toUpperCase()}</span></div>

                <div class="detail-label">Protocol:</div>
                <div class="detail-value">${rule.protocol}</div>

                <div class="detail-label">Message:</div>
                <div class="detail-value">${rule.msg || 'N/A'}</div>

                <div class="detail-label">Classification:</div>
                <div class="detail-value">${rule.classtype || 'N/A'}</div>

                <div class="detail-label">Priority:</div>
                <div class="detail-value">${rule.priority !== null ? rule.priority : 'N/A'}</div>

                <div class="detail-label">Revision:</div>
                <div class="detail-value">${rule.rev || 'N/A'}</div>
            </div>
        </div>

        <div class="detail-section">
            <h3>Network</h3>
            <div class="detail-grid">
                <div class="detail-label">Source:</div>
                <div class="detail-value">${rule.src_ip}:${rule.src_port}</div>

                <div class="detail-label">Direction:</div>
                <div class="detail-value">${rule.direction}</div>

                <div class="detail-label">Destination:</div>
                <div class="detail-value">${rule.dst_ip}:${rule.dst_port}</div>
            </div>
        </div>
    `;

    if (rule.reference && rule.reference.length > 0) {
        html += `
            <div class="detail-section">
                <h3>References</h3>
                <ul>
                    ${rule.reference.map(ref => `<li>${ref}</li>`).join('')}
                </ul>
            </div>
        `;
    }

    if (rule.metadata && Object.keys(rule.metadata).length > 0) {
        html += `
            <div class="detail-section">
                <h3>Metadata</h3>
                <div class="detail-grid">
                    ${Object.entries(rule.metadata).map(([key, value]) => `
                        <div class="detail-label">${key}:</div>
                        <div class="detail-value">${value}</div>
                    `).join('')}
                </div>
            </div>
        `;
    }

    html += `
        <div class="detail-section">
            <h3>Raw Rule</h3>
            <div class="rule-raw">${escapeHtml(rule.raw_rule)}</div>
        </div>
    `;

    detailDiv.innerHTML = html;
    modal.style.display = 'block';
}

// Update pagination controls
function updatePagination(data) {
    const pageInfo = document.getElementById('page-info');
    const prevBtn = document.getElementById('prev-page');
    const nextBtn = document.getElementById('next-page');

    const totalPages = Math.ceil(data.total / data.page_size);

    pageInfo.textContent = `Page ${data.page} of ${totalPages} (${data.total} rules)`;

    prevBtn.disabled = data.page <= 1;
    nextBtn.disabled = data.page >= totalPages;
}

// Change page
function changePage(delta) {
    currentPage += delta;
    loadRules();
}

// Show loading indicator
function showLoading() {
    document.getElementById('loading').style.display = 'block';
    document.getElementById('rules-list').style.display = 'none';
}

// Hide loading indicator
function hideLoading() {
    document.getElementById('loading').style.display = 'none';
    document.getElementById('rules-list').style.display = 'flex';
}

// Show error message
function showError(message) {
    const errorDiv = document.getElementById('error-message');
    errorDiv.textContent = message;
    errorDiv.style.display = 'block';
}

// Hide error message
function hideError() {
    document.getElementById('error-message').style.display = 'none';
}

// Escape HTML to prevent XSS
function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}
