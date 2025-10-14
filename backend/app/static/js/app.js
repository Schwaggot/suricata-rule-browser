// Suricata Rule Browser - Frontend JavaScript

const API_BASE = '/api/v1';
let currentPage = 1;
let currentFilters = {};
let totalRules = 0;

// Store Choices.js instances for all filter dropdowns
let choicesInstances = {};

// Column order (must match the order in createRuleRow)
const columnOrder = [
    'sid', 'action', 'protocol', 'message', 'source', 'category', 'classtype',
    'severity', 'attack_target', 'deployment', 'affected_product',
    'confidence', 'performance', 'network', 'revision'
];

// Column visibility state
let visibleColumns = {
    sid: false,
    action: false,
    protocol: true,
    message: true,
    source: true,
    category: true,
    classtype: true,
    severity: false,
    attack_target: false,
    deployment: false,
    affected_product: false,
    confidence: false,
    performance: false,
    network: true,
    revision: false
};

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    initializeTheme();
    initializeColumnVisibility();
    initializeChoices();
    initializeEventListeners();
    loadStats();
    loadRules();
});

// Initialize theme from localStorage or system preference
function initializeTheme() {
    const savedTheme = localStorage.getItem('theme');
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;

    if (savedTheme === 'dark' || (!savedTheme && prefersDark)) {
        document.documentElement.style.colorScheme = 'dark';
        updateThemeIcon('dark');
    } else {
        document.documentElement.style.colorScheme = 'light';
        updateThemeIcon('light');
    }
}

// Toggle theme
function toggleTheme() {
    const currentScheme = document.documentElement.style.colorScheme;
    const newScheme = currentScheme === 'dark' ? 'light' : 'dark';

    document.documentElement.style.colorScheme = newScheme;
    localStorage.setItem('theme', newScheme);
    updateThemeIcon(newScheme);
}

// Update theme icon
function updateThemeIcon(theme) {
    const icon = document.querySelector('.theme-icon');
    if (icon) {
        icon.textContent = theme === 'dark' ? '☀️' : '🌙';
    }
}

// Initialize column visibility from localStorage
function initializeColumnVisibility() {
    const saved = localStorage.getItem('columnVisibility');
    if (saved) {
        visibleColumns = JSON.parse(saved);
    }

    // Update checkboxes to match saved state
    Object.keys(visibleColumns).forEach(column => {
        const checkbox = document.querySelector(`input[data-column="${column}"]`);
        if (checkbox) {
            checkbox.checked = visibleColumns[column];
        }
    });

    // Apply initial visibility
    applyColumnVisibility();
}

// Toggle column visibility
function toggleColumn(columnName, isVisible) {
    visibleColumns[columnName] = isVisible;
    localStorage.setItem('columnVisibility', JSON.stringify(visibleColumns));
    applyColumnVisibility();
}

// Apply column visibility to table
function applyColumnVisibility() {
    const table = document.getElementById('rules-table');

    // Update header visibility
    const headers = table.querySelectorAll('thead th');
    headers.forEach(th => {
        const column = th.getAttribute('data-column');
        if (column) {
            th.style.display = visibleColumns[column] ? '' : 'none';
        }
    });

    // Update cell visibility for all rows
    const rows = table.querySelectorAll('tbody tr');
    rows.forEach(row => {
        const cells = row.querySelectorAll('td');
        // Use columnOrder array to ensure cells match the correct columns
        columnOrder.forEach((column, index) => {
            if (cells[index]) {
                cells[index].style.display = visibleColumns[column] ? '' : 'none';
            }
        });
    });
}

// Initialize Choices.js for all filter dropdowns
function initializeChoices() {
    const filterIds = [
        'action-filter',
        'protocol-filter',
        'classtype-filter',
        'source-filter',
        'category-filter',
        'severity-filter',
        'attack-target-filter',
        'deployment-filter',
        'affected-product-filter',
        'confidence-filter',
        'performance-filter'
    ];

    filterIds.forEach(id => {
        const element = document.getElementById(id);
        if (element) {
            const choices = new Choices(element, {
                removeItemButton: true,
                searchEnabled: true,
                searchPlaceholderValue: 'Search...',
                placeholder: true,
                placeholderValue: 'Select options',
                itemSelectText: '',
                shouldSort: false,
                // Customize the no results text
                noResultsText: 'No options found',
                noChoicesText: 'No options available'
            });

            choicesInstances[id] = choices;

            // Add clear all button to the filter group
            const filterGroup = element.closest('.filter-group');
            if (filterGroup) {
                const clearBtn = document.createElement('button');
                clearBtn.className = 'filter-clear-btn';
                clearBtn.innerHTML = '×';
                clearBtn.title = 'Clear this filter';
                clearBtn.type = 'button';
                clearBtn.addEventListener('click', (e) => {
                    e.preventDefault();
                    choices.removeActiveItems();
                    handleFilterChange();
                });

                // Insert the clear button after the label
                const label = filterGroup.querySelector('label');
                if (label) {
                    label.style.display = 'flex';
                    label.style.justifyContent = 'space-between';
                    label.style.alignItems = 'center';
                    label.appendChild(clearBtn);
                }
            }
        }
    });
}

// Set up event listeners
function initializeEventListeners() {
    // Theme toggle
    document.getElementById('theme-toggle').addEventListener('click', toggleTheme);

    // Column visibility toggle
    const columnToggleBtn = document.getElementById('column-toggle-btn');
    const columnDropdown = document.getElementById('column-dropdown');

    columnToggleBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const isVisible = columnDropdown.style.display === 'block';
        columnDropdown.style.display = isVisible ? 'none' : 'block';
    });

    // Close dropdown when clicking outside
    document.addEventListener('click', (e) => {
        if (!e.target.closest('.column-toggle-wrapper')) {
            columnDropdown.style.display = 'none';
        }
    });

    // Column checkboxes
    const columnCheckboxes = document.querySelectorAll('.column-option input[type="checkbox"]');
    columnCheckboxes.forEach(checkbox => {
        checkbox.addEventListener('change', (e) => {
            const column = e.target.getAttribute('data-column');
            toggleColumn(column, e.target.checked);
        });
    });

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
    document.getElementById('source-filter').addEventListener('change', handleFilterChange);
    document.getElementById('category-filter').addEventListener('change', handleFilterChange);
    document.getElementById('severity-filter').addEventListener('change', handleFilterChange);
    document.getElementById('attack-target-filter').addEventListener('change', handleFilterChange);
    document.getElementById('deployment-filter').addEventListener('change', handleFilterChange);
    document.getElementById('affected-product-filter').addEventListener('change', handleFilterChange);
    document.getElementById('confidence-filter').addEventListener('change', handleFilterChange);
    document.getElementById('performance-filter').addEventListener('change', handleFilterChange);
    document.getElementById('sort-by').addEventListener('change', handleFilterChange);
    document.getElementById('sort-order').addEventListener('change', handleFilterChange);

    // Pagination - Top
    document.getElementById('prev-page-top').addEventListener('click', () => changePage(-1));
    document.getElementById('next-page-top').addEventListener('click', () => changePage(1));

    // Pagination - Bottom
    document.getElementById('prev-page-bottom').addEventListener('click', () => changePage(-1));
    document.getElementById('next-page-bottom').addEventListener('click', () => changePage(1));

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
        populateActionFilter(data.actions);
        populateProtocolFilter(data.protocols);
        populateClasstypeFilter(data.classtypes);
        populateSourceFilter(data.sources);
        populateCategoryFilter(data.categories);
        populateSeverityFilter(data.signature_severities);
        populateAttackTargetFilter(data.attack_targets);
        populateDeploymentFilter(data.deployments);
        populateAffectedProductFilter(data.affected_products);
        populateConfidenceFilter(data.confidences);
        populatePerformanceFilter(data.performance_impacts);
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

// Populate action filter dropdown
function populateActionFilter(actions) {
    const sortedActions = Object.keys(actions).sort();
    const choices = sortedActions.map(action => ({
        value: action,
        label: `${action} (${actions[action]})`
    }));

    if (choicesInstances['action-filter']) {
        choicesInstances['action-filter'].setChoices(choices, 'value', 'label', true);
    }
}

// Populate protocol filter dropdown
function populateProtocolFilter(protocols) {
    const sortedProtocols = Object.keys(protocols).sort();
    const choices = sortedProtocols.map(protocol => ({
        value: protocol,
        label: `${protocol} (${protocols[protocol]})`
    }));

    if (choicesInstances['protocol-filter']) {
        choicesInstances['protocol-filter'].setChoices(choices, 'value', 'label', true);
    }
}

// Populate classtype filter dropdown
function populateClasstypeFilter(classtypes) {
    const sortedClasstypes = Object.keys(classtypes).sort((a, b) => {
        // Put "(unset)" at the end
        if (a === "(unset)") return 1;
        if (b === "(unset)") return -1;
        return a.localeCompare(b);
    });
    const choices = sortedClasstypes.map(classtype => ({
        value: classtype,
        label: `${classtype} (${classtypes[classtype]})`
    }));

    if (choicesInstances['classtype-filter']) {
        choicesInstances['classtype-filter'].setChoices(choices, 'value', 'label', true);
    }
}

// Populate source filter dropdown
function populateSourceFilter(sources) {
    const sortedSources = Object.keys(sources).sort((a, b) => {
        // Put "(unset)" at the end
        if (a === "(unset)") return 1;
        if (b === "(unset)") return -1;
        return a.localeCompare(b);
    });
    const choices = sortedSources.map(source => ({
        value: source,
        label: `${source} (${sources[source]})`
    }));

    if (choicesInstances['source-filter']) {
        choicesInstances['source-filter'].setChoices(choices, 'value', 'label', true);
    }
}

// Populate category filter dropdown
function populateCategoryFilter(categories) {
    if (!categories || Object.keys(categories).length === 0) {
        return;
    }

    const sortedCategories = Object.keys(categories).sort((a, b) => {
        // Put "(unset)" at the end
        if (a === "(unset)") return 1;
        if (b === "(unset)") return -1;
        return a.localeCompare(b);
    });
    const choices = sortedCategories.map(category => ({
        value: category,
        label: `${category} (${categories[category]})`
    }));

    if (choicesInstances['category-filter']) {
        choicesInstances['category-filter'].setChoices(choices, 'value', 'label', true);
    }
}

// Populate severity filter dropdown
function populateSeverityFilter(severities) {
    if (!severities || Object.keys(severities).length === 0) {
        return;
    }

    const sortedSeverities = Object.keys(severities).sort((a, b) => {
        // Put "(unset)" at the end
        if (a === "(unset)") return 1;
        if (b === "(unset)") return -1;
        return a.localeCompare(b);
    });
    const choices = sortedSeverities.map(severity => ({
        value: severity,
        label: `${severity} (${severities[severity]})`
    }));

    if (choicesInstances['severity-filter']) {
        choicesInstances['severity-filter'].setChoices(choices, 'value', 'label', true);
    }
}

// Populate attack target filter dropdown
function populateAttackTargetFilter(targets) {
    if (!targets || Object.keys(targets).length === 0) {
        return;
    }

    const sortedTargets = Object.keys(targets).sort((a, b) => {
        // Put "(unset)" at the end
        if (a === "(unset)") return 1;
        if (b === "(unset)") return -1;
        return a.localeCompare(b);
    });
    const choices = sortedTargets.map(target => ({
        value: target,
        label: `${target} (${targets[target]})`
    }));

    if (choicesInstances['attack-target-filter']) {
        choicesInstances['attack-target-filter'].setChoices(choices, 'value', 'label', true);
    }
}

// Populate deployment filter dropdown
function populateDeploymentFilter(deployments) {
    if (!deployments || Object.keys(deployments).length === 0) {
        return;
    }

    const sortedDeployments = Object.keys(deployments).sort((a, b) => {
        // Put "(unset)" at the end
        if (a === "(unset)") return 1;
        if (b === "(unset)") return -1;
        return a.localeCompare(b);
    });
    const choices = sortedDeployments.map(deployment => ({
        value: deployment,
        label: `${deployment} (${deployments[deployment]})`
    }));

    if (choicesInstances['deployment-filter']) {
        choicesInstances['deployment-filter'].setChoices(choices, 'value', 'label', true);
    }
}

// Populate affected product filter dropdown
function populateAffectedProductFilter(products) {
    if (!products || Object.keys(products).length === 0) {
        return;
    }

    const sortedProducts = Object.keys(products).sort((a, b) => {
        // Put "(unset)" at the end
        if (a === "(unset)") return 1;
        if (b === "(unset)") return -1;
        return a.localeCompare(b);
    });
    const choices = sortedProducts.map(product => ({
        value: product,
        label: `${product} (${products[product]})`
    }));

    if (choicesInstances['affected-product-filter']) {
        choicesInstances['affected-product-filter'].setChoices(choices, 'value', 'label', true);
    }
}

// Populate confidence filter dropdown
function populateConfidenceFilter(confidences) {
    if (!confidences || Object.keys(confidences).length === 0) {
        return;
    }

    const sortedConfidences = Object.keys(confidences).sort((a, b) => {
        // Put "(unset)" at the end
        if (a === "(unset)") return 1;
        if (b === "(unset)") return -1;
        return a.localeCompare(b);
    });
    const choices = sortedConfidences.map(confidence => ({
        value: confidence,
        label: `${confidence} (${confidences[confidence]})`
    }));

    if (choicesInstances['confidence-filter']) {
        choicesInstances['confidence-filter'].setChoices(choices, 'value', 'label', true);
    }
}

// Populate performance filter dropdown
function populatePerformanceFilter(impacts) {
    if (!impacts || Object.keys(impacts).length === 0) {
        return;
    }

    const sortedImpacts = Object.keys(impacts).sort((a, b) => {
        // Put "(unset)" at the end
        if (a === "(unset)") return 1;
        if (b === "(unset)") return -1;
        return a.localeCompare(b);
    });
    const choices = sortedImpacts.map(impact => ({
        value: impact,
        label: `${impact} (${impacts[impact]})`
    }));

    if (choicesInstances['performance-filter']) {
        choicesInstances['performance-filter'].setChoices(choices, 'value', 'label', true);
    }
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

    // Clear all Choices.js instances
    Object.keys(choicesInstances).forEach(key => {
        if (choicesInstances[key]) {
            choicesInstances[key].removeActiveItems();
        }
    });

    document.getElementById('sort-by').value = 'msg';
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

    // Get selected values from Choices.js instances
    const action = choicesInstances['action-filter']?.getValue(true);
    if (action && action.length > 0) {
        action.forEach(val => params.append('action', val));
    }

    const protocol = choicesInstances['protocol-filter']?.getValue(true);
    if (protocol && protocol.length > 0) {
        protocol.forEach(val => params.append('protocol', val));
    }

    const classtype = choicesInstances['classtype-filter']?.getValue(true);
    if (classtype && classtype.length > 0) {
        classtype.forEach(val => params.append('classtype', val));
    }

    const source = choicesInstances['source-filter']?.getValue(true);
    if (source && source.length > 0) {
        source.forEach(val => params.append('source', val));
    }

    const category = choicesInstances['category-filter']?.getValue(true);
    if (category && category.length > 0) {
        category.forEach(val => params.append('category', val));
    }

    const severity = choicesInstances['severity-filter']?.getValue(true);
    if (severity && severity.length > 0) {
        severity.forEach(val => params.append('signature_severity', val));
    }

    const attackTarget = choicesInstances['attack-target-filter']?.getValue(true);
    if (attackTarget && attackTarget.length > 0) {
        attackTarget.forEach(val => params.append('attack_target', val));
    }

    const deployment = choicesInstances['deployment-filter']?.getValue(true);
    if (deployment && deployment.length > 0) {
        deployment.forEach(val => params.append('deployment', val));
    }

    const affectedProduct = choicesInstances['affected-product-filter']?.getValue(true);
    if (affectedProduct && affectedProduct.length > 0) {
        affectedProduct.forEach(val => params.append('affected_product', val));
    }

    const confidence = choicesInstances['confidence-filter']?.getValue(true);
    if (confidence && confidence.length > 0) {
        confidence.forEach(val => params.append('confidence', val));
    }

    const performance = choicesInstances['performance-filter']?.getValue(true);
    if (performance && performance.length > 0) {
        performance.forEach(val => params.append('performance_impact', val));
    }

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
        rulesList.innerHTML = '<tr><td colspan="15" style="text-align: center; padding: 40px;">No rules found matching your criteria.</td></tr>';
        return;
    }

    data.rules.forEach(rule => {
        const ruleRow = createRuleRow(rule);
        rulesList.appendChild(ruleRow);
    });

    // Apply column visibility to newly rendered rows
    applyColumnVisibility();
}

// Create a rule row element
function createRuleRow(rule) {
    const row = document.createElement('tr');
    row.className = 'rule-row';
    row.addEventListener('click', () => showRuleDetail(rule));

    // Helper function to create a cell with optional badge
    const createCell = (content, className = '', isBadge = false, badgeClass = '') => {
        const cell = document.createElement('td');
        if (className) cell.className = className;

        if (isBadge && content && content !== '-') {
            const badge = document.createElement('span');
            badge.className = `badge ${badgeClass}`;
            badge.textContent = content;
            cell.appendChild(badge);
        } else {
            cell.textContent = content || '-';
        }
        return cell;
    };

    // SID column
    const sidCell = document.createElement('td');
    sidCell.className = 'sid-cell';
    sidCell.textContent = rule.id || 'N/A';
    row.appendChild(sidCell);

    // Action column
    const actionCell = document.createElement('td');
    const actionBadge = document.createElement('span');
    actionBadge.className = `badge badge-action ${rule.action}`;
    actionBadge.textContent = rule.action.toUpperCase();
    actionCell.appendChild(actionBadge);
    row.appendChild(actionCell);

    // Protocol column
    const protocolCell = document.createElement('td');
    const protocolBadge = document.createElement('span');
    protocolBadge.className = 'badge badge-protocol';
    protocolBadge.textContent = rule.protocol.toUpperCase();
    protocolCell.appendChild(protocolBadge);
    row.appendChild(protocolCell);

    // Message column
    const msgCell = document.createElement('td');
    msgCell.className = 'msg-cell';
    msgCell.textContent = rule.msg || 'No message';
    row.appendChild(msgCell);

    // Source column
    const sourceCell = document.createElement('td');
    if (rule.source) {
        const sourceBadge = document.createElement('span');
        sourceBadge.className = 'badge badge-source';
        sourceBadge.textContent = rule.source.toUpperCase();
        sourceCell.appendChild(sourceBadge);
    } else {
        sourceCell.textContent = '-';
    }
    row.appendChild(sourceCell);

    // Category column
    const categoryCell = document.createElement('td');
    if (rule.category) {
        const categoryBadge = document.createElement('span');
        categoryBadge.className = 'badge badge-category';
        categoryBadge.textContent = rule.category;
        categoryCell.appendChild(categoryBadge);
    } else {
        categoryCell.textContent = '-';
    }
    row.appendChild(categoryCell);

    // Class Type column
    row.appendChild(createCell(rule.classtype));

    // Severity column
    row.appendChild(createCell(rule.signature_severity, '', true, 'badge-severity'));

    // Attack Target column
    row.appendChild(createCell(rule.attack_target));

    // Deployment column
    row.appendChild(createCell(rule.deployment));

    // Affected Product column
    const productCell = document.createElement('td');
    productCell.className = 'product-cell';
    productCell.textContent = rule.affected_product || '-';
    productCell.title = rule.affected_product || '';
    row.appendChild(productCell);

    // Confidence column
    row.appendChild(createCell(rule.confidence, '', true, 'badge-confidence'));

    // Performance Impact column
    row.appendChild(createCell(rule.performance_impact, '', true, 'badge-performance'));

    // Network column
    const networkCell = document.createElement('td');
    networkCell.className = 'network-cell';
    const networkText = `${rule.src_ip}:${rule.src_port} ${rule.direction} ${rule.dst_ip}:${rule.dst_port}`;
    networkCell.textContent = networkText;
    networkCell.title = networkText;
    row.appendChild(networkCell);

    // Revision column
    row.appendChild(createCell(rule.rev));

    return row;
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
                <ul class="reference-list">
                    ${rule.reference.map(ref => `<li>${formatReference(ref)}</li>`).join('')}
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
            <h3>Formatted Rule</h3>
            <div class="rule-raw">${formatRawRule(rule.raw_rule)}</div>
        </div>

        <div class="detail-section">
            <h3>Raw Rule</h3>
            <div class="rule-raw-original">${escapeHtml(rule.raw_rule)}</div>
        </div>
    `;

    detailDiv.innerHTML = html;
    modal.style.display = 'block';
}

// Format raw rule with proper indentation and line breaks
function formatRawRule(rawRule) {
    // First, normalize the raw rule by collapsing whitespace
    let normalized = rawRule.replace(/\s+/g, ' ').trim();

    // Find the opening parenthesis that starts the options
    const openParenIndex = normalized.indexOf('(');
    if (openParenIndex === -1) {
        return escapeHtml(normalized); // No options found
    }

    // Split header and options
    const header = normalized.substring(0, openParenIndex).trim();
    const optionsWithParens = normalized.substring(openParenIndex);

    // Remove outer parentheses
    const optionsContent = optionsWithParens.substring(1, optionsWithParens.length - 1);

    // Split by semicolons, but respect quoted strings
    let options = [];
    let current = '';
    let inQuotes = false;
    let escapeNext = false;

    for (let i = 0; i < optionsContent.length; i++) {
        const char = optionsContent[i];

        if (escapeNext) {
            current += char;
            escapeNext = false;
            continue;
        }

        if (char === '\\') {
            current += char;
            escapeNext = true;
            continue;
        }

        if (char === '"') {
            inQuotes = !inQuotes;
            current += char;
        } else if (char === ';' && !inQuotes) {
            const trimmed = current.trim();
            if (trimmed) {
                options.push(trimmed);
            }
            current = '';
        } else {
            current += char;
        }
    }

    // Add the last option if any
    const trimmed = current.trim();
    if (trimmed) {
        options.push(trimmed);
    }

    // Build formatted output (escape HTML for each part)
    let result = `<span class="rule-header-line">${escapeHtml(header)}</span> (\n`;

    options.forEach((opt, index) => {
        const isLast = index === options.length - 1;
        result += `    <span class="rule-option">${escapeHtml(opt)};</span>`;
        if (!isLast) {
            result += '\n';
        }
    });

    result += '\n)';

    return result;
}

// Update pagination controls
function updatePagination(data) {
    const totalPages = Math.ceil(data.total / data.page_size);
    const pageText = `Page ${data.page} of ${totalPages} (${data.total} rules)`;

    // Update top pagination
    const pageInfoTop = document.getElementById('page-info-top');
    const prevBtnTop = document.getElementById('prev-page-top');
    const nextBtnTop = document.getElementById('next-page-top');

    pageInfoTop.textContent = pageText;
    prevBtnTop.disabled = data.page <= 1;
    nextBtnTop.disabled = data.page >= totalPages;

    // Update bottom pagination
    const pageInfoBottom = document.getElementById('page-info-bottom');
    const prevBtnBottom = document.getElementById('prev-page-bottom');
    const nextBtnBottom = document.getElementById('next-page-bottom');

    pageInfoBottom.textContent = pageText;
    prevBtnBottom.disabled = data.page <= 1;
    nextBtnBottom.disabled = data.page >= totalPages;
}

// Change page
function changePage(delta) {
    currentPage += delta;
    loadRules();
}

// Show loading indicator
function showLoading() {
    document.getElementById('loading').style.display = 'block';
    document.querySelector('.table-wrapper').style.display = 'none';
}

// Hide loading indicator
function hideLoading() {
    document.getElementById('loading').style.display = 'none';
    document.querySelector('.table-wrapper').style.display = 'block';
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

// Format reference to clickable link
function formatReference(ref) {
    // Parse reference format: "type,value"
    // Common types: url, cve, bugtraq, nessus, mcafee, etc.
    const parts = ref.split(',', 2);

    if (parts.length !== 2) {
        return escapeHtml(ref);
    }

    const type = parts[0].toLowerCase().trim();
    const value = parts[1].trim();

    let url = '';
    let displayText = '';

    switch (type) {
        case 'url':
            // URL reference - add https:// if not present
            if (value.startsWith('http://') || value.startsWith('https://')) {
                url = value;
            } else {
                url = `https://${value}`;
            }
            displayText = value;
            break;

        case 'cve':
            url = `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${value}`;
            displayText = value;
            break;

        case 'bugtraq':
            url = `https://www.securityfocus.com/bid/${value}`;
            displayText = `BugTraq ${value}`;
            break;

        case 'nessus':
            url = `https://www.tenable.com/plugins/nessus/${value}`;
            displayText = `Nessus ${value}`;
            break;

        case 'mcafee':
            url = `https://www.mcafee.com/threat-intelligence/malware/default.aspx?id=${value}`;
            displayText = `McAfee ${value}`;
            break;

        default:
            // Unknown type, display as-is
            return escapeHtml(ref);
    }

    return `<a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer" class="reference-link">${escapeHtml(displayText)}</a>`;
}
