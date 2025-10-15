/**
 * Transforms page JavaScript
 */

// Track filter row counter for unique IDs
let filterRowCounter = 0;

// Load saved transforms on page load
document.addEventListener('DOMContentLoaded', () => {
    loadTransforms();
    setupFormHandlers();
    addFilterRow(); // Add initial filter row
});

/**
 * Load all saved transforms
 */
async function loadTransforms() {
    const container = document.getElementById('transforms-container');
    const loading = document.getElementById('loading-transforms');

    loading.style.display = 'block';

    try {
        const response = await fetch(`${API_BASE}/transforms`);
        if (!response.ok) {
            throw new Error('Failed to load transforms');
        }

        const transforms = await response.json();
        loading.style.display = 'none';

        if (transforms.length === 0) {
            container.innerHTML = '<p class="no-data">No transforms created yet.</p>';
            return;
        }

        // Display transforms
        container.innerHTML = transforms.map(e => {
            // Handle single or multiple criteria
            const criteriaList = Array.isArray(e.criteria) ? e.criteria : [e.criteria];
            const criteriaText = criteriaList.map((c, i) => {
                const prefix = criteriaList.length > 1 ? `${i + 1}. ` : '';
                return `${prefix}${escapeHtml(c.field)} ${escapeHtml(c.operator)} "${escapeHtml(String(c.value))}"${c.case_sensitive ? ' (case sensitive)' : ''}`;
            }).join('<br>');

            return `
            <div class="transform-card ${e.enabled ? '' : 'disabled'}">
                <div class="transform-header">
                    <h4>${escapeHtml(e.name)}</h4>
                    <div class="transform-actions">
                        <button class="btn-icon" onclick="runDryRun('${e.id}')" title="Run Dry Run">🔍</button>
                        <button class="btn-icon" onclick="toggleTransform('${e.id}', ${!e.enabled})" title="${e.enabled ? 'Disable' : 'Enable'}">
                            ${e.enabled ? '✓' : '○'}
                        </button>
                        <button class="btn-icon danger" onclick="deleteTransform('${e.id}')" title="Delete">✕</button>
                    </div>
                </div>
                ${e.description ? `<p class="transform-description">${escapeHtml(e.description)}</p>` : ''}
                <div class="transform-details">
                    <strong>Rule Filter${criteriaList.length > 1 ? 's (AND)' : ''}:</strong><br>${criteriaText}<br>
                    <strong>Actions:</strong> ${e.actions.map(a =>
                        `${escapeHtml(a.action_type)}${a.key ? ': ' + escapeHtml(a.key) : ''} = "${escapeHtml(String(a.value))}"`
                    ).join(', ')}
                </div>
            </div>
            `;
        }).join('');
    } catch (error) {
        loading.style.display = 'none';
        container.innerHTML = `<p class="error-message">Error loading transforms: ${escapeHtml(error.message)}</p>`;
    }
}

/**
 * Add a new filter row
 */
function addFilterRow() {
    const container = document.getElementById('criteria-container');
    const rowId = filterRowCounter++;

    const filterRow = document.createElement('div');
    filterRow.className = 'criteria-section';
    filterRow.dataset.rowId = rowId;
    filterRow.innerHTML = `
        <div class="form-group">
            <label for="criteria-field-${rowId}">Field:</label>
            <select id="criteria-field-${rowId}" class="criteria-field">
                <option value="msg">Message</option>
                <option value="category">Category</option>
                <option value="action">Action</option>
                <option value="protocol">Protocol</option>
                <option value="source">Source</option>
                <option value="classtype">Class Type</option>
                <option value="metadata.signature_severity">Metadata: Severity</option>
                <option value="metadata.attack_target">Metadata: Attack Target</option>
            </select>
        </div>

        <div class="form-group">
            <label for="criteria-operator-${rowId}">Operator:</label>
            <select id="criteria-operator-${rowId}" class="criteria-operator">
                <option value="contains">Contains</option>
                <option value="exact_match">Exact Match</option>
                <option value="regex">Regex</option>
                <option value="in_list">In List</option>
            </select>
        </div>

        <div class="form-group">
            <label for="criteria-value-${rowId}">Value:</label>
            <input type="text" id="criteria-value-${rowId}" class="criteria-value" required placeholder="e.g., FTP">
        </div>

        <div class="form-group">
            <label>
                <input type="checkbox" id="criteria-case-sensitive-${rowId}" class="criteria-case-sensitive">
                Case Sensitive
            </label>
        </div>

        <div class="form-group">
            <button type="button" class="btn btn-danger btn-sm" onclick="removeFilterRow(${rowId})" title="Remove Filter">✕</button>
        </div>
    `;

    container.appendChild(filterRow);
}

/**
 * Remove a filter row
 */
function removeFilterRow(rowId) {
    const container = document.getElementById('criteria-container');
    const rows = container.querySelectorAll('.criteria-section');

    // Don't allow removing the last filter
    if (rows.length <= 1) {
        alert('You must have at least one filter');
        return;
    }

    const row = container.querySelector(`[data-row-id="${rowId}"]`);
    if (row) {
        row.remove();
    }
}

/**
 * Setup form event handlers
 */
function setupFormHandlers() {
    const form = document.getElementById('create-transform-form');
    const testFilterBtn = document.getElementById('test-filter-btn');
    const addFilterBtn = document.getElementById('add-filter-btn');
    const closeModalBtn = document.getElementById('close-test-modal');
    const modal = document.getElementById('test-filter-modal');

    if (!form || !testFilterBtn || !addFilterBtn) {
        console.error('Form elements not found!');
        return;
    }

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        await createTransform();
    });

    testFilterBtn.addEventListener('click', async () => {
        await testFilter();
    });

    addFilterBtn.addEventListener('click', () => {
        addFilterRow();
    });

    // Close modal when clicking X
    if (closeModalBtn) {
        closeModalBtn.addEventListener('click', () => {
            modal.style.display = 'none';
        });
    }

    // Close modal when clicking outside
    window.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.style.display = 'none';
        }
    });
}

/**
 * Build transform object from form
 */
function buildTransformFromForm() {
    const container = document.getElementById('criteria-container');
    const filterRows = container.querySelectorAll('.criteria-section');

    // Collect all criteria from filter rows
    const criteriaList = Array.from(filterRows).map(row => {
        const field = row.querySelector('.criteria-field').value;
        const operator = row.querySelector('.criteria-operator').value;
        const value = row.querySelector('.criteria-value').value;
        const caseSensitive = row.querySelector('.criteria-case-sensitive').checked;

        return {
            field,
            operator,
            value,
            case_sensitive: caseSensitive
        };
    });

    // If only one filter, send as single object; otherwise send as array
    const criteria = criteriaList.length === 1 ? criteriaList[0] : criteriaList;

    return {
        name: document.getElementById('transform-name').value,
        description: document.getElementById('transform-description').value || null,
        enabled: true,
        criteria: criteria,
        actions: [
            {
                action_type: document.getElementById('action-type').value,
                key: document.getElementById('action-key').value || null,
                value: document.getElementById('action-value').value
            }
        ]
    };
}

/**
 * Test filter (dry run) - shows results in modal
 */
async function testFilter() {
    const transform = buildTransformFromForm();

    try {
        const response = await fetch(`${API_BASE}/transforms/test`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(transform)
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Failed to test filter: ${errorText}`);
        }

        const result = await response.json();
        displayModalResults(result);
    } catch (error) {
        alert(`Error testing filter: ${error.message}`);
    }
}

/**
 * Create new transform
 */
async function createTransform() {
    const transform = buildTransformFromForm();

    try {
        const response = await fetch(`${API_BASE}/transforms`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(transform)
        });

        if (!response.ok) {
            throw new Error('Failed to create transform');
        }

        alert('Transform created successfully!');

        // Clear form
        document.getElementById('create-transform-form').reset();

        // Clear all filter rows and add one fresh row
        const container = document.getElementById('criteria-container');
        container.innerHTML = '';
        filterRowCounter = 0;
        addFilterRow();

        // Reload list
        loadTransforms();
    } catch (error) {
        alert(`Error creating transform: ${error.message}`);
    }
}

/**
 * Run dry run for existing transform
 */
async function runDryRun(transformId) {
    try {
        const response = await fetch(`${API_BASE}/transforms/${transformId}/dry-run`, {
            method: 'POST'
        });

        if (!response.ok) {
            throw new Error('Failed to run dry run');
        }

        const result = await response.json();
        displayModalResults(result);
    } catch (error) {
        alert(`Error running dry run: ${error.message}`);
    }
}

/**
 * Display filter summary from form inputs
 */
function displayFilterSummary() {
    const container = document.getElementById('criteria-container');
    const filterRows = container.querySelectorAll('.criteria-section');
    const summary = document.getElementById('modal-filter-summary');

    const criteriaItems = Array.from(filterRows).map((row, index) => {
        const field = row.querySelector('.criteria-field');
        const operator = row.querySelector('.criteria-operator');
        const value = row.querySelector('.criteria-value').value;
        const caseSensitive = row.querySelector('.criteria-case-sensitive').checked;

        const fieldText = field.options[field.selectedIndex].text;
        const operatorText = operator.options[operator.selectedIndex].text;

        const prefix = filterRows.length > 1 ? `<strong>Filter ${index + 1}:</strong> ` : '';
        const caseSensitiveText = caseSensitive ? ' (case sensitive)' : '';

        return `<div class="filter-summary-item">${prefix}${escapeHtml(fieldText)} ${escapeHtml(operatorText)} "${escapeHtml(value)}"${caseSensitiveText}</div>`;
    }).join('');

    const andNote = filterRows.length > 1 ? '<div class="filter-summary-item"><em>All filters must match (AND logic)</em></div>' : '';

    summary.innerHTML = criteriaItems + andNote;
}

/**
 * Display filter test results in modal
 */
function displayModalResults(result) {
    const modal = document.getElementById('test-filter-modal');

    // Display filter summary
    displayFilterSummary();

    // Update total with "X / Y" format
    const percentage = result.total_rules > 0
        ? ((result.total_matched / result.total_rules) * 100).toFixed(1)
        : 0;
    document.getElementById('modal-total-matched').textContent =
        `${result.total_matched.toLocaleString()} / ${result.total_rules.toLocaleString()} (${percentage}%)`;

    // Update breakdowns
    displayBreakdown('modal-breakdown-source', result.breakdown_by_source);
    displayBreakdown('modal-breakdown-category', result.breakdown_by_category);
    displayBreakdown('modal-breakdown-action', result.breakdown_by_action);

    // Update example matches
    const tbody = document.getElementById('modal-example-matches-body');
    if (result.example_matches.length === 0) {
        if (result.total_matched === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="no-data"><strong>No rules matched your filter.</strong><br>Try adjusting your filter criteria.</td></tr>';
        } else {
            tbody.innerHTML = '<tr><td colspan="4">No matches found</td></tr>';
        }
    } else {
        tbody.innerHTML = result.example_matches.map(match => `
            <tr>
                <td>${match.sid}</td>
                <td>${escapeHtml(match.msg)}</td>
                <td>${escapeHtml(match.source || '(unknown)')}</td>
                <td>${escapeHtml(match.category || '(unset)')}</td>
            </tr>
        `).join('');
    }

    // Show modal
    modal.style.display = 'block';
}

/**
 * Display breakdown data
 */
function displayBreakdown(elementId, data) {
    const container = document.getElementById(elementId);

    if (Object.keys(data).length === 0) {
        container.innerHTML = '<p class="no-data">No data</p>';
        return;
    }

    container.innerHTML = Object.entries(data)
        .sort((a, b) => b[1] - a[1])
        .map(([key, value]) => `
            <div class="breakdown-item">
                <span class="breakdown-key">${escapeHtml(key)}</span>
                <span class="breakdown-value">${value}</span>
            </div>
        `).join('');
}

/**
 * Toggle transform enabled/disabled
 */
async function toggleTransform(transformId, enable) {
    const action = enable ? 'enable' : 'disable';

    try {
        const response = await fetch(`${API_BASE}/transforms/${transformId}/${action}`, {
            method: 'POST'
        });

        if (!response.ok) {
            throw new Error(`Failed to ${action} transform`);
        }

        loadTransforms();
    } catch (error) {
        alert(`Error: ${error.message}`);
    }
}

/**
 * Delete transform
 */
async function deleteTransform(transformId) {
    if (!confirm('Are you sure you want to delete this transform?')) {
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/transforms/${transformId}`, {
            method: 'DELETE'
        });

        if (!response.ok) {
            throw new Error('Failed to delete transform');
        }

        loadTransforms();
    } catch (error) {
        alert(`Error deleting transform: ${error.message}`);
    }
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
