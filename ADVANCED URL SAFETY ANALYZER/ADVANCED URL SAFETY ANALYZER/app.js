function displayResults(data) {
    const resultSection = document.getElementById('resultSection');
    
    let statusClass = 'warning';
    let statusIcon = '⚠️';
    let statusText = 'Needs Caution';

    if (data.is_safe && data.risk_level === 'low') {
        statusClass = 'safe';
        statusIcon = '✅';
        statusText = 'SAFE';
    } else if (data.risk_level === 'high' || !data.is_safe) {
        statusClass = 'unsafe';
        statusIcon = '❌';
        statusText = 'UNSAFE';
    }

    let resultHTML = `
        <div class="safety-status ${statusClass}">
            ${statusIcon} <span style="font-size: 1.5em;">${statusText}</span>
            <div style="margin-top: 10px; font-size: 0.9em;">
                Analysis of: <strong>${data.url}</strong>
            </div>
        </div>

        <div class="analysis-grid">
            <div class="analysis-card">
                <h3>🔒 SSL & Security</h3>
                <ul>
                    <li>
                        <span class="icon ${data.ssl_info.has_ssl ? 'success' : 'danger'}">${data.ssl_info.has_ssl ? '✅' : '❌'}</span>
                        SSL Certificate: ${data.ssl_info.has_ssl ? 'Valid' : 'Invalid/Missing'}
                    </li>
                    <li>
                        <span class="icon ${data.ssl_info.valid_ssl ? 'success' : 'warning-icon'}">${data.ssl_info.valid_ssl ? '✅' : '⚠️'}</span>
                        Certificate Valid: ${data.ssl_info.valid_ssl ? 'Yes' : 'No'}
                    </li>
                    <li>
                        <span class="icon info">📅</span>
                        Days Until Expiry: ${data.ssl_info.days_until_expiry || 'N/A'}
                    </li>
                    <li>
                        <span class="icon info">🏢</span>
                        Issuer: ${data.ssl_info.issuer || 'Unknown'}
                    </li>
                </ul>
            </div>

            <div class="analysis-card">
                <h3>🌐 Hosting Information</h3>
                <ul>
                    <li>
                        <span class="icon info">📍</span>
                        IP Address: ${data.hosting_info.ip_address || 'Unknown'}
                    </li>
                    <li>
                        <span class="icon info">🏢</span>
                        Organization: ${data.hosting_info.organization || 'Unknown'}
                    </li>
                    <li>
                        <span class="icon ${data.hosting_info.exists ? 'success' : 'danger'}">${data.hosting_info.exists ? '✅' : '❌'}</span>
                        Website Accessible: ${data.hosting_info.exists ? 'Yes' : 'No'}
                    </li>
                    <li>
                        <span class="icon info">📅</span>
                        Domain Age: ${data.security_analysis.domain_age || 'Unknown'}
                    </li>
                </ul>
            </div>

            <div class="analysis-card">
                <h3>📊 Security Analysis</h3>
                <ul>
                    <li>
                        <span class="icon ${data.security_analysis.valid_domain ? 'success' : 'danger'}">${data.security_analysis.valid_domain ? '✅' : '❌'}</span>
                        Valid Domain: ${data.security_analysis.valid_domain ? 'Yes' : 'No'}
                    </li>
                    <li>
                        <span class="icon ${data.security_analysis.has_https ? 'success' : 'warning-icon'}">${data.security_analysis.has_https ? '✅' : '⚠️'}</span>
                        Uses HTTPS: ${data.security_analysis.has_https ? 'Yes' : 'No'}
                    </li>
                    <li>
                        <span class="icon ${data.security_analysis.redirects_https ? 'success' : 'info'}">${data.security_analysis.redirects_https ? '✅' : 'ℹ️'}</span>
                        Redirects to HTTPS: ${data.security_analysis.redirects_https ? 'Yes' : 'No'}
                    </li>
                    <li>
                        <span class="icon info">⚡</span>
                        Response Time: ${data.security_analysis.response_time || 'N/A'}ms
                    </li>
                </ul>
            </div>
        </div>
    `;

    // Add warnings if any
    if (data.warnings && data.warnings.length > 0) {
        resultHTML += `
            <div class="analysis-card" style="grid-column: 1 / -1;">
                <h3>⚠️ Security Warnings</h3>
                <ul>
                    ${data.warnings.map(warning => `<li><span class="icon warning-icon">⚠️</span> ${warning}</li>`).join('')}
                </ul>
            </div>
        `;
    }

    // Add website content preview if available
    if (data.content_analysis && data.content_analysis.title) {
        resultHTML += `
            <div class="website-preview">
                <h3>📄 Website Content Preview</h3>
                <div class="preview-content">
                    <div class="detail-item">
                        <span class="detail-label">Title:</span> ${data.content_analysis.title}
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Description:</span> ${data.content_analysis.description || 'Not available'}
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Content Type:</span> ${data.content_analysis.content_type || 'Unknown'}
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Content Length:</span> ${data.content_analysis.content_length || 0} characters
                    </div>
                    ${data.content_analysis.has_login_fields ? `
                    <div class="detail-item">
                        <span class="detail-label warning-icon">⚠️ Contains login forms:</span> Yes
                    </div>` : ''}
                </div>
            </div>
        `;
    }

    // Add error information if present
    if (data.error) {
        resultHTML += `
            <div class="analysis-card" style="grid-column: 1 / -1; border-left-color: #e74c3c;">
                <h3>❌ Analysis Errors</h3>
                <p>${data.error}</p>
            </div>
        `;
    }

    resultSection.innerHTML = resultHTML;
    resultSection.style.display = 'block';
}