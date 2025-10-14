// Audio elements for sound effects
const scanStartSound = new Audio('/sounds/scan-start.mp3');
const scanCompleteSound = new Audio('/sounds/scan-complete.mp3');
const pulseSound = new Audio('/sounds/pulse.mp3');

// Configure audio properties
scanStartSound.volume = 0.5;
scanCompleteSound.volume = 0.4;
pulseSound.volume = 0.3;

// Preload sounds
scanStartSound.load();
scanCompleteSound.load();
pulseSound.load();

const loaderMessages = [
    "Initializing Scan Sequence...",
    "Analyzing Target Structure...",
    "Probing Security Parameters...",
    "Scanning Network Topology...",
    "Detecting Vulnerabilities...",
    "Processing Security Headers...",
    "Identifying Technologies..."
];

function updateLoaderText() {
    const loaderText = document.querySelector('.loader-text');
    let messageIndex = 0;

    return setInterval(() => {
        loaderText.textContent = loaderMessages[messageIndex];
        messageIndex = (messageIndex + 1) % loaderMessages.length;
    }, 2000);
}

document.getElementById('reconForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    const target = document.getElementById('target').value;
    const resultsSection = document.getElementById('results');
    const scanStatus = document.getElementById('scanStatus');
    const cyberLoader = document.getElementById('cyberLoader');

    try {
        // Play scan start sound
        scanStartSound.currentTime = 0;
        scanStartSound.play();

        // Start pulse sound
        const pulseInterval = setInterval(() => {
            pulseSound.currentTime = 0;
            pulseSound.play();
        }, 2000);

        // Show loader and start message rotation
        cyberLoader.classList.add('active');
        const messageInterval = updateLoaderText();

        // Hide results section until scan is complete
        resultsSection.style.display = 'none';
        scanStatus.textContent = 'Scanning...';
        scanStatus.style.color = 'var(--accent-color)';

        // Make API request
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: target })
        });

        if (!response.ok) {
            throw new Error('Scan failed');
        }

        const data = await response.json();

        // Update status and hide loader
        clearInterval(messageInterval);
        clearInterval(pulseInterval);
        cyberLoader.classList.remove('active');
        resultsSection.style.display = 'block';
        scanStatus.textContent = 'Completed';
        scanStatus.style.color = '#00ff00';

        // Play completion sound
        scanCompleteSound.currentTime = 0;
        scanCompleteSound.play();

        // Display results
        displayResults(data);
    } catch (error) {
        console.error('Error:', error);
        clearInterval(messageInterval);
        clearInterval(pulseInterval);
        cyberLoader.classList.remove('active');
        resultsSection.style.display = 'block';
        scanStatus.textContent = 'Failed';
        scanStatus.style.color = '#ff0000';
    }
});


function displayResults(data) {

    // This section has been moved up to combine with server info

    // Display web server info and contact info
    const serverContent = document.querySelector('#location .content');
    serverContent.innerHTML = `
        <div class="server-info">
            <p><strong>Server:</strong> ${data.server?.name || 'Unknown'} ${data.server?.version || ''}</p>
            ${(data.contact && (data.contact.email || data.contact.phone)) ? `
                <p><strong>Contact Email:</strong> ${data.contact.email || 'Not found'}</p>
                <p><strong>Contact Phone:</strong> ${data.contact.phone || 'Not found'}</p>
            ` : ''}
            ${data.location ? `
                <p><strong>IP:</strong> ${data.location.ip}</p>
                <p><strong>City:</strong> ${data.location.city}</p>
                <p><strong>Region:</strong> ${data.location.region}</p>
                <p><strong>Country:</strong> ${data.location.country}</p>
                <p><strong>ISP:</strong> ${data.location.isp}</p>
            ` : '<p class="no-results">Location data not available</p>'}
        </div>
    `;

    // Display vulnerabilities
    const vulnContent = document.querySelector('#vulnerabilities .content');
    vulnContent.innerHTML = data.vulnerabilities.length ? data.vulnerabilities.map(vuln => `
        <div class="vuln-item severity-${vuln.severity.toLowerCase()}">
            <h4>${vuln.type}</h4>
            <p>${vuln.description}</p>
            <span class="severity">${vuln.severity}</span>
        </div>
    `).join('') : '<p class="no-results">No vulnerabilities found</p>';

    // Display open ports
    console.log("Open Ports",data.openPorts);
    const portsContent = document.querySelector('#openPorts .content');
    portsContent.innerHTML = data.openPorts.length ? `
        <ul>${data.openPorts.map(port => `<li>${port.service} Port: ${port.port} ${port.state}</li>`).join('')}</ul>
    ` : '<p class="no-results">No open ports detected</p>';

    // Display security headers
    const headersContent = document.querySelector('#headers .content');
    headersContent.innerHTML = `
        <div class="headers-present">
            <h4>Present Headers</h4>
            ${data.securityHeaders.length ? `
                <ul>${data.securityHeaders.map(h => `
                    <li>${h.header}</li>
                `).join('')}</ul>
            ` : '<p class="no-results">No security headers found</p>'}
        </div>
        <div class="headers-missing">
            <h4>Missing Headers</h4>
            ${data.missingSecurityHeaders.length ? `
                <ul>${data.missingSecurityHeaders.map(h => `
                    <li>${h}</li>
                `).join('')}</ul>
            ` : '<p class="no-results">All security headers are present</p>'}
        </div>
    `;

    // Display technologies
    const techGrid = document.querySelector('#technologies .tech-grid');
    techGrid.innerHTML = data.technologies.length ?
        data.technologies.map(tech => `
            <div class="tech-item">
                <div class="tech-icon">⚡</div>
                <div class="tech-name">${tech.name}</div>
                <div class="tech-type">${tech.type}</div>
            </div>
        `).join('') : '<p class="no-results">No technologies detected</p>';
}
