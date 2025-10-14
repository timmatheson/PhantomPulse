const axios = require('axios');
const cheerio = require('cheerio');
const net = require('net');
const https = require('https');
const tls = require('tls');
const dns = require('dns').promises;
const { promisify } = require('util');

class Scanner {
    constructor(url) {
        this.url = url;
        this.results = {
            headers: null,
            openPorts: [],
            vulnerabilities: [],
            technologies: [],
            securityHeaders: [],
            missingSecurityHeaders: [],
            ssl: {
                valid: false,
                issuer: null,
                validFrom: null,
                validTo: null,
                protocol: null,
                cipher: null
            },
            subdomains: [],
            location: {
                ip: null,
                country: null,
                city: null,
                coordinates: {
                    latitude: null,
                    longitude: null
                }
            },
            server: {
                name: null,
                version: null
            }
        };
    }

    parseServerHeader(header) {
        if (!header) return null;
        
        // Common server header patterns
        const patterns = {
            apache: /^Apache\/?(\d+[\.\d]*)?/i,
            nginx: /^nginx\/?(\d+[\.\d]*)?/i,
            iis: /^Microsoft-IIS\/(\d+[\.\d]*)/i,
            lighttpd: /^lighttpd\/(\d+[\.\d]*)/i,
            nodejs: /^Node\.js\/(\d+[\.\d]*)/i,
            express: /^Express\/(\d+[\.\d]*)/i
        };

        for (const [server, pattern] of Object.entries(patterns)) {
            const match = header.match(pattern);
            if (match) {
                return {
                    name: server.charAt(0).toUpperCase() + server.slice(1),
                    version: match[1] || null
                };
            }
        }

        // For custom or unrecognized server headers, return the full string
        return {
            name: header,
            version: null
        };
    }

    async analyzeHeaders(headers) {
        const securityHeaders = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection',
            'Referrer-Policy'
        ];

        this.results.headers = headers;

        // Detect web server from Server header
        if (headers['server']) {
            this.results.server = this.parseServerHeader(headers['server']);
        }

        // Check for alternative server headers
        const altServerHeaders = ['x-powered-by', 'x-server', 'x-server-name'];
        for (const header of altServerHeaders) {
            if (headers[header] && !this.results.server.name) {
                this.results.server = this.parseServerHeader(headers[header]);
                break;
            }
        }

        securityHeaders.forEach(header => {
            if (headers[header.toLowerCase()]) {
                this.results.securityHeaders.push({
                    header,
                    value: headers[header.toLowerCase()]
                });
            } else {
                this.results.missingSecurityHeaders.push(header);
            }
        });

        // Check for sensitive headers
        const sensitiveHeaders = ['server', 'x-powered-by'];
        sensitiveHeaders.forEach(header => {
            if (headers[header]) {
                this.results.vulnerabilities.push({
                    type: 'Information Disclosure',
                    description: `Sensitive header '${header}' exposed`,
                    severity: 'Medium'
                });
            }
        });
    }

    async checkPort(host, port) {
        return new Promise((resolve) => {
            const socket = new net.Socket();
            const timeout = 1000;

            socket.setTimeout(timeout);

            socket.on('connect', () => {
                socket.destroy();
                resolve(true);
            });

            socket.on('timeout', () => {
                socket.destroy();
                resolve(false);
            });

            socket.on('error', () => {
                socket.destroy();
                resolve(false);
            });

            socket.connect(port, host);
        });
    }

    async scanPorts() {
        const commonPorts = [80, 443, 8080, 8443, 21, 22, 23, 25, 3306, 5432];
        const hostname = new URL(this.url).hostname;

        for (const port of commonPorts) {
            try {
                const isOpen = await this.checkPort(hostname, port);
                if (isOpen) {
                    const service = this.getServiceName(port);
                    this.results.openPorts.push({
                        port: port,
                        service: service,
                        state: 'open'
                    });

                    if (![80, 443].includes(port)) {
                        this.results.vulnerabilities.push({
                            type: 'Open Port',
                            description: `Port ${port} (${service}) is open and may expose sensitive services`,
                            severity: 'High'
                        });
                    }
                }
            } catch (error) {
                console.error(`Error scanning port ${port}:`, error);
            }
        }
    }

    getServiceName(port) {
        const services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            80: 'HTTP',
            443: 'HTTPS',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            8080: 'HTTP-Alternate',
            8443: 'HTTPS-Alternate'
        };
        return services[port] || 'Unknown';
    }

    async checkSSL() {
        try {
            const hostname = new URL(this.url).hostname;
            const options = {
                host: hostname,
                port: 443,
                method: 'GET',
                rejectUnauthorized: false,
            };

            return new Promise((resolve, reject) => {
                const req = https.request(options, (res) => {
                    const cert = res.socket.getPeerCertificate();
                    const protocol = res.socket.getProtocol();
                    const cipher = res.socket.getCipher();

                    try{
                      this.results.ssl = {
                        valid: res.socket.authorized,
                        issuer: cert.issuer?.O || cert.issuer?.CN,
                        validFrom: new Date(cert.valid_from).toISOString(),
                        validTo: new Date(cert.valid_to).toISOString(),
                        protocol: protocol,
                        cipher: cipher.name,
                        bits: cipher.bits
                    };
                    }catch(e){
                      this.results.ssl = {
                          valid: "unknown",
                          issuer: "unknown",
                          validFrom: "unknown",
                          validTo: "unknown",
                          protocol: "unknown",
                          cipher: "unknown",
                          bits: "unknown"
                      };
                      console.error('Error processing SSL certificate:', e);
                    }
                    resolve();
                });

                req.on('error', (error) => {
                    console.error('SSL check error:', error);
                    resolve();
                });

                req.end();
            });
        } catch (error) {
            console.error('SSL check error:', error);
        }
    }

    async findSubdomains() {
        try {
            const hostname = new URL(this.url).hostname;
            const baseDomain = hostname.split('.').slice(-2).join('.');
            const commonSubdomains = ['www', 'mail', 'ftp', 'webmail', 'admin', 'test', 'dev', 'staging', 'api', 'blog'];

            for (const sub of commonSubdomains) {
                const subdomain = `${sub}.${baseDomain}`;
                try {
                    const addresses = await dns.resolve4(subdomain);
                    if (addresses && addresses.length > 0) {
                        this.results.subdomains.push({
                            subdomain: subdomain,
                            ip: addresses[0]
                        });
                    }
                } catch (error) {
                    // Subdomain not found, skip
                }
            }
        } catch (error) {
            console.error('Subdomain enumeration error:', error);
        }
    }

    async getLocationInfo() {
        try {
            const hostname = new URL(this.url).hostname;
            const ip = (await dns.resolve4(hostname))[0];

            // Use ip-api.com for geolocation (free, no API key required)
            const geoResponse = await axios.get(`http://ip-api.com/json/${ip}`);
            const geoData = geoResponse.data;

            if (geoData.status === 'success') {
                this.results.location = {
                    ip: ip,
                    country: geoData.country,
                    city: geoData.city,
                    coordinates: {
                        latitude: geoData.lat,
                        longitude: geoData.lon
                    }
                };
            }
        } catch (error) {
            console.error('Location detection error:', error);
        }
    }

    async checkCommonVulnerabilities(html) {
        const $ = cheerio.load(html);

        // Check for unencrypted form submissions
        $('form').each((i, form) => {
            const action = $(form).attr('action');
            if (action && action.startsWith('http://')) {
                this.results.vulnerabilities.push({
                    type: 'Insecure Form',
                    description: 'Form submits data over unencrypted HTTP',
                    severity: 'High'
                });
            }
        });

        // Check for mixed content
        $('script, link, img').each((i, el) => {
            const src = $(el).attr('src') || $(el).attr('href');
            if (src && src.startsWith('http://')) {
                this.results.vulnerabilities.push({
                    type: 'Mixed Content',
                    description: 'Page loads resources over unencrypted HTTP',
                    severity: 'Medium'
                });
            }
        });

        // Detect technologies
        if ($('meta[name="generator"]').length) {
            this.results.technologies.push({
                name: $('meta[name="generator"]').attr('content'),
                type: 'CMS'
            });
        }

        // Common JavaScript frameworks
        const frameworks = {
            'react': '[data-reactroot], .react',
            'angular': '[ng-controller], [ng-app]',
            'vue': '[v-bind], [v-model]',
            'jquery': 'script[src*="jquery"]'
        };

        for (const [framework, selector] of Object.entries(frameworks)) {
            if ($(selector).length) {
                this.results.technologies.push({
                    name: framework,
                    type: 'Framework'
                });
            }
        }
    }
}

async function scanTarget(url) {
    const scanner = new Scanner(url);

    try {
        // Perform initial HTTP request
        const response = await axios.get(url, {
            headers: {
                'User-Agent': 'PhantomPulse Security Scanner 1.0'
            },
            validateStatus: false, // Allow all HTTP status codes
            timeout: 10000
        });

        // Analyze response headers
        await scanner.analyzeHeaders(response.headers);

        // Scan common ports
        await scanner.scanPorts();

        // Check for common vulnerabilities in the HTML
        await scanner.checkCommonVulnerabilities(response.data);

        // Get location information
        await scanner.getLocationInfo();

        // Check SSL certificate
        await scanner.checkSSL();

        // Find subdomains
        await scanner.findSubdomains();

        return scanner.results;

    } catch (error) {
        console.error('Scan error:', error);
        throw new Error('Failed to complete security scan');
    }
}

module.exports = { scanTarget };
