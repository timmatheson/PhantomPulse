# PhantomPulse

PhantomPulse is a modern, cyber-themed network and website reconnaissance tool. It provides a visually engaging interface for scanning websites and networks, displaying results with a dark, hacker-inspired UI.

## Features
- **Target Scan:** Enter a URL to scan for open ports, vulnerabilities, security headers, technologies, and more.
- **World Location:** Shows IP geolocation and ISP information for the target.
- **Web Server Detection:** Detects and displays the web server and version.
- **Contact Info:** Attempts to retrieve domain contact email and phone from public WHOIS data.
- **SSL Analysis:** Checks SSL certificate validity and details.
- **Subdomain Enumeration:** Finds common subdomains for the target domain.
- **Vulnerability Checks:** Looks for common web vulnerabilities and misconfigurations.
- **Sound Effects:** Plays cyberpunk-style sounds during scan and on completion.

## Usage
1. **Install dependencies:**
   ```bash
   npm install
   ```
2. **Start the server:**
   ```bash
   npm start
   ```
3. **Open your browser:**
   Go to [http://localhost:3000](http://localhost:3000)
4. **Scan a target:**
   Enter a website URL (e.g., `https://example.com`) and click "Initialize Scan".

## Project Structure
- `public/` - Frontend HTML, CSS, JS, and sound files
- `utils/scanner.js` - Main scanning logic (headers, ports, SSL, WHOIS, etc.)
- `server.js` - Express server and API endpoint

## Notes
- WHOIS contact info may not be available for all domains (privacy-protected or some TLDs).
- Sound files must be placed in `public/sounds/` as described in the code comments.
- For best results, run as administrator/root if you want to scan privileged ports (<1024).

## License
MIT
