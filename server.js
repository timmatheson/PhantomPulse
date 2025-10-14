const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');
const { scanTarget } = require('./utils/scanner');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"]
        }
    }
}));
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Rate limiting setup
const rateLimit = require('express-rate-limit');
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});

app.use('/api/', limiter);

// Validation middleware
const validateScanRequest = (req, res, next) => {
    const { url } = req.body;

    try {
        new URL(url);
        next();
    } catch (error) {
        res.status(400).json({ error: 'Invalid URL provided' });
    }
};

// Scan endpoint
app.post('/api/scan', validateScanRequest, async (req, res) => {
    try {
        const { url } = req.body;
        const results = await scanTarget(url);
        res.json(results);
    } catch (error) {
        console.error('Scan error:', error);
        res.status(500).json({
            error: 'Error during scan',
            message: error.message
        });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'development' ? err.message : 'An error occurred'
    });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Access the application at http://localhost:${PORT}`);
});
