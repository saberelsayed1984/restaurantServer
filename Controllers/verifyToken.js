const jwt = require('jsonwebtoken');
const path = require('path');
const { fileURLToPath } = require('url');
const dotenv = require('dotenv');

const __dirname = path.dirname(fileURLToPath(import.meta.url));

dotenv.config({ path: path.join(__dirname, '../.env') });

function verifyToken(req, res, next) {
    if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
        try {
        const decoded = jwt.verify(
            req.headers.authorization.split(' ')[1],
            process.env.JWT_SECRET
        );
        req.user = decoded; // Store the decoded token in the req.user object for future use
        next(); // Continue to the next middleware or route handler
        } catch (err) {
        return res.status(401).json({
            error: true,
            status: 401,
            message: 'Invalid token',
        });
        }
    } else {
        return res.status(401).json({
        error: true,
        status: 401,
        message: 'Please provide a token',
        });
    }
    }

    module.exports = verifyToken;
