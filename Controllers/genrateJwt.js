const jwt = require("jsonwebtoken");
const path = require("path");
const { fileURLToPath } = require("url");
const dotenv = require("dotenv");


module.exports = function generateToken(payload) {
const token = jwt.sign(
    payload,
    process.env.JWT_SECRET,
    { expiresIn: process.env.TOKEN_EXPIRATION }
    );
return token;
};
