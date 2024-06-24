const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cors = require("cors"); 
require('dotenv').config();
const usersRouter = require('./routres/routUser.js');
const app = express(); 
app.use(cors({
    origin: "*",
    methods: "GET,POST,PUT,DELETE,",
    Credential: true,
}))
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.urlencoded({ extended: true }))
app.use(express.json());
app.use('/v1/api/users', usersRouter);
app.use('/v2/password', usersRouter)
// app.use('/v1/api/food', routerFood)
app.get('/', (req, res) => {
    app.use((error, req, res, next) => {
        res.status(error.statusCode || 500).json({status: error.statusText || httpStatusText.ERROR,
            message:error.message, code: error.statusCode || 500, data: null})
        });})
const dbURI = process.env.mongoUrl;

async function connect() {
    try {
        
        await mongoose.connect(dbURI);

        console.log("Connected to the database");
    } catch (error) {
        console.error("Error connecting to the database: ", error);
    }
}

connect ()
        .then(() => {
    try {
        app.listen(port, () => {
            console.log(`server connected to http://localhost:${port}`)
        })
    }
    catch (error) {
        console.log("cannot connect to the server") 
    } }).catch(error => {
        console.log("Invalid Database connection")
    })
const port = process.env.PORT;
