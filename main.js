// Include the dependencies
//need sorted
const mysql = require('mysql');
const express = require('express');
const session = require('express-session');
const path = require('path');
const nunjucks = require('nunjucks');
const nodemailer = require('nodemailer');
const dotenv = require("dotenv");
const uuidv1 = require('uuid/v1');
const cookieParser = require('cookie-parser');
const cryptography = require('crypto');
const fs = require('fs');
const fetch = require('node-fetch');
const { Console } = require('console');

//file path for dotenv
dotenv.config({ path: './components/.env'});

// Initialize express
const app = express();

// Configure nunjucks template engine
const env = nunjucks.configure('views', {
  	autoescape: true,
  	express: app
});
env.addFilter('formatNumber', num => String(num).replace(/(.)(?=(\d{3})+$)/g,'$1,'));
env.addFilter('formatDateTime', date => (new Date(date).toISOString()).slice(0, -1).split('.')[0]);
// Use sessions and other dependencies
app.use(session({
	//secret: secret_key,
	secret: process.env.SESSION_KEY,
	resave: true,
	saveUninitialized: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'static')));
app.use(cookieParser());

console.log("Database Address: " + process.env.DATABASE_HOST)
console.log("Database Name: " + process.env.DATABASE)

//required routes
app.use('/', require('./routes/userRoutes'));
app.use('/postRoutes', require('./routes/postRoutes'));

// Listen on port 3000 (http://localhost:3000/)
app.listen(3000);

//server start time
const currentTime = new Date();
console.log("Server started on: " + currentTime)