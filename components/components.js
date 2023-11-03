//common functions that are widely used in multiple files
//needs sorted
const fs = require('fs');
const path = require('path');
const nodemailer = require('nodemailer');
const db = require('./db')

//emailer
const transporter = nodemailer.createTransport({
	host: 'smtp.gmail.com',
	port: 465,
	secure: true,
	auth: {
		user: 'xxxxxx@xxxxxx.xxx',
		pass: 'xxxxxx'
	}
});

// Function that checks whether the user is logged-in or not
const isLoggedin = (request, callback, callback2) => {
	// Check if the loggedin param exists in session
	init(request, settings => {
		if (request.session.account_loggedin) {
			return callback !== undefined ? callback(settings) : false;
		} else if (request.cookies.rememberme) {
			// if the remember me cookie exists check if an account has the same value in the database
			db.query('SELECT * FROM accounts WHERE rememberme = ?', [request.cookies.rememberme], (error, accounts, fields) => {
				if (accounts.length > 0) {
					request.session.account_loggedin = true;
					request.session.account_id = accounts[0].id;
					request.session.account_username = accounts[0].username;
					request.session.account_role = accounts[0].role;
					request.session.account_password = accounts[0].password;
					return callback !== undefined ? callback(settings) : false;
				} else {
					return callback2 !== undefined ? callback2(settings) : false;
				}
			});
		} else {
			return callback2 !== undefined ? callback2(settings) : false;
		}
	});
};

// Function is admin
//????????
//not sure if this needs deleted
const isAdmin = (request, callback, callback2) => {
	isLoggedin(request, () => {
		if (request.session.account_role == 'Admin') {
			callback();
		} else {
			callback2();
		}
	}, callback2);
};

// Function init - check loggedin and retrieve settings
const init = (request, callback) => {
	if (request.session.account_loggedin) {
		// Update last seen date
		let d = new Date();
		let now = (new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString()).slice(0, -1).split('.')[0];
		db.query('UPDATE accounts SET last_seen = ? WHERE id = ?', [now, request.session.account_id]);
	}
	db.query('SELECT * FROM settings', (error, settings) => {
		if (error) throw error;
		let settings_obj = {};
		for (let i = 0; i < settings.length; i++) {
			settings_obj[settings[i].setting_key] = settings[i].setting_value;
		}
		callback(settings_obj);
	});
};

// LoginAttempts function - prevents bruteforce attacks
const loginAttempts = (ip, update = true, callback) => {
	// Get the current date
	let d = new Date();
	let now = (new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString()).slice(0, -1).split('.')[0];
	// Update attempts left
	if (update) {
		db.query('INSERT INTO login_attempts (ip_address, `date`) VALUES (?,?) ON DUPLICATE KEY UPDATE attempts_left = attempts_left - 1, `date` = VALUES(`date`)', [ip, now]);
	}
	// Retrieve the login attempts from the db
	db.query('SELECT * FROM login_attempts WHERE ip_address = ?', [ip], (error, results) => {
		let login_attempts = [];
		if (results.length > 0) {
			// Determine expiration date
			let expire = new Date(results[0].date);
			expire.setDate(expire.getDate() + 1);
			// If current date is greater than the expiration date
			if (d.getTime() > expire.getTime()) {
				// Delete attempts
				db.query('DELETE FROM login_attempts WHERE id_address = ?', [ip]);
			} else {
				login_attempts = results[0];
			}
		}
		// Execute callback function
		if (callback != undefined) callback(login_attempts);
	});
};

// format settings key
const settingsFormatKey = key => {
    key = key.toLowerCase().replaceAll('_', ' ').replace('url', 'URL').replace('db ', 'Database ').replace(' pass', ' Password').replace(' user', ' Username').replace(/\b\w/g, l => l.toUpperCase());
    return key;
};

// Format settings variables in HTML format
const settingsFormatVarHtml = (key, value) => {
	let html = '';
	let type = 'text';
	type = key == 'pass' ? 'password' : type;
	type = ['true', 'false'].includes(value.toLowerCase()) ? 'checkbox' : type;
	checked = value.toLowerCase() == 'true' ? ' checked' : '';
	html += '<label for="' + key + '">' + settingsFormatKey(key) + '</label>';
	if (type == 'checkbox') {
		html += '<input type="hidden" name="' + key + '" value="false">';
	}
	html += '<input type="' + type + '" name="' + key + '" id="' + key + '" value="' + value + '" placeholder="' + settingsFormatKey(key) + '"' + checked + '>';
	return html;
};

// Format settings tabs
const settingsFormatTabs = tabs => {
	let html = '';
	html += '<div class="tabs">';
	html += '<a href="#" class="active">General</a>';
	for (let tab in tabs) {
		html += '<a href="#">' + tabs[tab] + '</a>';
	}
	html += '</div>';
	return html;
};

// Format settings form
const settingsFormatForm = settings => {
	let html = '';
	html += '<div class="tab-content active">';
	let category = '';
	for (let setting in settings) {
		if (category != '' && category != settings[setting]['category']) {
			html += '</div><div class="tab-content">';
		}
		category = settings[setting]['category'];
		html += settingsFormatVarHtml(settings[setting]['key'], settings[setting]['value']);
	}
	html += '</div>';
	return html;
};

// Get settings from database
const getSettings = callback => {
	db.query('SELECT * FROM settings ORDER BY id', (error, settings, fields) => {
		settings2 = {};
		for (let setting in settings) {
			settings2[settings[setting]['setting_key']] = { 'key': settings[setting]['setting_key'], 'value': settings[setting]['setting_value'], 'category': settings[setting]['category'] };
		}
		callback(settings2);	
	});
};

// Formate date to time elapsed string
const timeElapsedString = date => {
	let seconds = Math.floor((new Date() - new Date(String(date).replace(/-/g,'/'))) / 1000);
	let interval = seconds / 31536000;
	if (interval > 1) {
	  	return Math.floor(interval) + ' years';
	}
	interval = seconds / 2592000;
	if (interval > 1) {
	  	return Math.floor(interval) + ' months';
	}
	interval = seconds / 86400;
	if (interval > 1) {
	  	return Math.floor(interval) + ' days';
	}
	interval = seconds / 3600;
	if (interval > 1) {
	  	return Math.floor(interval) + ' hours';
	}
	interval = seconds / 60;
	if (interval > 1) {
	  	return Math.floor(interval) + ' minutes';
	}
	return Math.floor(seconds) + ' seconds';
};


module.exports = {
    transporter,
    isLoggedin,
    isAdmin,
    init,
    loginAttempts,
    settingsFormatKey,
    settingsFormatVarHtml,
    settingsFormatTabs,
    settingsFormatForm,
    getSettings,
    timeElapsedString
}