const express = require('express');
const router = express.Router();
const mysql = require("mysql");
const cryptography = require('crypto');
const uuidv1 = require('uuid/v1');
const nodemailer = require('nodemailer');
const fs = require('fs');
const path = require('path');
const comp = require('../components/components')
const db = require('../components/db')


//----------------------------------------------------------------------------------------------------------------------------------------------------------------
// ----------  USER POST FUNCTIONS -------------------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------------------------------------------------

exports.userLogin = (request, response) => comp.init(request, settings => {
	// Create variables and assign the post data
	let username = request.body.username;
	let password = request.body.password;
	//THIS PASSWORD IS NOT SALTED!!! THIS NEEDS TO BE SALTED! OTHERWISE PASSWORD HASH IS JUST THE SAME!
	//maybe swap this out for bcrypt
	let hashedPassword = cryptography.createHash('sha1').update(request.body.password).digest('hex');
	let token = request.body.token;
	// Get client IP address
	let ip = request.headers['x-forwarded-for'] || request.socket.remoteAddress;
	// Bruteforce protection
	if (settings['brute_force_protection'] == 'true') {
		loginAttempts(ip, false, result => {
			if (result && result['attempts_left'] <= 1) {
				// No login attempts remaining
				response.send('You cannot login right now! Please try again later!');
				return response.end();				
			}
		});
	}
	// check if the data exists and is not empty
	if (username && password) {
		// Ensure the captured token matches the session token (CSRF Protection)
		if (settings['csrf_protection'] == 'true' && token != request.session.token) {
			// Incorrect token
			response.send('Incorrect token provided!');
			return response.end();			
		}
		// Select the account from the accounts table
		db.query('SELECT * FROM accounts WHERE username = ? AND password = ?', [username, hashedPassword], (error, accounts) => {
			// If the account exists
			if (accounts.length > 0) {
				// Twofactor
				if (settings['twofactor_protection'] == 'true' && accounts[0].ip != ip) {
					request.session.tfa_id = accounts[0].id;
					request.session.tfa_email = accounts[0].email;
					response.send('tfa: twofactor');
					return response.end();						
				}
				// Make sure account is activated
				if (settings['account_activation'] == 'true' && accounts[0].activation_code != 'activated' && accounts[0].activation_code != '') {
					response.send('Please activate your account to login!');
					return response.end();					
				}
				// Account exists (username and password match)
				// Create session variables
				request.session.account_loggedin = true;
				request.session.account_id = accounts[0].id;
				request.session.account_username = accounts[0].username;
				request.session.account_password = accounts[0].password;
				request.session.account_role = accounts[0].role;
				// If user selected the remember me option
				if (request.body.rememberme) {
					// Create cookie hash, will be used to check if user is logged in
					let hash = accounts[0].rememberme ? accounts[0].rememberme : cryptography.createHash('sha1').update(username + password + secret_key).digest('hex');
					// Num days until the cookie expires (user will log out)
					let days = 90;
					// Set the cookie
					response.cookie('rememberme', hash, { maxAge: 1000*60*60*24*days, httpOnly: true });
					// Update code in database
					db.query('UPDATE accounts SET rememberme = ? WHERE username = ?', [hash, username]);
				}
				// Delete login attempts
				db.query('DELETE FROM login_attempts WHERE ip_address = ?', [ip]);
				// Output success and redirect to home page
				response.send('success'); // do not change the message as the ajax code depends on it
				return response.end();
			} else {
				// Bruteforce
				if (settings['brute_force_protection'] == 'true') loginAttempts(ip);
				// Incorrect username/password
				response.send('Incorrect Username and/or Password!');
				return response.end();
			}
		});
	} else {
		// Bruteforce
		if (settings['brute_force_protection'] == 'true') loginAttempts(ip);
		// Incorrect username/password
		response.send('Incorrect Username and/or Password!');
		return response.end();
	}
});

exports.userRegister = (request, response) => comp.init(request, settings => {
    // Create variables and assign the POST data
    let username = request.body.username;
    let password = request.body.password;
    let cpassword = request.body.cpassword;
    let hashedPassword = cryptography.createHash('sha1').update(request.body.password).digest('hex');
    let email = request.body.email;
    let token = request.body.token;
    // Get client IP address
    let ip = request.headers['x-forwarded-for'] || request.socket.remoteAddress;
    // Default role
    let role = 'Member';
    // Ensure the captured token matches the session token (CSRF Protection)
    if (settings['csrf_protection'] == 'true' && token != request.session.token) {
        // Incorrect token
        response.send('Incorrect token provided!');
        return response.end();			
    }
    // Validate captcha if enabled
    if (settings['recaptcha'] == 'true') {
        if (!request.body['g-recaptcha-response']) {
            response.send('Invalid captcha!');
            return response.end();			
        } else {
            fetch('https://www.google.com/recaptcha/api/siteverify?response=' + request.body['g-recaptcha-response'] + '&secret=' + settings['recaptcha_secret_key']).then(res => res.json()).then(body => {
                if (body.success !== undefined && !body.success) {
                    response.send('Invalid captcha!');
                    return response.end();
                }
            });
        }
    }
    // Check if the POST data exists and not empty
    if (username && password && email) {
        // Check if account exists already in the accounts table based on the username or email
        db.query('SELECT * FROM accounts WHERE username = ? OR email = ?', [username, email], (error, accounts, fields) => {
            // Check if account exists and validate input data
            if (accounts.length > 0) {
                response.send('Account already exists with that username and/or email!');
                response.end();
            } else if (!/\S+@\S+\.\S+/.test(email)) {
                response.send('Invalid email address!');
                response.end();
            } else if (!/[A-Za-z0-9]+/.test(username)) {
                response.send('Username must contain only characters and numbers!');
                response.end();
            } else if (password != cpassword) {
                response.send('Passwords do not match!');
                response.end();
            } else if (username.length < 5 || username.length > 20) {
                response.send('Username must be between 5 and 20 characters long!');
                response.end();
            } else if (password.length < 5 || password.length > 20) {
                response.send('Password must be between 5 and 20 characters long!');
                response.end();
            } else if (settings['account_activation'] == 'true') {
                // Generate a random unique ID
                let activationCode = uuidv1();
                // Change the below domain to your domain
                let activateLink = request.protocol + '://' + request.get('host') + '/activate/' + email + '/' + activationCode;
                // Get the activation email template
                let activationTemplate = fs.readFileSync(path.join(__dirname, 'views/activation-email-template.html'), 'utf8').replaceAll('%link%', activateLink);
                // Change the below mail options
                let mailOptions = {
                    from: settings['mail_from'], // "Your Name / Business name" <xxxxxx@gmail.com>
                    to: email,
                    subject: 'Account Activation Required',
                    text: activationTemplate.replace(/<\/?[^>]+(>|$)/g, ''),
                    html: activationTemplate
                };
                // Insert account with activation code
                db.query('INSERT INTO accounts (username, password, email, activation_code, role, ip) VALUES (?, ?, ?, ?, ?, ?)', [username, hashedPassword, email, activationCode, role, ip], () => {
                    // Send activation email
                    comp.transporter.sendMail(mailOptions, (error, info) => {
                        if (error) {
                            return console.log(error);
                        }
                        console.log('Message %s sent: %s', info.messageId, info.response);
                    });
                    response.send('Please check your email to activate your account!');
                    response.end();
                });
            } else {
                // Insert account
                db.query('INSERT INTO accounts (username, password, email, activation_code, role, ip) VALUES (?, ?, ?, "activated", ?, ?)', [username, hashedPassword, email, role, ip], (error, result) => {
                    // Registration success!
                    if (settings['auto_login_after_register'] == 'true') {
                        // Authenticate the user
                        request.session.account_loggedin = true;
                        request.session.account_id = result.insertId;
                        request.session.account_username = username;
                        request.session.account_password = hashedPassword;
                        request.session.account_role = role;				
                        response.send('autologin');
                        response.end();						
                    } else {
                        response.send('You have registered! You can now login!');
                        response.end();
                    }
                });
            }
        });
    } else {
        // Form is not complete...
        response.send('Please complete the registration form!');
        response.end();
    }
});

exports.forgotPassword = (request, response) => comp.init(request, settings => {
    // Render activate template and output message
    if (request.body.email) {
        // Retrieve account info from database that's associated with the captured email
        db.query('SELECT * FROM accounts WHERE email = ?', [request.body.email], (error, accounts) => {
            // If account exists
            if (accounts.length > 0) {
                // Generate a random unique ID
                let resetCode = uuidv1();
                // Change the below domain to your domain
                let resetLink = request.protocol + '://' + request.get('host') + '/resetpassword/' + request.body.email + '/' + resetCode;
                console.log(resetLink);
                // Change the below mail options
                let mailOptions = {
                    from: settings['mail_from'], // "Your Name / Business name" <xxxxxx@gmail.com>
                    to: request.body.email,
                    subject: 'Password Reset',
                    text: 'Please click the following link to reset your password: ' + resetLink,
                    html: '<p>Please click the following link to reset your password: <a href="' + resetLink + '">' + resetLink + '</a></p>'
                };
                // Update reset column in db
                db.query('UPDATE accounts SET reset = ? WHERE email = ?', [resetCode, request.body.email]);
                // Send reset password email
                comp.transporter.sendMail(mailOptions, (error, info) => {
                    if (error) {
                        return console.log(error);
                    }
                    console.log('Message %s sent: %s', info.messageId, info.response);
                });
                // Render forgot password template
                response.render('forgotpassword.html', { msg: 'Reset password link has been sent to your email!' });
            } else {
                // Render forgot password template
                response.render('forgotpassword.html', { msg: 'An account with that email does not exist!' });	
            }
        });
    }
});

exports.editProfile = (request, response) => comp.init(request, settings => {
    // Create variables for easy access
	let username = request.body.username;
	let password = request.body.password;
	let cpassword = request.body.cpassword;
	let hashedPassword = cryptography.createHash('sha1').update(request.body.password).digest('hex');
	let email = request.body.email;
	let errorMsg = '';
	// Validation
	if (password != cpassword) {
		errorMsg = 'Passwords do not match!';
	} else if (!/\S+@\S+\.\S+/.test(email)) {
		errorMsg = 'Invalid email address!';
	} else if (!/[A-Za-z0-9]+/.test(username)) {
		errorMsg = 'Username must contain only characters and numbers!';
	} else if (password != cpassword) {
		errorMsg = 'Passwords do not match!';
	} else if (username.length < 5 || username.length > 20) {
		errorMsg = 'Username must be between 5 and 20 characters long!';
	} else if (password && password.length < 5 || password.length > 20) {
		errorMsg = 'Password must be between 5 and 20 characters long!';
	} else if (username && email) {
		// Get account details from database
		db.query('SELECT * FROM accounts WHERE username = ?', [username], (error, accounts, fields) => {
			// Does the account require activation
			let requiresActivation = false;
			// Activation code
			let activationCode = 'activated';
			// Update the password
			hashedPassword = !password ? request.session.account_password : hashedPassword;
			// Check if account activation is required
			if (settings['account_activation'] == 'true' && accounts.length > 0 && accounts[0].email != email) {
				// Generate a random unique ID
				activationCode = uuidv1();
				// Change the below domain to your domain
				let activateLink = request.protocol + '://' + request.get('host') + '/activate/' + email + '/' + activationCode;
				// Change the below mail options
				let mailOptions = {
					from: '"Your Name / Business name" <xxxxxx@gmail.com>',
					to: email,
					subject: 'Account Activation Required',
					text: 'Please click the following link to activate your account: ' + activateLink,
					html: '<p>Please click the following link to activate your account: <a href="' + activateLink + '">' + activateLink + '</a></p>'
				};
				requiresActivation = true;
			}
			// Check if username exists
			if (accounts.length > 0 && username != request.session.account_username) {
				// Username exists
				response.render('profile-edit.html', { account: accounts[0], msg: 'Username already exists!', role: request.session.account_role });
			} else {
				// Update account with new details
				db.query('UPDATE accounts SET username = ?, password = ?, email = ?, activation_code = ? WHERE username = ?', [username, hashedPassword, email, activationCode, request.session.account_username], () => {
					// Update session with new username
					request.session.account_username = username;
					// Output message
					let msg = 'Account Updated!';
					// Account activation required?
					if (requiresActivation) {
						// Send activation email
						comp.transporter.sendMail(mailOptions, (error, info) => {
							if (error) {
								return console.log(error);
							}
							console.log('Message %s sent: %s', info.messageId, info.response);
						});
						// Update msg
						msg = 'You have changed your email address! You need to re-activate your account! You will be automatically logged-out.';	
						// Destroy session data
						request.session.destroy();					
					}
					// Get account details from database
					db.query('SELECT * FROM accounts WHERE username = ?', [username], (error, accounts, fields) => {
						// Render edit profile page
						response.render('profile-edit.html', { account: accounts[0], msg: msg, role: request.session.account_role });
					});
				});
			}
		});
	}
	// Output error message if any
	if (errorMsg) {
		// Get account details from database
		db.query('SELECT * FROM accounts WHERE username = ?', [username], (error, accounts, fields) => {
			// Render edit profile page
			response.render('profile-edit.html', { account: accounts[0], msg: errorMsg, role: request.session.account_role });
		});
	}
});

exports.resetPassword = (request, response) => {
    // Make sure the params are specified
	if (request.params.email && request.params.code) {
		// Retrieve account info from database that's associated with the captured email
		db.query('SELECT * FROM accounts WHERE email = ? AND reset = ?', [request.params.email, request.params.code], (error, accounts) => {
			// Check if account exists
			if (accounts.length > 0) {
				// Output msg
				let msg = '';
				// Check if user submitted the form
				if (request.body.npassword && request.body.cpassword) {
					// Validation
					if (request.body.npassword != request.body.cpassword) {
						msg = 'Passwords do not match!';
					} else if (request.body.npassword.length < 5 || request.body.npassword.length > 20) {
						msg = 'Password must be between 5 and 20 characters long!';
					} else {
						// Success! Update password
						msg = 'Your password has been reset! You can now <a href="/">login</a>!';
						// Hash password
						let hashedPassword = cryptography.createHash('sha1').update(request.body.npassword).digest('hex');
						// Update password
						db.query('UPDATE accounts SET password = ?, reset = "" WHERE email = ?', [hashedPassword, request.params.email]);
					}
					// Render reset password template
					response.render('resetpassword.html', { msg: msg, email: request.params.email, code: request.params.code });
				} else {
					msg = 'Password fields must not be empty!';
					// Render reset password template
					response.render('resetpassword.html', { msg: msg, email: request.params.email, code: request.params.code });
				}	
			} else {
				response.send('Incorrect email and/or code provided!');
				response.end();						
			}
		});
	} else {
		response.send('No email and/or code provided!');
		response.end();		
	}
};

exports.twoFactorAuth = (request, response) => {
	// Check if the tfa session variables are declared
	if (request.session.tfa_id && request.session.tfa_email) {
		// Retrieve account info from database that's associated with the captured email
		db.query('SELECT * FROM accounts WHERE id = ? AND email = ?', [request.session.tfa_id, request.session.tfa_email], (error, accounts) => {
			// Output msg
			let msg = '';
			// If accounts not empty
			if (accounts.length > 0) {
				// Check if user submitted the form
				if (request.body.code) {
					// Check if captured code and account code match
					if (request.body.code == accounts[0]['tfa_code']) {
						// Get client IP address
						let ip = request.headers['x-forwarded-for'] || request.socket.remoteAddress;
						// Update IP address in db
						db.query('UPDATE accounts SET ip = ? WHERE id = ?', [ip, request.session.tfa_id]);
						// Authenticate the user
						request.session.account_loggedin = true;
						request.session.account_id = accounts[0].id;
						request.session.account_username = accounts[0].username;
						request.session.account_password = accounts[0].password;
						request.session.account_role = accounts[0].role;
						// Redirect to home page	
						return response.redirect('/home');					
					} else {
						msg = 'Incorrect email and/or code!';
					}
				}
			} else {
				msg = 'Incorrect email and/or code!';
			}
			// Render twofactor template
			response.render('twofactor.html', { msg: msg });	
		});
	} else {
		// Redirect to login page
		response.redirect('/');
	}
};

//----------------------------------------------------------------------------------------------------------------------------------------------------------------
// ---------- ADMIN POST FUNCTIONS -------------------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------------------------------------------------

exports.createAccount =  (request, response) => comp.isAdmin(request, settings => {

    // GET request ID exists, edit account
    if (request.params.id) {
        // Edit an existing account
        page = 'Edit'
        // Retrieve account by ID with the GET request ID
        db.query('SELECT * FROM accounts WHERE id = ?', [request.params.id], (error, accounts) => {
            // If user submitted the form
            if (request.body.submit) {
                // update account
                let password = accounts[0]['password']
                // If password exists in POST request
                if (request.body.password) {
                    password = cryptography.createHash('sha1').update(request.body.password).digest('hex');
                }
                // Update account details
                db.query('UPDATE accounts SET username = ?, password = ?, email = ?, activation_code = ?, rememberme = ?, role = ?, registered = ?, last_seen = ? WHERE id = ?', [request.body.username, password, request.body.email, request.body.activation_code, request.body.rememberme, request.body.role, request.body.registered, request.body.last_seen, request.params.id]);
                // Redirect to admin accounts page
                response.redirect('/admin/accounts/msg2/n0/n0/n0/n0/ASC/id/1');
            } else if (request.body.delete) {
                // delete account
                response.redirect('/admin/account/delete/' + request.params.id);
            }
        });
    } else if (request.body.submit) {
        // Hash password
        let password = cryptography.createHash('sha1').update(request.body.password).digest('hex');
        // Create account
        db.query('INSERT INTO accounts (username,password,email,activation_code,rememberme,role,registered,last_seen) VALUES (?,?,?,?,?,?,?,?)', [request.body.username, password, request.body.email, request.body.activation_code, request.body.rememberme, request.body.role, request.body.registered, request.body.last_seen]);
        // Redirect to admin accounts page
        response.redirect('/admin/accounts/msg1/n0/n0/n0/n0/ASC/id/1');
    }
    }, () => {
    // Redirect to login page
    response.redirect('/');
});

exports.updateEmailTemplate = (request, response) => comp.isAdmin(request, settings => {
    // If form submitted
    if (request.body.activation_email_template && request.body.twofactor_email_template) {
        // Update the template files
        fs.writeFileSync(path.join(__dirname, '../views/activation-email-template.html'), request.body.activation_email_template);
        fs.writeFileSync(path.join(__dirname, '../views/twofactor-email-template.html'), request.body.twofactor_email_template);
        // Redirect and output message
        response.redirect('/admin/emailtemplate/msg1');
    }
    }, () => {
    // Redirect to login page
    response.redirect('/');
});

exports.updateSettings = (request, response) => comp.isAdmin(request, settings => {
    // Update settings
    for (let item in request.body) {
        let key = item;
        let value = request.body[item];
        if (value.includes('true')) {
            value = 'true';
        }
        db.query('UPDATE settings SET setting_value = ? WHERE setting_key = ?', [value, key]);
    }
    // Redirect and output message
    response.redirect('/admin/settings/msg1');
    }, () => {
    // Redirect to login page
    response.redirect('/');
});
//----------------------------------------------------------------------------------------------------------------------------------------------------------------


//IF YOU GET CANNOT POST ERROR, USUALLY ITS BECAUSE THE HTML NEEDS UPDATED