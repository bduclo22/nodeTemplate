const mysql = require("mysql");
const fs = require('fs');
const path = require('path');
const comp = require('../components/components')
const db = require('../components/db')


//----------------------------------------------------------------------------------------------------------------------------------------------------------------
// ----------   USER FUNCTIONS -------------------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------------------------------------------------

// Get all the users account details so we can populate them on the profile page
exports.getUserData = (request, response, next) => {
	db.query('SELECT * FROM accounts WHERE username = ?', [request.session.account_username], (error, accounts, fields) => {
		// Format the registered date
		accounts[0].registered = new Date(accounts[0].registered).toISOString().split('T')[0];
		request.accounts = accounts[0]
		//this requires a next because this functions is used for 2 different routes
		return next();
	});
}

// Check if the email and activation code match in the database
exports.activateAccount = (request, response) => {
	db.query('SELECT * FROM accounts WHERE email = ? AND activation_code = ?', [request.params.email, request.params.code], (error, accounts) => {
		// If email and code are valid
		if (accounts.length > 0) {
			// Email and activation exist, update the activation code to "activated"
			db.query('UPDATE accounts SET activation_code = "activated" WHERE email = ? AND activation_code = ?', [request.params.email, request.params.code], () => {
				// Authenticate the user
				request.session.account_loggedin = true;
				request.session.account_id = accounts[0].id;
				request.session.account_username = accounts[0].username;
				request.session.account_password = accounts[0].password;
				request.session.account_role = accounts[0].role;
				// Reditect to home page
				response.redirect('/home');
			});
		} else {
			// Render activate template and output message
			response.render('activate.html', { msg: 'Incorrect email and/or activation code!' });
		}
	});
}

//display reset form
exports.resetForm = (request, response) => {
	// Make sure the params are specified
	if (request.params.email && request.params.code) {
		// Retrieve account info from database that's associated with the captured email
		db.query('SELECT * FROM accounts WHERE email = ? AND reset = ?', [request.params.email, request.params.code], (error, accounts) => {
			// Check if account exists
			if (accounts.length > 0) {
				// Render forgot password template
				response.render('resetpassword.html', { email: request.params.email, code: request.params.code });	
			} else {
				response.send('Incorrect email and/or code provided!');
				response.end();						
			}
		});
	} else {
		response.send('No email and/or code provided!');
		response.end();		
	}
}

//display twofactor auth
exports.twoFactor = (request, response) => {
	// Check if the tfa session variables are declared
	if (request.session.tfa_id && request.session.tfa_email) {
		// Generate a random unique ID
		let twofactorCode = uuidv1();
		// Get the twofactor email template
		let twofactorTemplate = fs.readFileSync(path.join(__dirname, 'views/twofactor-email-template.html'), 'utf8').replaceAll('%code%', twofactorCode);
		// Change the below mail options
		let mailOptions = {
			from: settings['mail_from'], // "Your Name / Business name" <xxxxxx@gmail.com>
			to: request.session.tfa_email,
			subject: 'Your Access Code',
			text: twofactorTemplate.replace(/<\/?[^>]+(>|$)/g, ''),
			html: twofactorTemplate
		};
		// Update tfa code column in db
		db.query('UPDATE accounts SET tfa_code = ? WHERE id = ?', [twofactorCode, request.session.tfa_id]);
		// Send tfa email
		transporter.sendMail(mailOptions, (error, info) => {
			if (error) {
				return console.log(error);
			}
			console.log('Message %s sent: %s', info.messageId, info.response);
		});
		// Render twofactor template
		response.render('twofactor.html');	
	} else {
		// Redirect to login page
		response.redirect('/');
	}	
}

//----------------------------------------------------------------------------------------------------------------------------------------------------------------
// ----------      ADMIN FUNCTIONS -------------------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------------------------------------------------

//gets admin page display info - dashboard.html
exports.getAdminInfo = (request, response) => {
	// Retrieve statistical data
	db.query('SELECT * FROM accounts WHERE cast(registered as DATE) = cast(now() as DATE) ORDER BY registered DESC; SELECT COUNT(*) AS total FROM accounts LIMIT 1; SELECT COUNT(*) AS total FROM accounts WHERE last_seen < date_sub(now(), interval 1 month) LIMIT 1; SELECT * FROM accounts WHERE last_seen > date_sub(now(), interval 1 day) ORDER BY last_seen DESC; SELECT COUNT(*) AS total FROM accounts WHERE last_seen > date_sub(now(), interval 1 month) LIMIT 1', (error, results, fields) => {
		// Render dashboard template
		response.render('admin/dashboard.html', { selected: 'dashboard', accounts: results[0], accounts_total: results[1][0], inactive_accounts: results[2][0], active_accounts: results[3], active_accounts2: results[4][0], timeElapsedString: comp.timeElapsedString });
	});
}

//gets and displays accounts on admin page - accounts.html
exports.getAdminAccounts = (request, response) => {
	// Params validation
	let msg = request.params.msg == 'n0' ? '' : request.params.msg;
	let search = request.params.search == 'n0' ? '' : request.params.search;
	let status = request.params.status == 'n0' ? '' : request.params.status;
	let activation = request.params.activation == 'n0' ? '' : request.params.activation;
	let role = request.params.role == 'n0' ? '' : request.params.role;
	let order = request.params.order == 'DESC' ? 'DESC' : 'ASC';
	let order_by_whitelist = ['id','username','email','activation_code','role','registered','last_seen'];
	let order_by = order_by_whitelist.includes(request.params.order_by) ? request.params.order_by : 'id';
	// Number of accounts to show on each pagination page
	let results_per_page = 20;
	let page = request.params.page ? request.params.page : 1;
	let param1 = (page - 1) * results_per_page;
	let param2 = results_per_page;
	let param3 = '%' + search + '%';
	// SQL where clause
	let where = '';
	where += search ? 'WHERE (username LIKE ? OR email LIKE ?) ' : '';
	// Add filters
	if (status == 'active') {
		where += where ? 'AND last_seen > date_sub(now(), interval 1 month) ' : 'WHERE last_seen > date_sub(now(), interval 1 month) ';
	}
	if (status == 'inactive') {
		where += where ? 'AND last_seen < date_sub(now(), interval 1 month) ' : 'WHERE last_seen < date_sub(now(), interval 1 month) ';
	}
	if (activation == 'pending') {
		where += where ? 'AND activation_code != "activated" ' : 'WHERE activation_code != "activated" ';
	}
	if (role) {
		where += where ? 'AND role = ? ' : 'WHERE role = ? ';
	}
	// Params array and append specified params
	let params = [];
	if (search) {
		params.push(param3, param3);
	}
	if (role) {
		params.push(role);
	}
	// Fetch the total number of accounts
	db.query('SELECT COUNT(*) AS total FROM accounts ' + where, params, (error, results) => {
		// Accounts total
		let accounts_total = results[0]['total'];
		// Append params to array
		params.push(param1, param2);
		// Retrieve all accounts from the database
		db.query('SELECT * FROM accounts ' + where + ' ORDER BY ' + order_by + ' ' + order + ' LIMIT ?,?', params, (error, accounts) => {
			// Determine the URL
			let url = '/admin/accounts/n0/' + (search ? search : 'n0') + '/' + (status ? status : 'n0') + '/' + (activation ? activation : 'n0') + '/' + (role ? role : 'n0');
			// Determine message
			if (msg) {
				if (msg == 'msg1') {
					msg = 'Account created successfully!';
				} else if (msg == 'msg2') { 
					msg = 'Account updated successfully!';
				} else if (msg == 'msg3') {
					msg = 'Account deleted successfully!';
				}
			}
			// Render accounts template
			response.render('admin/accounts.html', { selected: 'accounts', selectedChild: 'view', accounts: accounts, accounts_total: accounts_total, msg: msg, page: parseInt(page), search: search, status: status, activation: activation, role: role, order: order, order_by: order_by, results_per_page: results_per_page, url: url, timeElapsedString: comp.timeElapsedString, Math: Math });
		});
	});
}

//gets and displays selected account on admin page - account.html
exports.adminAccountForm = (request, response) => {
	// Default page (Create/Edit)
    let page = request.params.id ? 'Edit' : 'Create';
	// Current date
	let d = new Date();
    // Default input account values
    let account = {
        'username': '',
        'password': '',
        'email': '',
        'activation_code': '',
        'rememberme': '',
        'role': 'Member',
		'registered': (new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString()).slice(0, -1).split('.')[0],
		'last_seen': (new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString()).slice(0, -1).split('.')[0]
    };
    let roles = ['Member', 'Admin'];
    // GET request ID exists, edit account
    if (request.params.id) {
		db.query('SELECT * FROM accounts WHERE id = ?', [request.params.id], (error, accounts) => {
			account = accounts[0];
			response.render('admin/account.html', { selected: 'accounts', selectedChild: 'manage', page: page, roles: roles, account: account });
		});
	} else {
		response.render('admin/account.html', { selected: 'accounts', selectedChild: 'manage', page: page, roles: roles, account: account });
	}
}

//deletes selected account on admin page - account.html/accounts.html
exports.accountDelete = (request, response) => {
	if (request.params.id) {
		db.query('DELETE FROM accounts WHERE id = ?', [request.params.id]);
		response.redirect('/admin/accounts/msg3/n0/n0/n0/n0/ASC/id/1');
	}
};

//gets and displays list of roles on admin page - roles.html
exports.rolesList = (request, response) => comp.init(request, settings => {
	// Roles list
	let roles_list = ['Member', 'Admin'];
	// Select and group roles from the accounts table
	db.query('SELECT role, COUNT(*) as total FROM accounts GROUP BY role; SELECT role, COUNT(*) as total FROM accounts WHERE last_seen > date_sub(now(), interval 1 month) GROUP BY role; SELECT role, COUNT(*) as total FROM accounts WHERE last_seen < date_sub(now(), interval 1 month) GROUP BY role', (error, roles) => {
		// Roles array
		new_roles = {};
		// Update the structure
		for (const role in roles[0]) {
			new_roles[roles[0][role]['role']] = roles[0][role]['total'];
		}
		for (const role in roles_list) {
			if (!new_roles[roles_list[role]]) new_roles[roles_list[role]] = 0;
		}
		// Get the total number of active roles
		new_roles_active = {};
		for (const role in roles[1]) {
			new_roles_active[roles[1][role]['role']] = roles[1][role]['total'];
		}
		// Get the total number of inactive roles
		new_roles_inactive = {};
		for (const role in roles[2]) {
			new_roles_inactive[roles[2][role]['role']] = roles[2][role]['total'];
		}
		// Render roles template
		response.render('admin/roles.html', { selected: 'roles', roles: new_roles, roles_active: new_roles_active, roles_inactive: new_roles_inactive });
	});
});

//gets and displays email template on admin page - email.html
exports.emailTemplate = (request, response) => comp.init(request, settings => {
	// Output message
	let msg = request.params.msg;
	// Read template files
	const activation_email_template = fs.readFileSync(path.join(__dirname, '../views/activation-email-template.html'), 'utf8');
	const twofactor_email_template = fs.readFileSync(path.join(__dirname, '../views/twofactor-email-template.html'), 'utf8');
	// Determine message
	if (msg == 'msg1') {
		msg = 'Email templates updated successfully!';
	} else {
		msg = '';
	}
	// Render emails template
	response.render('admin/emailtemplates.html', { selected: 'emailtemplate', msg: msg, activation_email_template: activation_email_template, twofactor_email_template: twofactor_email_template });
});

//gets and displays admin settings - settings.html
exports.adminSettings = (request, response) => comp.init(request, settings => {
	// Output message
	let msg = request.params.msg;
	// Determine message
	if (msg == 'msg1') {
		msg = 'Settings updated successfully!';
	} else {
		msg = '';
	}
	// Retrieve settings
	comp.getSettings(settings => {
		// Render settings template
		response.render('admin/settings.html', { selected: 'settings', msg: msg, settings: settings, settingsFormatTabs: comp.settingsFormatTabs, settingsFormatForm: comp.settingsFormatForm });
	});
});
//----------------------------------------------------------------------------------------------------------------------------------------------------------------
// ----------  END ADMIN FUNCTIONS -------------------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------------------------------------------------
