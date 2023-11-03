const express = require('express');
const userController = require('../controllers/userController');
const router = express.Router();
const cryptography = require('crypto');
const comp = require('../components/components')



//----------------------------------------------------------------------------------------------------------------------------------------------------------------
// ----------   USER ROUTES -------------------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------------------------------------------------

// http://localhost:3000/ - display login page
router.get(['/', '/login'], (request, response) => comp.isLoggedin(request, () => {
	// User is logged in, redirect to home page
	response.redirect('/home');
}, () => {
	// Create CSRF token
	let token = cryptography.randomBytes(20).toString('hex');
	// Store token in session
	request.session.token = token;
	// User is not logged in, render login template
	response.render('index.html', { token: token });
}));

// http://localhost:3000/register - display the registration page
router.get('/register', (request, response) => comp.isLoggedin(request, () => {
	// User is logged in, redirect to home page
	response.redirect('/home');
}, (settings) => {
	// Create CSRF token
	let token = cryptography.randomBytes(20).toString('hex');
	// Store token in session
	request.session.token = token;
	// User is not logged in, render login template
	response.render('register.html', { token: token, settings: settings });
}));

// http://localhost:3000/forgotpassword - user can use this page if they have forgotten their password
router.get('/forgotpassword', (request, response) => {
	// Render forgot password template and output message
	response.render('forgotpassword.html');	
});

// http://localhost:3000/home - display the home page
router.get('/home', (request, response) => comp.isLoggedin(request, settings => {
	// Render home template
	response.render('home.html', { username: request.session.account_username, role: request.session.account_role });
}, () => {
	// Redirect to login page
	response.redirect('/');
}));

// http://localhost:3000/profile - display the profile page
router.get('/profile', (request, response) => comp.isLoggedin (request, settings => {
	// Get all the users account details so we can populate them on the profile page
	userController.getUserData (request, response, next => {
		// Render profile page
		//this cant be put in controller because the function is used for 2 seperate routes
		response.render('profile.html', { account: request.accounts, role: request.session.account_role });
	});
}, () => {
	// Redirect to login page
	response.redirect('/');
}));

// http://localhost:3000/edit_profile - displat the edit profile page
router.get('/edit_profile', (request, response) => comp.isLoggedin(request, settings => {
	// Get all the users account details so we can populate them on the profile page
	userController.getUserData (request, response, next => {
		// Render profile-edit page
		//this cant be put in controller because the function is used for 2 seperate routes
		response.render('profile-edit.html', { account: request.accounts, role: request.session.account_role });
	});

}, () => {
	// Redirect to login page
	response.redirect('/');
}));

// http://localhost:3000/logout - Logout page
router.get('/logout', (request, response) => {
	// Destroy session data
	request.session.destroy();
	// Clear remember me cookie
	response.clearCookie('rememberme');
	// Redirect to login page
	response.redirect('/');
});

// http://localhost:3000/activate/<email>/<code> - activate an account
router.get('/activate/:email/:code', (request, response) => {

	// Check if the email and activation code match in the database
	userController.activateAccount (request, response);

});

// http://localhost:3000/resetpassword - display the reset form
router.get('/resetpassword/:email/:code', (request, response) => {
	// Make sure the params are specified
	userController.resetForm (request, response);
});

// http://localhost:3000/twofactor - twofactor authentication
router.get('/twofactor', (request, response) => comp.init(request, settings => {
	userController.twoFactor (request, response);
}));


//----------------------------------------------------------------------------------------------------------------------------------------------------------------
// ----------      ADMIN ROUTES -------------------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------------------------------------------------

// http://localhost:3000/admin/ - Admin dashboard page
router.get('/admin/', (request, response) => comp.isAdmin(request, settings => {

	userController.getAdminInfo (request, response);

}, () => {
	// Redirect to login page
	response.redirect('/');
}));

// http://localhost:3000/admin/accounts - Admin accounts page
router.get(['/admin/accounts', '/admin/accounts/:msg/:search/:status/:activation/:role/:order/:order_by/:page'], (request, response) => comp.isAdmin(request, settings => {

	userController.getAdminAccounts (request, response);

}, () => {
	// Redirect to login page
	response.redirect('/');
}));

// http://localhost:3000/admin/account - Admin edit/create account
router.get(['/admin/account', '/admin/account/:id'], (request, response) => comp.isAdmin(request, settings => {
	
	userController.adminAccountForm (request, response);

}, () => {
	// Redirect to login page
	response.redirect('/');
}));

// http://localhost:3000/admin/account/delete/:id - Delete account based on the ID param
router.get('/admin/account/delete/:id', (request, response) => comp.isAdmin(request, settings => {
    // GET request ID exists, delete account
	
	userController.accountDelete (request, response);

}, () => {
	// Redirect to login page
	response.redirect('/');
}));

// http://localhost:3000/admin/roles - View accounts roles
router.get('/admin/roles', (request, response) => comp.isAdmin(request, settings => {
	
	userController.rolesList (request, response);

}, () => {
	// Redirect to login page
	response.redirect('/');
}));

// http://localhost:3000/admin/emailtemplate - View email templates (GET)
router.get(['/admin/emailtemplate', '/admin/emailtemplate/:msg'], (request, response) => comp.isAdmin(request, settings => {
	
	userController.emailTemplate (request, response);

}, () => {
	// Redirect to login page
	response.redirect('/');
}));

// http://localhost:3000/admin/settings - View settings (GET)
router.get(['/admin/settings', '/admin/settings/:msg'], (request, response) => comp.isAdmin(request, settings => {
	
	userController.adminSettings (request, response);

}, () => {
	// Redirect to login page
	response.redirect('/');
}));

// http://localhost:3000/admin/myaccount - Redirect to edit account page
router.get('/admin/myaccount', (request, response) => comp.isAdmin(request, settings => {
	// Redirect to edit account page
	response.redirect('/admin/account/' + request.session.account_id);
}, () => {
	// Redirect to login page
	response.redirect('/');
}));

// http://localhost:3000/admin/about - View about page
router.get('/admin/about', (request, response) => comp.isAdmin(request, settings => {
	// Render about template
   	response.render('admin/about.html', { selected: 'about' });
}, () => {
	// Redirect to login page
	response.redirect('/');
}));

//----------------------------------------------------------------------------------------------------------------------------------------------------------------
// ----------  END ADMIN ROUTES -------------------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------------------------------------------------

module.exports = router;