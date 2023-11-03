const express = require('express');
const postController = require('../controllers/postController');
const router = express.Router();


//ANY POSTS ROUTES GO IN HERE
// http://localhost:3000/login - user login
router.post(['/', '/login'], postController.userLogin);

// http://localhost:3000/register - user register
router.post('/register', postController.userRegister);

router.post('/forgotpassword', postController.forgotPassword);

router.post('/edit_profile', postController.editProfile);

router.post(['/admin/account', '/admin/account/:id'], postController.createAccount);

router.post(['/admin/emailtemplate', '/admin/emailtemplate/:msg'], postController.updateEmailTemplate);

router.post(['/admin/settings', '/admin/settings/:msg'], postController.updateSettings);

// http://localhost:3000/resetpassword - update password
router.post('/resetpassword/:email/:code', postController.resetPassword);

// http://localhost:3000/twofactor - twofactor authentication
router.post('/twofactor', postController.twoFactorAuth);


module.exports = router;