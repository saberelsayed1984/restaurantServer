const express = require('express');
const router = express.Router();
const userController = require('../Controllers/userControl')
router.route('/signUp')
        .post(userController.signUp);
router.route('/signIn')
        .post( userController.signIn);
router.route('/ForgetPassword')
        .post(userController.ForgetPassword)
router.route('/verifyEmail/:userId/:token')
        .get(userController.verifyEmail);
router.route('/resetpassword/:userId/:token')
        .get(userController.getResetPassword)
        .post(userController.resetPassword);        
router.route('/:userId')
        .put(userController.update);
router.route('/:userId')
        .post(userController.newPassword);
router.route('/:userId')
        .delete(userController.deleteUser)    
// router.get("/google",  passport.authenticate("google",{scope:["email","profile"]}))
// router.get("/google/callback", passport.authenticate("google"), userControllr.callback)
//router.post('/uplodePhoto/:id', photoUpload.single('image'), userControllr.uplodePhoto);
module.exports = router;

