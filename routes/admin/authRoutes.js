const express = require('express');
const router = express.Router();
const { adminLogin, verifyOTP, createAdmin } = require('../../controllers/admin/authController');
const { validateAdminLogin, validateOTP } = require('../../middlewares/validation');
const loginLimiter = require('../../middlewares/rateLimit');

router.post('/create', createAdmin);
router.post('/login', loginLimiter, validateAdminLogin, adminLogin, );
router.post('/verifyOtp', validateOTP, verifyOTP);

module.exports = router;