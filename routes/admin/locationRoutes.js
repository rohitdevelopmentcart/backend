const express = require('express');
const router = express.Router();
const auth = require('../../middlewares/auth');
const { validateLocation } = require('../../middlewares/validation');
const {
  createLocation,
  getLocations,
  editLocation,
  removeLocation
} = require('../../controllers/admin/locationController');

router.post('/', auth(['admin']), validateLocation, createLocation);
router.get('/', auth(['admin']), getLocations);
router.put('/:id', auth(['admin']), validateLocation, editLocation);
router.delete('/:id', auth(['admin']), removeLocation);

module.exports = router;
