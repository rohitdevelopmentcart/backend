const express = require('express');
const router = express.Router();
const auth = require('../../middlewares/auth');
const { validateStudentType } = require('../../middlewares/validation');
const {
  createStudentType,
  getStudentTypes,
  updateStudentType,
  deleteStudentType
} = require('../../controllers/admin/studentTypeController');

router.post('/', auth(['admin']), validateStudentType, createStudentType);
router.get('/', auth(['admin']), getStudentTypes);
router.put('/:id', auth(['admin']), validateStudentType, updateStudentType);
router.delete('/:id', auth(['admin']), deleteStudentType);

module.exports = router;