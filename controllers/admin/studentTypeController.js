const StudentType = require('../../models/StudentType');
const {ApiError} = require('../../utils/errorHandler');
const apiResponse = require('../../utils/apiResponse');

const createStudentType = async (req, res, next) => {
  try {
    const { type, name, price } = req.body;
    
    // Check for duplicate
    const existingType = await StudentType.findOne({ type, name });
    if (existingType) {
      throw new ApiError(400, 'Student type with this name already exists');
    }
    
    const studentType = new StudentType({ type, name, price });
    await studentType.save();
    
    apiResponse(res, 201, true, 'Student type created successfully', studentType);
  } catch (error) {
    next(error);
  }
};

const getStudentTypes = async (req, res, next) => {
  try {
    const { type } = req.query;
    const query = type ? { type } : {};
    const studentTypes = await StudentType.find(query).sort({ name: 1 });
    apiResponse(res, 200, true, 'Student types retrieved successfully', studentTypes);
  } catch (error) {
    next(error);
  }
};

const updateStudentType = async (req, res, next) => {
  try {
    const { id } = req.params;
    const { name, price } = req.body;
    const studentType = await StudentType.findById(id);
    if (!studentType) {
      throw new ApiError(404, 'Student type not found');
    }

    // Prevent modification of institute types
    if (studentType.type === 'institute') {
      throw new ApiError(403, 'Institute types cannot be modified');
    }
    
    // Check for duplicate name
    if (name && name !== studentType.name) {
      const existingType = await StudentType.findOne({ 
        type: studentType.type, 
        name,
        _id: { $ne: id }
      });
      if (existingType) {
        throw new ApiError(400, 'Student type with this name already exists');
      }
      studentType.name = name;
    }
    
    if (price) studentType.price = price;
    await studentType.save();
    
    apiResponse(res, 200, true, 'Student type updated successfully', studentType);
  } catch (error) {
    next(error);
  }
};

const deleteStudentType = async (req, res, next) => {
  try {
    const { id } = req.params;
    
    const studentType = await StudentType.findById(id);
    if (!studentType) {
      throw new ApiError(404, 'Student type not found');
    }
    
    // Prevent deletion of institute types
    if (studentType.type === 'institute') {
      throw new ApiError(403, 'Institute types cannot be deleted');
    }
    
    await studentType.remove();
    
    apiResponse(res, 200, true, 'Student type deleted successfully');
  } catch (error) {
    next(error);
  }
};

module.exports = {
  createStudentType,
  getStudentTypes,
  updateStudentType,
  deleteStudentType
};