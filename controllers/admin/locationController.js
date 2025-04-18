const {
    addLocation,
    getLocationsByTypeAndParent,
    updateLocation,
    deleteLocation
  } = require('../../services/locationService');
  const ApiError = require('../../utils/errorHandler');
  const apiResponse = require('../../utils/apiResponse');
  
  const createLocation = async (req, res, next) => {
    try {
      const { name, type, parentId } = req.body;
      const location = await addLocation(name, type, parentId);
      apiResponse(res, 201, true, 'Location created successfully', location);
    } catch (error) {
      next(error);
    }
  };
  
  const getLocations = async (req, res, next) => {
    try {
      const { type, parentId } = req.query;
      const locations = await getLocationsByTypeAndParent(type, parentId);
      apiResponse(res, 200, true, 'Locations retrieved successfully', locations);
    } catch (error) {
      next(error);
    }
  };
  
  const editLocation = async (req, res, next) => {
    try {
      const { id } = req.params;
      const { name } = req.body;
      const updatedLocation = await updateLocation(id, name);
      apiResponse(res, 200, true, 'Location updated successfully', updatedLocation);
    } catch (error) {
      next(error);
    }
  };
  
  const removeLocation = async (req, res, next) => {
    try {
      const { id } = req.params;
      await deleteLocation(id);
      apiResponse(res, 200, true, 'Location deleted successfully');
    } catch (error) {
      next(error);
    }
  };
  
  module.exports = {
    createLocation,
    getLocations,
    editLocation,
    removeLocation
  };