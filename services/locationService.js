const Location = require('../models/Location');

const addLocation = async (name, type, parentId = null) => {
  // Check for duplicates
  const existingLocation = await Location.findOne({ name, type, parent: parentId });
  if (existingLocation) {
    throw new Error('Location with this name already exists');
  }

  // Validate parent exists if provided
  if (parentId) {
    const parent = await Location.findById(parentId);
    if (!parent) {
      throw new Error('Parent location not found');
    }

    // Validate type hierarchy
    if ((type === 'state' && parent.type !== 'country') || 
        (type === 'city' && parent.type !== 'state')) {
      throw new Error('Invalid location hierarchy');
    }
  }

  const location = new Location({ name, type, parent: parentId });
  return await location.save();
};

const getLocationsByTypeAndParent = async (type, parentId = null) => {
  return await Location.find({ type, parent: parentId }).sort({ name: 1 });
};

const updateLocation = async (id, name) => {
  const location = await Location.findById(id);
  if (!location) {
    throw new Error('Location not found');
  }

  // Check if new name already exists for this type and parent
  const existingLocation = await Location.findOne({
    name,
    type: location.type,
    parent: location.parent,
    _id: { $ne: id }
  });
  if (existingLocation) {
    throw new Error('Location with this name already exists');
  }

  location.name = name;
  return await location.save();
};

const deleteLocation = async (id) => {
  const location = await Location.findById(id);
  if (!location) {
    throw new Error('Location not found');
  }

  // Check if location has children
  const childCount = await Location.countDocuments({ parent: id });
  if (childCount > 0) {
    throw new Error('Cannot delete location with child locations');
  }

  return await Location.findByIdAndDelete(id);
};

module.exports = {
  addLocation,
  getLocationsByTypeAndParent,
  updateLocation,
  deleteLocation
};