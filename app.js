const express = require('express');
const authRoutes = require('./routes/admin/authRoutes');
const locationRoutes = require('./routes/admin/locationRoutes')
const studentTypeRoutes = require('./routes/admin/studentTypeRoutes')

const app = express();

app.use(express.json());
app.use('/api/admin', authRoutes);
app.use('/api/admin/locations', locationRoutes);
app.use('/api/admin/student-types', studentTypeRoutes);

module.exports = app;
