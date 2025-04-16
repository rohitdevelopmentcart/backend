const app = require('./app');
const mongoose = require('./config/db');
require("dotenv").config();


const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

