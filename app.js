require('dotenv').config(); // Load environment variables from .env
const express = require('express');
const morgan = require('morgan');
const helmet = require('helmet');
const authRoutes = require('./routes/authRoutes');
const path = require('path');

// Initialize Express App
const app = express();

// Middleware
app.use(helmet()); // Adds security headers
app.use(morgan('dev')); // Logging
app.use(express.json()); // Parses JSON request bodies

// Routes
app.use('/api/auth', authRoutes);

// Catch-all Error Handler for unhandled routes
app.use((req, res, next) => {
  const error = new Error('Not Found');
  error.status = 404;
  next(error);
});

app.use((error, req, res, next) => {
  res.status(error.status || 500);
  res.json({
    error: {
      message: error.message
    }
  });
});

// Start HTTP Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
