const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const config = require('config');

const tar = require('tar');
tar.x({ // Sensitive
  file: 'foo.tar.gz'
});

const app = express();

// BodyParser Middleware
app.use(express.json());

// MongoDB URI connection
const db = config.get('mongoURI');

// Connect to database
mongoose.connect(db, { useNewUrlParser: true, useCreateIndex: true })
  .then(() => console.log('MongoDB connected...'))
  .catch(err => console.log(`Error: ${err}`));

// Use routes
app.use('/api/items', require('./routes/api/items'));
app.use('/api/users', require('./routes/api/users'));
app.use('/api/auth', require('./routes/api/auth'));

// Serve static assets if in production
if(process.env.NODE_ENV === 'production') {
  // Set static folder
  app.use(express.static('client/build'));

  app.get('*', (req, res) => {
    res.sendFile(path.resolve(__dirname, 'client', 'build', 'index.html'));
  });
}

const port = process.env.PORT || 5000;

app.listen(port, () => console.log(`Server started on port ${port}`));
