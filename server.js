const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');

const items = require('./routes/api/items');

const app = express();

// BodyParser Middleware
app.use(bodyParser.json());

// MongoDB URI connection
const db = require('./config/keys').mongoURI;

// Connect to database
mongoose.connect(db, {useNewUrlParser: true})
  .then(() => console.log('MongoDB connected...'))
  .catch(err => console.log(`Error: ${err}`));

// Use routes
app.use('/api/items', items);

const port = process.env.PORT || 5000;

app.listen(port, () => console.log(`Server started on port ${port}`));