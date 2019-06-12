const express = require('express');
const bcrypt = require('bcryptjs');
const config = require('config');
const jwt = require('jsonwebtoken');
const auth = require('../../middleware/auth');

const router = express.Router();

// Item model
const User = require('../../models/User');

// @route   GET api/auth
// @desc    Auth user
// @access  Public
router.post('/', (req, res) => {
  const { email, password } = req.body;

  // Simple validation
  if (!email || !password) {
    res.status(400).json( 'Please enter all fields' );
  }

  // Check for existing user
  User.findOne({ email })
    .then(user => {
      if(!user) return res.status(400).json( 'User does not exist' );

      // Validate Password
      bcrypt.compare(password, user.password)
        .then(isMatch => {
          if(!isMatch) return res.status(400).json( 'Invalid credentials' );

          jwt.sign(
            { id: user.id },
            config.get('jwtSecret'),
            { expiresIn: 3000 },
            (err, token) => {
              if(err) throw err;
              res.json({
                token,
                user: {
                  name: user.name,
                  email: user.email,
                  password: user.password
                }
              });
            }
          )
        })
    })
});

// @route   GET api/auth/user
// @desc    Get user data
// @access  Private
router.get('/user', auth, (req, res) => {
  User.findById(req.user.id)
    .select('-password')
    .then(user => res.json(user));
});

module.exports = router;