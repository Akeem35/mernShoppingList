const express = require('express');
const bcrypt = require('bcryptjs');
const config = require('config');
const jwt = require('jsonwebtoken');

const router = express.Router();

// Item model
const User = require('../../models/User');

// @route   GET api/users
// @desc    Register new user
// @access  Public
router.post('/', (req, res) => {
  const { name, email, password } = req.body;

  // Simple validation
  if (!name || !email || !password) {
    res.status(400).json('Please enter all fields');
  }

  // Check for existing user
  User.findOne({ email })
    .then(user => {
      if(user) return res.status(400).json('User already exist');

      const newUser = new User({
        name,
        email,
        password
      });

      // Create Salt & Hash
      bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash(newUser.password, salt, (err, hash) => {
          if(err) throw err;
          newUser.password = hash;
          newUser.save()
            .then(user => {

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
            });
        })
      })
    })
});

module.exports = router;