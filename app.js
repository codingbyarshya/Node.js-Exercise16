const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');

dotenv.config();

const router = express.Router();

const users = [];

router.post('/users/signup', (req, res) => {
  const { username, password } = req.body;

  const userExists = users.find(user => user.username === username);
  if (userExists) {
    return res.status(400).json({ error: 'User already exists' });
  }

  bcrypt.genSalt(10, (err, salt) => {
    if (err) {
      return res.status(500).json({ error: 'Error occurred while signing up' });
    }

    bcrypt.hash(password, salt, (err, hashedPassword) => {
      if (err) {
        return res.status(500).json({ error: 'Error occurred while signing up' });
      }

      const newUser = {
        id: users.length + 1,
        username,
        password: hashedPassword,
      };
      users.push(newUser);

      res.status(201).json({ msg: 'Signup successful. Now you can log in.' });
    });
  });
});

router.post('/users/login', (req, res) => {
  const { username, password } = req.body;

  const user = users.find(user => user.username === username);
  if (!user) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  bcrypt.compare(password, user.password, (err, passwordMatch) => {
    if (err) {
      return res.status(500).json({ error: 'Error occurred while logging in' });
    }

    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const payload = {
      id: user.id,
      username: user.username,
    };
    const token = jwt.sign(payload, process.env.SECRET);

    res.json({ token, id: user.id, username: user.username });
  });
});

module.exports = router;
