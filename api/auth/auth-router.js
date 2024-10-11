const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Users = require('../users/users-model');
const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || 'shh';

router.post('/register', async (req, res) => {
  try {
      const { username, password } = req.body;
      const newUser = await Users.add({ username, password: bcrypt.hashSync(password, 8) });
      res.status(201).json(newUser);
  } catch (err) {
      console.error('Error registering user:', err);
      res.status(500).json({ message: 'Error registering user' });
  }
});

router.post('/login', async (req, res) => {
  try {
      const { username, password } = req.body;
      const user = await Users.findBy({ username }).first();
      if (user && bcrypt.compareSync(password, user.password)) {
          const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });
          res.status(200).json({ message: `Welcome ${user.username}`, token });
      } else {
          res.status(401).json({ message: 'Invalid credentials' });
      }
  } catch (err) {
      console.error('Error logging in user:', err);
      res.status(500).json({ message: 'Error logging in' });
  }
});

module.exports = router;