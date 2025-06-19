require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require("mongoose");
const User = require('./models/User');
const Post = require('./models/Post');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const fs = require('fs');
const path = require('path');



const app = express();
const salt = bcrypt.genSaltSync(10);
const secret = process.env.JWT_SECRET;

// Configure Multer
const uploadMiddleware = multer({ dest: 'uploads/' });

// Middleware
app.use(cors({ credentials: true, origin: 'http://localhost:3000' }));
app.use(express.json());
app.use(cookieParser());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Connect to MongoDB
mongoose.set('strictQuery', false);

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('Failed to connect to MongoDB',err));

// Routes
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const userDoc = await User.create({
      username,
      password: bcrypt.hashSync(password, salt),
    });
    res.json(userDoc);
  } catch (e) {
    console.error(e);
    res.status(400).json(e);
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const userDoc = await User.findOne({ username });
  if (userDoc && bcrypt.compareSync(password, userDoc.password)) {
    jwt.sign({ username, id: userDoc._id }, secret, {}, (err, token) => {
      if (err) return res.status(500).json({ message: 'Token generation error' });
      res.cookie('token', token).json({ id: userDoc._id, username });
    });
  } else {
    res.status(400).json('Wrong credentials');
  }
});

app.get('/profile', (req, res) => {
  const { token } = req.cookies;
  jwt.verify(token, secret, {}, (err, info) => {
    if (err) return res.status(401).json({ message: 'Invalid token' });
    res.json(info);
  });
});

app.post('/logout', (req, res) => {
  res.cookie('token', '').json('ok');
});
app.post('/post', uploadMiddleware.single('file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: 'No file uploaded' });
  }

  const { originalname, path: tempPath } = req.file;
  const ext = path.extname(originalname);
  const newPath = tempPath + ext;

  fs.rename(tempPath, newPath, async (err) => {
    if (err) {
      return res.status(500).json({ message: 'File renaming error' });
    }

    const { token } = req.cookies;
    jwt.verify(token, secret, {}, async (err, info) => {
      if (err) {
        return res.status(401).json({ message: 'Invalid token' });
      }
      
      const { title, summary, content } = req.body;
      const postDoc = await Post.create({
        title,
        summary,
        content,
        cover: newPath,
        author: info.id,
      });

      res.json(postDoc);
    });
  });
});



app.put('/post', uploadMiddleware.single('file'), async (req, res) => {
  let newPath = null;
  if (req.file) {
    const { originalname, path: tempPath } = req.file;
    const ext = path.extname(originalname);
    newPath = tempPath + ext;
    fs.renameSync(tempPath, newPath);
  }

  const { token } = req.cookies;
  jwt.verify(token, secret, {}, async (err, info) => {
    if (err) return res.status(401).json({ message: 'Invalid token' });
    const { id, title, summary, content } = req.body;
    const postDoc = await Post.findById(id);
    if (JSON.stringify(postDoc.author) !== JSON.stringify(info.id)) {
      return res.status(400).json('You are not the author');
    }
    await postDoc.updateOne({
      title,
      summary,
      content,
      cover: newPath || postDoc.cover,
    });
    res.json(postDoc);
  });
});

app.get('/post', async (req, res) => {
  res.json(
    await Post.find()
      .populate('author', ['username'])
      .sort({ createdAt: -1 })
      .limit(20)
  );
});

app.get('/post/:id', async (req, res) => {
  const { id } = req.params;
  const postDoc = await Post.findById(id).populate('author', ['username']);
  res.json(postDoc);
});
app.delete('/post/:id', async (req, res) => {
  const { id } = req.params;
  console.log('Received ID:', id); // Verify the received ID

  try {
    // Cast the string ID to an ObjectId
    let objectId;
    try {
      objectId = mongoose.Types.ObjectId(id);
    } catch (err) {
      return res.status(400).json({ message: 'Invalid ID format' });
    }

    // Find the post
    const postDoc = await Post.findById(objectId);
    if (!postDoc) {
      return res.status(404).json({ message: 'Post not found' });
    }

    // Verify user permissions
    const { token } = req.cookies;
    const user = jwt.verify(token, secret);
    if (user.id.toString() !== postDoc.author.toString()) {
      return res.status(403).json({ message: 'Unauthorized to delete this post' });
    }

    // Delete the post
    await postDoc.deleteOne();
    
    // Optionally delete the associated file
    if (postDoc.cover) {
      fs.unlink(postDoc.cover, (err) => {
        if (err) {
          console.error('Error deleting file:', err);
        }
      });
    }

    res.json({ message: 'Post deleted successfully' });
  } catch (err) {
    console.error('Error deleting post:', err);
    res.status(500).json({ message: 'An error occurred while deleting the post' });
  }
});



app.listen(4000, () => console.log('Server running on port 4000'));



