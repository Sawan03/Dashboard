// Import required modules
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const { body, validationResult } = require('express-validator');
const cors = require('cors'); // Import cors
const path = require('path');

// Create the Express app
const app = express();

// Middleware
app.use(express.json());
app.use(helmet()); // Adds security headers
app.use(morgan('combined')); // Logs HTTP requests

// CORS configuration
app.use(cors({
  origin: 'http://localhost:3000', // Replace with your frontend origin
  methods: 'GET,POST,PUT,DELETE',
  allowedHeaders: 'Content-Type,Authorization',
}));

// Enable trust proxy
app.set('trust proxy', 1); // Set to 1 to trust the first proxy

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
});

app.use(limiter);

// Connect to MongoDB Atlas (replace with your URI)
const MONGO_URI = 'mongodb+srv://sawanrathore815:ttmZa7vqZWKdYyLj@cluster0.vabf9.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';

mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('MongoDB connected'))
.catch(err => console.error('MongoDB connection error:', err));

// User schema and model
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  role: {
    type: String,
    enum: ['Administrator', 'Manager', 'Regular User'],
    default: 'Regular User',
  },
});

const User = mongoose.model('User', userSchema);

// Job schema and model
const jobSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  location: { type: String, required: true },
  salary: { type: Number, required: true },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  createdAt: { type: Date, default: Date.now }
});

const Job = mongoose.model('Job', jobSchema);

// Middleware to verify JWT and extract user info
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'No token, authorization denied' });
  }

  try {
    const decoded = jwt.verify(token, 'your_jwt_secret'); // Replace with your secret key
    req.user = decoded;
    next();
  } catch (err) {
    res.status(400).json({ message: 'Invalid token' });
  }
};

// Middleware to check role permissions
const authorizeRole = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res
        .status(403)
        .json({ message: 'Access forbidden: insufficient rights' });
    }
    next();
  };
};

// Register route
app.post(
  '/api/register',
  [
    body('username').isString().notEmpty().withMessage('Username is required'),
    body('password').isString().isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;

    try {
      // Check if user already exists
      const existingUser = await User.findOne({ username });
      if (existingUser) {
        return res.status(400).json({ message: 'Username already exists' });
      }

      // Determine role based on username
      let role;
      if (username.toLowerCase().includes('admin')) {
        role = 'Administrator';
      } else if (username.toLowerCase().includes('manager')) {
        role = 'Manager';
      } else {
        role = 'Regular User';
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Create new user
      const newUser = new User({ username, password: hashedPassword, role });
      await newUser.save();

      res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
      console.error('Error registering user:', error);
      res.status(500).json({ message: 'Server error' });
    }
  }
);

// Login route
app.post(
  '/api/login',
  [
    body('username').isString().notEmpty().withMessage('Username is required'),
    body('password').isString().notEmpty().withMessage('Password is required'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;

    try {
      const user = await User.findOne({ username });
      if (!user) {
        return res.status(400).json({ message: 'User not found' });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(400).json({ message: 'Invalid credentials' });
      }

      // Generate JWT token with role and username
      const token = jwt.sign(
        { id: user._id, role: user.role, username: user.username },
        'your_jwt_secret', // Replace with your secret key
        { expiresIn: '1h' }
      );

      res.json({ token, role: user.role, username: user.username });
    } catch (error) {
      console.error('Error logging in:', error);
      res.status(500).json({ message: 'Server error' });
    }
  }
);

// Update admin details route
app.post(
  '/api/update-admin',
  authenticateToken,
  authorizeRole(['Administrator']),
  [
    body('currentUsername').isString().notEmpty().withMessage('Current username is required'),
    body('newUsername').isString().notEmpty().withMessage('New username is required'),
    body('currentPassword').isString().notEmpty().withMessage('Current password is required'),
    body('newPassword').isString().isLength({ min: 6 }).withMessage('New password must be at least 6 characters'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { currentUsername, newUsername, currentPassword, newPassword } = req.body;

    try {
      const admin = await User.findOne({ username: currentUsername });
      if (!admin) {
        return res.status(400).json({ message: 'Admin not found' });
      }

      const isPasswordValid = await bcrypt.compare(currentPassword, admin.password);
      if (!isPasswordValid) {
        return res.status(400).json({ message: 'Invalid password' });
      }

      // Update admin details
      admin.username = newUsername;
      admin.password = await bcrypt.hash(newPassword, 10);
      await admin.save();

      res.json({ message: 'Admin details updated successfully' });
    } catch (error) {
      console.error('Error updating admin details:', error);
      res.status(500).json({ message: 'Server error' });
    }
  }
);

// Route to get data for Administrators
app.get('/api/admin-data', authenticateToken, authorizeRole(['Administrator']), (req, res) => {
  res.json({ message: 'Admin specific data' });
});

// Route to get data for Managers
app.get('/api/manager-data', authenticateToken, authorizeRole(['Manager']), (req, res) => {
  res.json({ message: 'Manager specific data' });
});

// Create a new job
app.post(
  '/api/jobs',
  authenticateToken,
  authorizeRole(['Administrator', 'Manager']),
  [
    body('title').isString().notEmpty().withMessage('Job title is required'),
    body('description').isString().notEmpty().withMessage('Job description is required'),
    body('location').isString().notEmpty().withMessage('Job location is required'),
    body('salary').isNumeric().withMessage('Job salary must be a number'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { title, description, location, salary } = req.body;
    const { id: createdBy } = req.user;

    try {
      const newJob = new Job({ title, description, location, salary, createdBy });
      await newJob.save();
      res.status(201).json({ message: 'Job created successfully', job: newJob });
    } catch (error) {
      console.error('Error creating job:', error);
      res.status(500).json({ message: 'Server error' });
    }
  }
);

// Get all jobs (for Administrators and Managers)
app.get('/api/jobs', authenticateToken, authorizeRole(['Administrator', 'Manager']), async (req, res) => {
  try {
    const jobs = await Job.find().populate('createdBy', 'username');
    res.json(jobs);
  } catch (error) {
    console.error('Error fetching jobs:', error);
    res.status(500).json({ message: 'Server error' });
  }
});


// Get job by ID (for Administrators and Managers) - Testing Purpose Only
app.get('/api/jobs/:id', authenticateToken, authorizeRole(['Administrator', 'Manager']), (req, res) => {
  const { id } = req.params;

  // Mock job data for testing
  const mockJobData = {
    id,
    title: 'Sample Job Title',
    description: 'This is a sample job description used for testing purposes.',
    location: 'Sample Location',
    salary: 50000,
    createdBy: {
      username: 'testAdmin'
    }
  };

  res.json(mockJobData);
});

// Create Job Endpoint
app.post('/api/create-job', authenticateToken, async (req, res) => {
  const { title, description, location, salary } = req.body;
  const createdBy = req.user.id;

  if (!title || !description || !location || !salary) {
    return res.status(400).json({ success: false, message: 'All fields are required' });
  }

  try {
    const newJob = new Job({ title, description, location, salary, createdBy });
    await newJob.save();
    res.status(201).json({ success: true, message: 'Job created successfully' });
  } catch (error) {
    console.error('Error creating job:', error);
    res.status(500).json({ success: false, message: 'An error occurred while creating the job' });
  }
});




// Update a job (for Administrators and Managers)
app.put(
  '/api/jobs/:id',
  authenticateToken,
  authorizeRole(['Administrator', 'Manager']),
  [
    body('title').optional().isString().notEmpty().withMessage('Job title is required'),
    body('description').optional().isString().notEmpty().withMessage('Job description is required'),
    body('location').optional().isString().notEmpty().withMessage('Job location is required'),
    body('salary').optional().isNumeric().withMessage('Job salary must be a number'),
  ],
  async (req, res) => {
    const { id } = req.params;
    const { title, description, location, salary } = req.body;

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const job = await Job.findById(id);
      if (!job) {
        return res.status(404).json({ message: 'Job not found' });
      }

      if (title) job.title = title;
      if (description) job.description = description;
      if (location) job.location = location;
      if (salary) job.salary = salary;

      await job.save();
      res.json({ message: 'Job updated successfully', job });
    } catch (error) {
      console.error('Error updating job:', error);
      res.status(500).json({ message: 'Server error' });
    }
  }
);

// Delete a job (for Administrators and Managers)
app.delete('/api/jobs/:id', authenticateToken, authorizeRole(['Administrator', 'Manager']), async (req, res) => {
  const { id } = req.params;

  try {
    const job = await Job.findById(id);
    if (!job) {
      return res.status(404).json({ message: 'Job not found' });
    }

    await job.remove();
    res.json({ message: 'Job deleted successfully' });
  } catch (error) {
    console.error('Error deleting job:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Serve static files (if applicable)
// app.use(express.static(path.join(__dirname, 'public')));

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
