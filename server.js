const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// --- INITIALIZE APP ---
const app = express();

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json()); // for parsing application/json

// --- CONFIGURATION ---
// This should be in a separate config file in a real app
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';

// --- DATABASE CONNECTION ---
const MONGO_URI = process.env.MONGO_URI || 'mongodb+srv://mohmmadalishaikh0211_db_user:ali12345@cluster0.wxybm7l.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';

mongoose.connect(MONGO_URI, { 
    tls: true // Enforce secure connection to fix SSL/TLS errors
})
.then(() => console.log('Successfully connected to MongoDB.'))
.catch(err => console.error('MongoDB connection error:', err));


// --- MONGOOSE SCHEMAS & MODELS ---

// User Schema
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    phoneNumber: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['job_seeker', 'employer'], required: true },
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

// Job Schema
const jobSchema = new mongoose.Schema({
    employer: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    title: { type: String, required: true },
    companyName: { type: String },
    description: { type: String, required: true },
    location: {
        village: { type: String, required: true },
        district: { type: String, required: true },
        state: { type: String, required: true }
    },
    requiredSkills: [String],
    createdAt: { type: Date, default: Date.now }
});
const Job = mongoose.model('Job', jobSchema);

// Application Schema
const applicationSchema = new mongoose.Schema({
    job: { type: mongoose.Schema.Types.ObjectId, ref: 'Job', required: true },
    applicant: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    status: { type: String, enum: ['applied', 'viewed', 'shortlisted', 'rejected'], default: 'applied' },
    appliedAt: { type: Date, default: Date.now }
});
const Application = mongoose.model('Application', applicationSchema);


// --- AUTHENTICATION MIDDLEWARE ---
const auth = (req, res, next) => {
    const token = req.header('x-auth-token');
    if (!token) {
        return res.status(401).json({ msg: 'No token, authorization denied' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded.user;
        next();
    } catch (err) {
        res.status(401).json({ msg: 'Token is not valid' });
    }
};


// --- API ROUTES ---

// -- Auth Routes --
// Register a new user
app.post('/api/auth/register', async (req, res) => {
    const { name, phoneNumber, password, role } = req.body;
    try {
        let user = await User.findOne({ phoneNumber });
        if (user) return res.status(400).json({ msg: 'User already exists' });

        user = new User({ name, phoneNumber, password, role });
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);
        await user.save();

        const payload = { user: { id: user.id } };
        jwt.sign(payload, JWT_SECRET, { expiresIn: 3600 }, (err, token) => {
            if (err) throw err;
            res.json({ token });
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ msg: 'Server Error' });
    }
});

// Login a user
app.post('/api/auth/login', async (req, res) => {
    const { phoneNumber, password } = req.body;
    try {
        let user = await User.findOne({ phoneNumber });
        if (!user) return res.status(400).json({ msg: 'Invalid credentials' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ msg: 'Invalid credentials' });

        const payload = { user: { id: user.id } };
        jwt.sign(payload, JWT_SECRET, { expiresIn: 3600 }, (err, token) => {
            if (err) throw err;
            res.json({ token });
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ msg: 'Server Error' });
    }
});

// Get logged in user data
app.get('/api/auth/user', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json(user);
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ msg: 'Server Error' });
    }
});

// -- Job Routes --
// Post a new job
app.post('/api/jobs', auth, async (req, res) => {
    const { title, companyName, description, location, requiredSkills } = req.body;
    try {
        const user = await User.findById(req.user.id);
        if (user.role !== 'employer') {
            return res.status(403).json({ msg: 'Only employers can post jobs' });
        }
        const newJob = new Job({
            employer: req.user.id,
            title,
            companyName,
            description,
            location,
            requiredSkills
        });
        const job = await newJob.save();
        res.json(job);
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ msg: 'Server Error' });
    }
});

// Get all jobs
app.get('/api/jobs', async (req, res) => {
    try {
        const jobs = await Job.find().sort({ createdAt: -1 });
        res.json(jobs);
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ msg: 'Server Error' });
    }
});

// Apply for a job
app.post('/api/jobs/:id/apply', auth, async (req, res) => {
    try {
        const job = await Job.findById(req.params.id);
        if (!job) return res.status(404).json({ msg: 'Job not found' });
        
        const user = await User.findById(req.user.id);
        if (user.role !== 'job_seeker') {
             return res.status(403).json({ msg: 'Only job seekers can apply' });
        }

        const existingApplication = await Application.findOne({ job: req.params.id, applicant: req.user.id });
        if(existingApplication) {
            return res.status(400).json({ msg: 'You have already applied for this job.' });
        }

        const newApplication = new Application({
            job: req.params.id,
            applicant: req.user.id
        });

        await newApplication.save();
        res.json({ msg: 'Application submitted successfully' });

    } catch (err) {
        console.error(err.message);
        res.status(500).json({ msg: 'Server Error' });
    }
});

// -- Employer Specific Routes --

// Get jobs posted by the logged-in employer
app.get('/api/jobs/my-jobs', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        
        // ADDED: Safety check to ensure the user exists in the database
        if (!user) {
            return res.status(404).json({ msg: 'User not found' });
        }

        if (user.role !== 'employer') {
            return res.status(403).json({ msg: 'Access denied' });
        }
        const jobs = await Job.find({ employer: req.user.id }).sort({ createdAt: -1 });
        res.json(jobs);
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ msg: 'Server Error' });
    }
});

// Get applicants for a specific job
app.get('/api/jobs/:jobId/applicants', auth, async (req, res) => {
    try {
        // First, check if the current user is the owner of the job
        const job = await Job.findById(req.params.jobId);
        if (!job) {
            return res.status(404).json({ msg: 'Job not found' });
        }
        if (job.employer.toString() !== req.user.id) {
            return res.status(403).json({ msg: 'User not authorized to view applicants for this job' });
        }

        // Find applications and populate applicant details
        const applications = await Application.find({ job: req.params.jobId })
            .populate('applicant', 'name phoneNumber'); // Populate with applicant's name and phone number

        res.json(applications);

    } catch (err) {
        console.error(err.message);
        res.status(500).json({ msg: 'Server Error' });
    }
});

// --- IVR (Toll-Free) Routes ---

// Register a user via a phone call (IVR)
app.post('/api/ivr/register', async (req, res) => {
    const { name, phoneNumber } = req.body;

    // Basic validation
    if (!name || !phoneNumber) {
        return res.status(400).json({ msg: 'Please provide a name and phone number.' });
    }

    try {
        let user = await User.findOne({ phoneNumber });
        if (user) {
            return res.status(400).json({ msg: 'This phone number is already registered.' });
        }

        // Generate a simple 4-digit PIN as a password for phone users
        const pin = Math.floor(1000 + Math.random() * 9000).toString();

        user = new User({
            name,
            phoneNumber,
            password: pin, // Temporarily store the plain PIN
            role: 'job_seeker'
        });

        // Hash the PIN before saving
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(pin, salt);
        await user.save();

        // The IVR system would read this message back to the user
        res.json({ 
            success: true, 
            message: `Registration successful. Your PIN is ${pin}. Please remember this PIN to log in later.` 
        });

    } catch (err) {
        console.error('IVR Registration Error:', err.message);
        res.status(500).json({ msg: 'Server error during registration.' });
    }
});


// --- SERVE FRONTEND ---
app.use(express.static(path.join(__dirname, 'client')));

app.get(/^(?!\/api).*/, (req, res) => {
    res.sendFile(path.join(__dirname, 'client', 'index.html'));
});


// --- SERVER INITIALIZATION ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server is running on http://localhost:${PORT}`));




