const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');

const app = express();
const PORT = 5000;
const JWT_SECRET = 'SeCrEt';

app.use(bodyParser.json());

mongoose.connect('mongodb+srv://root:root@portal.yrud5.mongodb.net/growthx_assignment')
    .then(() => console.log('DB Connected'))
    .catch(err => console.error('DB Connection failed:', err));


const userSchema = new mongoose.Schema({
    username: { type: String, required: true },
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['user', 'admin'], required: true }
});
const User = mongoose.model('User', userSchema);

const assignmentSchema = new mongoose.Schema({
    userId: { type: String, required: true },
    task: { type: String, required: true },
    admin: { type: String, required: true },
    status: { type: String, enum: ['pending', 'accepted', 'rejected'], default: 'pending' },
    createdAt: { type: Date, default: Date.now }
});
const Assignment = mongoose.model('Assignment', assignmentSchema);

const authenticateJWT = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access Denied' });
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(400).json({ error: 'Invalid Token' });
        req.user = user;
        next();
    });
};

app.post('/register', async (req, res) => {
    const { username, email, password, role } = req.body;
    if (!username || !email || !password || !role) {
        return res.status(400).json({ error: 'provide all required fields' });
    }
    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ error: 'Already registered, go to login' });
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, email, password: hashedPassword, role });
        await newUser.save();
        res.json({ message: 'User successfully registered' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to register' });
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user) return res.status(400).json({ error: 'User not found' });
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: 'Invalid credentials' });
        const token = jwt.sign({ _id: user._id, role: user.role }, JWT_SECRET);
        res.json({ token });
    } catch (err) {
        res.status(500).json({ error: 'Failed to login' });
    }
});

app.post('/upload', authenticateJWT, async (req, res) => {
    if (req.user.role !== 'user') return res.status(403).json({ error: 'Access denied' });
    const { task, admin } = req.body;
    const newAssignment = new Assignment({ userId: req.user._id, task, admin });
    await newAssignment.save();
    res.json({ message: 'Assignment uploaded successfully' });
});

app.get('/admins', authenticateJWT, async (req, res) => {
    const admins = await User.find({ role: 'admin' }).select('username');
    res.json(admins);
});

app.get('/assignments', authenticateJWT, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });

    const assignments = await Assignment.find({ admin: req.user.username });
    res.json(assignments);
})


app.post('/assignments/:id/accept', authenticateJWT, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });
    try {
        await Assignment.findByIdAndUpdate(req.params.id, { status: 'accepted' });
        res.json({ message: 'Assignment accepted' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to accept assignment' });
    }
});

app.post('/assignments/:id/reject', authenticateJWT, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });
    try {
        await Assignment.findByIdAndUpdate(req.params.id, { status: 'rejected' });
        res.json({ message: 'Assignment rejected' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to reject assignment' });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
