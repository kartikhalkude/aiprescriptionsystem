const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || '28c13fcfb3540104ff1d58e8a4b2051c73a7beb0a5fdc86fe464ac941695c277cbdce4d29cab3cfea0f61e83aa6e79f40887e16b69f296dd6318a15b6d68dd4f152d0d24a47e5d1e01164290f775f0f2aa3a2660ba6987f5dbab09276ce81157f00f8775600830a60a44861a4111a3b798e3cdcf614fdacdedbc237ce2e20084b5aa763a167b6f5e95e646e57344afdf6dd68aca8e62c41c8ca43325a5f5ab186e052a5dd37c24036b0b09132c54ac43431ecac9f7adc1df2fc3493f4f81b292acdadc55aee72c5a446962a576e1af07e8334f123b1a7b5f8147bd29777db1c3df6788b21699163c284dfa9e6fa4d7eef348667ad8c08f93cdd4c584b569251f';

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

mongoose.connect('mongodb://localhost:27017/ai-prescription', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('Connected to MongoDB');
}).catch(err => {
    console.error('MongoDB connection error:', err);
});

const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['patient', 'doctor'], required: true },
    age: Number,
    specialization: String
});

const PrescriptionSchema = new mongoose.Schema({
    patientId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    doctorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    symptoms: { type: String, required: true },
    duration: { type: String, required: true },
    severity: { type: Number, required: true, min: 1, max: 10 },
    aiDiagnosis: String,
    medications: [{
        name: { type: String, required: true },
        dosage: { type: String, required: true },
        frequency: { type: String, required: true },
        duration: String
    }],
    doctorNotes: String,
    status: { 
        type: String, 
        enum: ['pending', 'approved', 'rejected'], 
        default: 'pending' 
    },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date }
});

const User = mongoose.model('User', UserSchema);
const Prescription = mongoose.model('Prescription', PrescriptionSchema);

const authenticateToken = (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }

        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (err) return res.status(403).json({ error: 'Invalid token' });
            req.user = user;
            next();
        });
    } catch (error) {
        res.status(500).json({ error: 'Authentication error' });
    }
};

app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password, role, age, specialization } = req.body;
        
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'Email already registered' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            name,
            email,
            password: hashedPassword,  // Save hashed password
            role,
            age,
            specialization
        });
        

        await user.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(400).json({ error: 'User not found' });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ error: 'Invalid password' });
        }

        const token = jwt.sign(
            { id: user._id, role: user.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({ 
            token,
            user: {
                id: user._id,
                name: user.name,
                role: user.role
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Login failed' });
    }
});

app.post('/api/prescriptions', authenticateToken, async (req, res) => {
    try {
        const { symptoms, duration, severity, aiDiagnosis } = req.body;
        const doctor = await User.findOne({ role: 'doctor' });

        if (!doctor) {
            return res.status(400).json({ error: 'No doctors available' });
        }

        if (!aiDiagnosis) {
            return res.status(400).json({ error: 'AI diagnosis is required' });
        }

        const prescription = new Prescription({
            patientId: req.user.id,
            doctorId: doctor._id,
            symptoms,
            duration,
            severity,
            aiDiagnosis, // ✅ Store AI-generated prescription
            status: "pending",
        });

        await prescription.save();
        res.status(201).json({ message: 'Prescription created & sent to doctor', prescription });
    } catch (error) {
        res.status(500).json({ error: 'Failed to create prescription' });
    }
});

app.get('/api/prescriptions', authenticateToken, async (req, res) => {
    try {
        let prescriptions;
        if (req.user.role === 'doctor') {
            prescriptions = await Prescription.find({ doctorId: req.user.id })
                .populate('patientId', 'name age')
                .sort({ createdAt: -1 });
        } else {
            prescriptions = await Prescription.find({ patientId: req.user.id })
                .populate('doctorId', 'name specialization')
                .sort({ createdAt: -1 });
        }

        res.json(prescriptions);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch prescriptions' });
    }
});


app.get('/api/prescriptions/:id', authenticateToken, async (req, res) => {
    try {
        const prescription = await Prescription.findById(req.params.id)
            .populate('patientId', 'name age')
            .populate('doctorId', 'name specialization');

        if (!prescription) {
            return res.status(404).json({ error: 'Prescription not found' });
        }

        res.json(prescription);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch prescription' });
    }
});

app.put('/api/prescriptions/:id', authenticateToken, async (req, res) => {
    try {
        const { medications, doctorNotes, status } = req.body;
        
        if (req.user.role !== 'doctor') {
            return res.status(403).json({ error: 'Only doctors can update prescriptions' });
        }

        const prescription = await Prescription.findByIdAndUpdate(
            req.params.id,
            {
                medications,
                doctorNotes,
                status,
                updatedAt: Date.now()
            },
            { new: true }
        );

        if (!prescription) {
            return res.status(404).json({ error: 'Prescription not found' });
        }

        res.json(prescription);
    } catch (error) {
        res.status(500).json({ error: 'Failed to update prescription' });
    }
});

app.get('/api/doctor/info', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'doctor') {
            return res.status(403).json({ error: 'Access denied' });
        }

        const doctor = await User.findById(req.user.id).select('name specialization');
        if (!doctor) {
            return res.status(404).json({ error: 'Doctor not found' });
        }

        res.json(doctor);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch doctor info' });
    }
});

app.get('/api/patient/info', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'patient') {
            return res.status(403).json({ error: 'Access denied' });
        }

        const patient = await User.findById(req.user.id).select('name age');
        if (!patient) {
            return res.status(404).json({ error: 'Patient not found' });
        }

        res.json(patient);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch patient info' });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});app.delete('/api/prescriptions/:id', authenticateToken, async (req, res) => {
    try {
        const prescription = await Prescription.findById(req.params.id);

        if (!prescription) {
            return res.status(404).json({ error: 'Prescription not found' });
        }

        // Check if the requester is either:
        // 1. The patient who created the prescription (can delete if status is "pending")
        // 2. The doctor assigned to review the prescription (can delete anytime)
        if (req.user.role === 'patient' && prescription.patientId.toString() === req.user.id) {
            if (prescription.status !== "pending") {
                return res.status(403).json({ error: 'You cannot delete an approved or rejected prescription' });
            }
        } else if (req.user.role === 'doctor' && prescription.doctorId.toString() !== req.user.id) {
            return res.status(403).json({ error: 'You are not authorized to delete this prescription' });
        }

        // Delete the prescription
        await Prescription.findByIdAndDelete(req.params.id);
        res.json({ message: 'Prescription deleted successfully' });

    } catch (error) {
        res.status(500).json({ error: 'Failed to delete prescription' });
    }
});
