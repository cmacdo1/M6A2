const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const {authenticateUser, authorizeUser} = require('./middleware');

const app = express();

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`App running on port ${PORT}...`);
});

app.use(express.json());

mongoose.connect('mongodb://localhost:27017/auth', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => {
    console.log('Mongo Database Connection was Successful');
}).catch((err) => console.log(err));

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true,
    },
    password: {
        type: String,
        required: true,
    },
    role: {
        type: String,
        enum: ['user', 'admin'],
        default: 'user',
    },
});

userSchema.pre('save', async function (next){
    const user = this;

    // Verifying the password has not been modified
    if(!user.isModified('password')) {
        return next();
    }

    // Hashing the user's password
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(user.password, salt);

    user.password = hash;

    next();
});

const User = mongoose.model('User', userSchema);

// Route for creating user
app.post('/register', async (req, res) => {
    try{
        const {email, password, role} = req.body;
        const user = new User({email, password, role});
        await user.save();

        res.json({
            success: true,
            message: 'User registered successfully',
        });
    }catch (error){
        console.error(error);
        res.status(500).json({
            success: false,
            message: 'An error occurred',
        });
    }
});

// Route for logging in user
app.post('/login', async (req, res) => {
    try{
        const {email, password} = req.body;
        const user = await User.findOne({email});

        if(!user){
            return res.status(400).json({
                success: false,
                message: 'Invalid email or password',
            });
        }

        // Checking that passwords match
        const isMatch = await bcrypt.compare(password, user.password);

        if(!isMatch){
            return res.status(400).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

        // Changed from userId: user._id to email: user.email because user information is not created with their id
        const token = jwt.sign({email: user.email, role: user.role}, 'secret', {
            expiresIn: '10d'
        });
        const cookieOptions = {
            expires: new Date(
                Date.now() + 10 * 24 * 60 * 60 * 1000
            ),
            httpOnly: true
        };

        res.cookie('jwt', token, cookieOptions);
        res.json({
            success: true,
            token,
        });
    } catch(error){
        console.error(error);
        res.status(500).json({
            success: false,
            message: 'An error occurred',
        });
    }
});

// Route for accessing protected resources
app.get('/protected', authenticateUser, authorizeUser(['admin']), (req, res) => {
    res.json({
        success: true,
        message: 'You have accessed a protected resource',
    });
});

// In-memory storage for invalid tokens
const invalidTokens = new Set();

// // Route for logging out a user
app.post('/logout', (req, res) => {
    // Get the token from the request header
    const token = req.headers.authorization;
  
    // Error response if token is not provided
    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'Token not provided',
        });
    }
  
    try {
        // Verify and decode the JWT token
        const decoded = jwt.verify(token, 'secret');

        // Add the decoded token to the list of invalid tokens
        invalidTokens.add(decoded.email);

        // clearing JWT cookie
        res.cookie('jwt', '', {
        expires: new Date(0)
        });
  
        // Return a response indicating successful logout
        res.status(200).json({
            success: true,
            message: 'Logout successful',
        });
    } catch (error) {
        // If token is invalid, return an error response
        res.status(401).json({
            success: false,
            message: 'Invalid token',
        });
    }
});