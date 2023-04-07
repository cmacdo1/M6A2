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

    if(!user.isModified('password')) {
        return next();
    }

    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(user.password, salt);

    user.password = hash;

    next();
});

const User = mongoose.model('User', userSchema);

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

        const isMatch = await bcrypt.compare(password, user.password);

        if(!isMatch){
            return res.status(400).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

        const token = jwt.sign({email: user.email, role: user.role}, 'secret');

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

app.get('/protected', authenticateUser, authorizeUser(['admin']), (req, res) => {
    res.json({
        success: true,
        message: 'You have accessed a protected resource',
    });
});
