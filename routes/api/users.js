const express = require('express');
const router  = express.Router();
const { check,validationResult } = require('express-validator'); 
const gravator = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt  = require('jsonwebtoken');
const config = require('config'); 

const User = require('../../models/users');

// @route POST api/users
// @desc Register User
// access Public
router.post('/', [
    check('name', 'Name is required')
    .not()
    .isEmpty(),
    check('email', "Enter the valid email").isEmail(),
    check('password', 'Password should be of length 6 or more')
    .isLength({ min: 6 })
], async (req,res) => {
    const errors = validationResult(req);
    if(!errors.isEmpty()) {
        return res.status(400).json({
            errors: errors.array()
        });
    }
    const {name, email, password} = req.body;
    try{
        // See if user exits
        let user = await User.findOne({ email });
        if(user) {
            return res.status(400).json({ 
                errors: [{ msg: 'User already exits' }]
            });
        }

        // Get users gravator
        const avator = gravator.url(email, {
            s: '200',
            r: 'pg',
            d: 'mm'
        })

        user = new User({
            name,
            email,
            avator,
            password
        })
        // Encrypt passwors
        const salt  = await bcrypt.genSalt(10);

        user.password = await bcrypt.hash(password,salt);

        await user.save();

        // Return JWT
        const payload = {
            user: {
                id: user.id
            }
        }

        jwt.sign(
            payload,
            config.get('jwtsecret'),
            {expiresIn: 3600000},
            (err, token) => {
                if(err) throw err;
                res.json({ token });
            });
    } catch(err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
    
    
})

module.exports = router;