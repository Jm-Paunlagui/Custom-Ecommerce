const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken'); // to generate token
const bcrypt = require('bcryptjs'); // encrypt password
// Check validation for requests
const {
  check,
  validationResult
} = require('express-validator');
const gravatar = require('gravatar'); // get user image by email
const auth = require('../middleware/auth')
// Models
const User = require('../models/User');
const sgMail = require('nodemailer');

console.log(process.env.EMAIL, process.env.PASSWORD)
const transporter = sgMail.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL,
    pass: process.env.PASSWORD
  }
});

// @route   POST api/user
// @desc    User Information
// @access  Private 
router.get('/', auth, async (req, res) => {
    try {
      // get user information by id 
      const user = await User.findById(req.user.id).select('-password')
      res.json(user)
    } catch (error) {
      console.log(err.message);
      res.status(500).send('Server Error')
    }
  })
  

// @route   POST api/user/register
// @desc    Register user
// @access  Public
router.post('/register', (req, res) => {
    const { name, email, password } = req.body;
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        const firstError = errors.array().map(error => error.msg)[0];
        return res.status(422).json({
          errors: firstError
        });
    } else { 
        User.findOne({
            email
        }).exec((user) => {
            if(user) return res.status(400).json({errors: 'Email is taken'})
            else{
                const token = jwt.sign({
                  name,
                  email,
                  password
                },process.env.JWT_SECRET,{
                    expiresIn: 240
                })
                const emailData = {
                    from: process.env.EMAIL_FROM,
                    to: email,
                    subject: 'Account activation link',
                    html: `
                              <h1>Please use the following to activate your account</h1>
                              <p>${process.env.CLIENT_URL}/users/activate/${token}</p>
                              <hr />
                              <p>This email may containe sensetive information</p>
                              <p>${process.env.CLIENT_URL}</p>
                          `
                  };
                  transporter.sendMail(emailData, (err, data) =>{
                    if(err) return console.log(err)
                    else return res.json({data})
                  })
               
            }              
             
        })
    }
})

// @route   POST api/user/activation
// @desc    Activation
// @access  Public
router.post('/activation', (req, res) => {
    const { token } = req.body;        
      
    if(token){
        jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
            if(err){
                console.log('Activation error');
                return res.status(401).json({
                errors: err
                });
            }else{
                const { name, email, password } = jwt.decode(token);
                // get image from gravatar
                const avatar = gravatar.url(email, {
                    s: '200', // Size
                    r: 'pg', // Rate,
                    d: 'mm',
                });
                // create user object
                user = new User({
                    name,
                    email,
                    avatar,
                    password,
                });

                // encrypt password
                
                // save password
                
                //save user in databasw
                user.save((err, user) => {
                    if (err) {
                        console.log('Save error', errorHandler(err));
                        return res.status(401).json({
                        errors: errorHandler(err)
                        });
                    } else {
                        
                        return res.json({
                        success: true,
                        message: user,
                        message: 'Signup success'
                        });
                    }
                });
            }
        })
    }else{
        return res.json({
            message: 'error happening please try again'
        });
    }
})

module.exports = router