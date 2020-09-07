const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken'); // to generate token
const bcrypt = require('bcryptjs'); // encrypt password
const _ = require('lodash');
const { OAuth2Client } = require('google-auth-library');
const fetch = require('node-fetch');
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

const {
    validSign,
    validLogin,
    forgotPasswordValidator,
    resetPasswordValidator
} = require('../helpers/valid')

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
router.post('/register', validSign, (req, res) => {
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

// @route   POST api/user/login
// @desc    Login user
// @access  Public
router.post('/login', validLogin, (req, res) => {
    const { email, password } = req.body;
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const firstError = errors.array().map(error => error.msg)[0];
    return res.status(422).json({
      errors: firstError
    });
  } else {
    // check if user exist
    User.findOne({
      email
    }).exec((err, user) => {
      if (err || !user) {
        return res.status(400).json({
          errors: 'User with that email does not exist. Please signup'
        });
      }
      // authenticate
      if (!user.authenticate(password)) {
        return res.status(400).json({
          errors: 'Email and password do not match'
        });
      }
      // generate a token and send to client
      const token = jwt.sign(
        {
          _id: user._id
        },
        process.env.JWT_SECRET,
        {
          expiresIn: '7d'
        }
      );
      const { _id, name, email, role } = user;

      return res.json({
        token,
        user: {
          _id,
          name,
          email,
          role
        }
      });
    });
  }
})

// @route   POST api/user/googlelogin
// @desc    Login user
// @access  Public
const client = new OAuth2Client(process.env.GOOGLE_CLIENT);
console.log(process.env.GOOGLE_CLIENT);

router.post('/googlelogin', (req, res) => {
  const { idToken } = req.body;

  client
    .verifyIdToken({ idToken, audience: process.env.GOOGLE_CLIENT })
    .then(response => {
      // console.log('GOOGLE LOGIN RESPONSE',response)
      const { email_verified, name, email } = response.payload;
      if (email_verified) {
        User.findOne({ email }).exec((err, user) => {
          if (user) {
            const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, {
              expiresIn: '7d'
            });
            const { _id, email, name, role } = user;
            return res.json({
              token,
              user: { _id, email, name, role }
            });
          } else {
            let password = email + process.env.JWT_SECRET;
            user = new User({ name, email, password });
            user.save((err, data) => {
              if (err) {
                console.log('ERROR GOOGLE LOGIN ON USER SAVE', err);
                return res.status(400).json({
                  error: 'User signup failed with google'
                });
              }
              const token = jwt.sign(
                { _id: data._id },
                process.env.JWT_SECRET,
                { expiresIn: '7d' }
              );
              const { _id, email, name, role } = data;
              return res.json({
                token,
                user: { _id, email, name, role }
              });
            });
          }
        });
      } else {
        return res.status(400).json({
          error: 'Google login failed. Try again'
        });
      }
    });
})

// @route   POST api/user/facebooklogin
// @desc    Login user
// @access  Public
router.post('/facebooklogin', (req, res) => {
  console.log('FACEBOOK LOGIN REQ BODY', req.body);
  const { userID, accessToken } = req.body;

  const url = `https://graph.facebook.com/v2.11/${userID}/?fields=id,name,email&access_token=${accessToken}`;

  return (
    fetch(url, {
      method: 'GET'
    })
      .then(response => response.json())
      // .then(response => console.log(response))
      .then(response => {
        const { email, name } = response;
        User.findOne({ email }).exec((err, user) => {
          if (user) {
            const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, {
              expiresIn: '7d'
            });
            const { _id, email, name, role } = user;
            return res.json({
              token,
              user: { _id, email, name, role }
            });
          } else {
            let password = email + process.env.JWT_SECRET;
            user = new User({ name, email, password });
            user.save((err, data) => {
              if (err) {
                console.log('ERROR FACEBOOK LOGIN ON USER SAVE', err);
                return res.status(400).json({
                  error: 'User signup failed with facebook'
                });
              }
              const token = jwt.sign(
                { _id: data._id },
                process.env.JWT_SECRET,
                { expiresIn: '7d' }
              );
              const { _id, email, name, role } = data;
              return res.json({
                token,
                user: { _id, email, name, role }
              });
            });
          }
        });
      })
      .catch(error => {
        res.json({
          error: 'Facebook login failed. Try later'
        });
      })
  );
})

// @route   PUT api/user/forgotpassword
// @desc    Forgot password
// @access  Public
router.put('/forgotpassword',  forgotPasswordValidator, (req, res) => {
    const { email } = req.body;
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        const firstError = errors.array().map(error => error.msg)[0];
        return res.status(422).json({
        errors: firstError
    });
    } else {
        User.findOne({ email }, (err, user) => {
        if (err || !user) {
            return res.status(400).json({
            error: 'User with that email does not exist'
            });
        }

        const token = jwt.sign({
            _id: user._id
          },
          process.env.JWT_RESET_PASSWORD,
          {
            expiresIn: '10m'
          });

        const emailData = {
            from: process.env.EMAIL_FROM,
            to: email,
            subject: `Password Reset link`,
            html: `
                    <h1>Please use the following link to reset your password</h1>
                    <p>${process.env.CLIENT_URL}/users/password/reset/${token}</p>
                    <hr />
                    <p>This email may contain sensetive information</p>
                    <p>${process.env.CLIENT_URL}</p>
                `
        };

        return user.updateOne({
            resetPasswordLink: token }, (err, success) => {
            if (err) {
                console.log('RESET PASSWORD LINK ERROR', err);
                return res.status(400).json({
                error:
                  'Database connection error on user password forgot request'
              });
            } else {
                transporter.sendMail(emailData, (err, data) =>{
                    if(err) return console.log(err)
                    else {
                        res.json({ data,
                            message: `Email has been sent to ${email}. Follow the instruction to activate your account`
                          });
                        //res.json({data})
                    } 
                  })
            }
          }
        );
      }
    );
  }
})

// @route   PUT api/user/resetpassword
// @desc    Forgot password
// @access  Public
router.put('/resetpassword', resetPasswordValidator, (req, res) => {
    const { resetPasswordLink, newPassword } = req.body;

    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        const firstError = errors.array().map(error => error.msg)[0];
        return res.status(422).json({ errors: firstError });
    } else {
        if (resetPasswordLink) {
            jwt.verify(resetPasswordLink, process.env.JWT_RESET_PASSWORD, function( err, decoded) {
            if (err) {
                return res.status(400).json({
                error: 'Expired link. Try again'
            });
        }

        User.findOne({
            resetPasswordLink
        },
          (err, user) => {
            if (err || !user) {
                return res.status(400).json({
                    error: 'Something went wrong. Try later'
                });
            }

            const updatedFields = {
                password: newPassword,
                resetPasswordLink: ''
            };

            user = _.extend(user, updatedFields);

            user.save((err, result) => {
                if (err) {
                    return res.status(400).json({ error: 'Error resetting user password' });
                }
                res.json({ message: `Great! Now you can login with your new password` });
            });
          }
        );
      });
    }
  }
})


module.exports = router