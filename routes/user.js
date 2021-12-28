const express = require('express');
const router = express.Router();
const User = require('../models/User');
const bcryptjs = require('bcryptjs');
const user_jwt=require('../middleware/user_jwt');
const jwt=require('jsonwebtoken');
var slugify = require('slugify');
const { token } = require('morgan');

router.get('/',user_jwt,async (req,res,next) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.status(200).json({
            success:true,
            user:user
        });



    } catch (error) {
        console.log(error.message);
        res.status(500).json({
            success:false,
            msg:'Server error'
        });
        next();
    }
})
/**
 * API : Post 
 * Registration
 */

router.post('/register', async (req, res, next) => {
    const { email, password, firstname, lastname , dob } = req.body;

    try {
        let user_exist = await User.findOne({ email:email });
        if (user_exist) {
            return res.status(400).json({
                success: false,
                msg: 'User already exists'
            });
        }
        let user = new User();
    
        
        user.email = email;
        user.firstname = firstname;
        user.lastname = lastname;
        user.dob = dob;

        const salt = await bcryptjs.genSalt(10);
        user.password= await bcryptjs.hash(password,salt);

        let size = 200;
        user.avatar = "https://gravatar.com/avatar/?s" + size + "&d=retro";
        user.username = slugify(`${firstname} ${lastname}`, {
            replacement:'_',
            lower:true
        });

        await user.save();

        const payload = {
            user:{
                id: user.id
            }
        }

        /**
         * Generating token for newly registered users 
         */
        
         jwt.sign(payload, process.env.jwtUserSecret, {
            expiresIn: 360000
        }, (err, token) => {
            if(err) throw err;
            
            res.status(200).json({
                success: true,
                msg:'User registered',
                token: token
            });
        });



    } catch (error) {
        console.log(error);
        res.status(402).json({
            success: false,
            msg: 'Something error occured'
        })
    }
});

/**
 * API : POST
 *  Login 
 */

router.post('/login',async (req,res,next) => {
    const email = req.body.email;
    const password = req.body.password;

    try {
        let user = await User.findOne({
            email:email
        });

        if(!user){
            return res.status(400).json({
                success:false,
                msg:'User does not exists'
            })
        }
        
        const isMatch = await bcryptjs.compare(password,user.password);

        if(!isMatch){
            return res.status(400).json({
                success:false,
                msg:'Wrong password ! Try again.'
            })
        }

        const payload = {
            user : {
                id:user.id
            }
        }

        jwt.sign(
            payload,process.env.jwtUserSecret,{
                expiresIn:36000 
            }, (error,token) => {
                if(error) throw error;

                res.status(200).json({
                    success:true,
                    msg:'User logged in',
                    token:token,
                    user:user
                });
                
            }
        )
        
    } catch (error) {
        console.log(error.message)
        res.status(500).json({
            success:false,
            msg:'Server error'

        });
    }
})



module.exports = router;