const { Router } = require('express')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const config = require('config')
const {check, validationResult} = require('express-validator')
const User = require('../models/User.js')
const router = Router()

router.post(
    '/register', 
    [
        check('email', 'incorrect email').isEmail(),
        check('password', 'min length of password 6 letters').isLength({min:6})
    ],
    async (req, res)=>{
        try{
            const errors = validationResult(req)
            if(!errors.isEmpty()){
                return res.status(400).json({
                    errors: errors.array(),
                    message: 'Incorrect email or password'
                })
            }
            const {email, password} = req.body
            const candidate = await User.findOne({email:email})
            if (candidate){
                return res.status(400).json({message:'This user already exist'})
            }
            const hashedPassword = await bcrypt.hash(password, 12)
            const user = new User({
                email,
                password: hashedPassword,
            })
            await user.save()
            res.status(201).json({message:'User has been created'})
        } catch (e){
            res.status(500).json({message: 'Something went wrong, try again'})
        }
    }
)
router.post(
    '/login',
    [
        check('email', 'incorrect email').normalizeEmail().isEmail(),
        check('password', 'incorrect password').exists()
    ],
    async (req, res)=>{
        try{
            const errors = validationResult(req)
            if(!errors.isEmpty()){
                return res.status(400).json({
                    errors: errors.array(),
                    message: 'Incorrect email or password'
                })
            }
            const {email, password} = req.body
            const user = await User.findOne({email})
            if(!user){
                return res.status(400).json({message: 'User does not exist'})
            }
            const isMatch = await bcrypt.compare(password, user.password)
            if(!isMatch){
                return res.status(400).json({message: 'incorrect password'})
            }
            const token = jwt.sign(
                {userId: user.id},
                config.get('jwtSecret'),
                {expiresIn: '1h'}
            )
            res.json({token, userId: user.id})
        } catch (e){
            res.status(500).json({message: 'Something went wrong, try again'})
        }
    }
)

module.exports = router