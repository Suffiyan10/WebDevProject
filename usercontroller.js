const userModel = require("../models/user");
const bycrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const SECRET_KEY = "greenmamba";

const signup = async (req,res) =>{
   
    const {username, email, password} = req.body;
    try{
        const existingUser = await userModel.findOne({ email:email });

        //If user exists

        if(existingUser){
            return res.status(400).json({message : "User already exists"});
        }

        //Password hash

        const hashedPassword = await bycrypt.hash(password, 10);

        //Creating a new user

        const result = await userModel.create({
            email: email,
            password: hashedPassword,
            username: username
        })

        //Token Generation

        const token = jwt.sign({email : result.email, id : result._id}, SECRET_KEY );
        res.status(201).json({user:result, token:token});

    }
    catch (error){
        console.log("error");
        res.status(500).json({message : "Something is not right!"});

    }
}

const login = async (req,res) =>{

    const {email,password} = req.body;

    try {
        //If user exists

        const existingUser = await userModel.findOne({ email:email });

        if(!existingUser){
            return res.status(404).json({message : "User not found"});
        }

        const matchPassword = await bycrypt.compare(password , existingUser.password);

        if(!matchPassword){
            return res.status(400).json({message : "Invalid credentials"});

        }
        const token = jwt.sign({email : existingUser.email, id : existingUser._id}, SECRET_KEY );
        res.status(201).json({user:existingUser , token:token});

        
    }
    catch (error) {
        console.log("error");
        res.status(500).json({message : "Something is not right!"});
    }

}

module.exports = { signup,login };