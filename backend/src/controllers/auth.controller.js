import {generateToken} from "../lib/utils.js";
import User from "../models/user.model.js";
import bcrypt from "bcryptjs";
import cloudinary from "../lib/cloudinary.js";

export const signup = async (req, res)=>{
    const { email, fullName, password } = req.body;
    try{
        if(password.length < 8){
            return res.status(400).json({message: "Password must contain at least 8 characters"});
        }
        const user = await User.findOne({email});
        if (user) return res.status(400).json({message: "User already exists"});
        const salt = await bcrypt.genSalt(10);
        const hashPassword = await bcrypt.hash(password,salt);

        const newUser = new User({
            fullName: fullName,
            email: email,
            password: hashPassword,
        });
        if(newUser){
            generateToken(newUser._id,res);
            await newUser.save();

            res.status(201).json({
                _id:newUser._id,
                fullName: newUser.fullName,
                email:newUser.email,
                profilePic:newUser.profilePic,
            });
        }
        else{
            return res.status(400).json({message:"Invalid user data"});
        }
    }
    catch(error){
        console.log("Error in controller",error.message);
        res.status(500).json({message: "Internal server error"});
    }
};
export const login = async (req, res)=>{
    const {email , password} = req.body;
    try{
        const user = await User.findOne({email});

        if(!user){
           return res.status(400).json({message:"Invalid credentials"});
        }

        const isPasswordCorrect = await bcrypt.compare(password,user.password);

        if(!isPasswordCorrect){
            return res.status(400).json({message:"Invalid credentials"});
        }
        generateToken(user._id,res);
        res.status(200).json({
            id:user._id,
            email:user.email,
            fullName:user.fullName,
            profilePic:user.profilePic,
        });
    }
    catch(error){
        console.log("error in login controller");
        res.status(500).json({message:"Internal server error"});
    }
};
export const logout = (req, res)=>{
    try{
    res.cookie("jwt","",{maxAge:0});
    res.status(200).json({message:"Logged out succesfully"});
    }
    catch(error){
        console.log("error in loging out controller");
        res.status(500).json({message:"Internal server error"});
    }
};
export const updateProfile = async (req,res)=>{
    try {
        const {profilePic} = req.body;
        const userID = req.user._id;

        if(!profilePic){
            return res.status(401).json({message:"Profile pic not found"});
        }

        const uploadResponse = await cloudinary.uploader.upload(profilePic);
        const updateUser = await User.findByIdAndUpdate(
            userID,
            {profilePic: uploadResponse.secure_url},
            {new: true}
        );
        res.status(200).json(updateUser);
    } catch (error) {
        console.log("Error in update Profile");
        return res.status(500).json({message:"Internal server error"});
    }
};
export const checkAuth = (req,res)=>{
    try {
        res.status(200).json(req.user);
    } catch (error) {
        console.log("Error in CheckAuth controller");
        res.status(500).json({message:"Internal server error"});
    }
};