const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const Token = require("../models/tokenModel");
const crypto = require("crypto");
const { url } = require("inspector");

    const generateToken = (id) => {
        return jwt.sign({ id }, process.env.JWT_SECRET, {expiresIn: "1d"})
    };
    
    //Register User
    const registerUser = asyncHandler( async (req,res) => {
    const {name, email, password} = req.body;
    
    // validation
    if (!name || !email || !password) {
        res.status(400)
        throw new Error("Veuillez remplir tous les champs requis")
    }
    if (password.length < 6) {
        res.status(400)
        throw new Error("Mot de passe doit être au moins 6 caractères")
    }
    
    // chek if user email already exists
    const userExists = await User.findOne({email});
    
    if (userExists) {
        res.status(400)
        throw new Error("l'e-mail a déjà été enregistré")
    }
    
    // create new user
    const user = await User.create({
        name,
        email,
        password,
    });
    
    //generate token
    const token = generateToken(user._id);
    
    // Send HTTP-only cookie
    res.cookie("token", token, {
        path: "/",
        httpOnly: true,
        expires: new Date(Date.now() + 1000 * 86400), //1 jour
        sameSite: "none",
        secure: true
    });
    
    if (user) {
        const {_id, name, email, photo, phone, bio} = user;
        res.status(201).json({
            _id, name, email, photo, phone, bio, token,
        })
    } else {
        res.status(400)
        throw new Error("données utilisateur invalides")
    }
    
});

 // login user
 const loginUser = asyncHandler ( async (req, res) => {
     
     const { email,password } = req.body;
     
     //Validate request
     if(!email || !password) {
        res.status(400);
        throw new Error("veuillez ajouter un email et un mot de passe");
     }
     
     //check if user exists 
     const user = await User.findOne({email})
     
     if(!user) {
        res.status(400);
        throw new Error("utilisateur introuvable, veuillez vous inscrire");
     }
     
     //User exists, check if password is correct
     const passwordIsCorrect = await bcrypt.compare(password, user.password);
     
     //generate token
    const token = generateToken(user._id);
    
    // Send HTTP-only cookie
    res.cookie("token", token, {
        path: "/",
        httpOnly: true,
        expires: new Date(Date.now() + 1000 * 86400), //1 jour
        sameSite: "none",
        secure: true
    });
     
     if (user && passwordIsCorrect) {
        const {_id, name, email, photo, phone, bio} = user;
        res.status(200).json({
            _id, name, email, photo, phone, bio, token,
        })
     } else {
        res.status(400);
        throw new Error("email ou mot de passe invalide");
     }
     
 });
 
   //Logout User
   const logout = asyncHandler(async (req, res) => {
        res.cookie("token", "", {
            path: "/",
            httpOnly: true,
            expires: new Date(0),
            sameSite: "none",
            secure: true
        });
        return res.status(200).json({ message: "Deconnexion avec succès" })
   });
   
   //Get User Data
   const getUser = asyncHandler (async (req, res) => {
       const user = await User.findById(req.user._id);
       
       if (user) {
        const {_id, name, email, photo, phone, bio} = user;
        res.status(200).json({
            _id, name, email, photo, phone, bio,
        })
    } else {
        res.status(400)
        throw new Error("Utilisateur introuvable");
    }
   })
   
   // Get Login Status
   const loginStatus = asyncHandler (async (req,res) => {
       const token = req.cookies.token;
       if (!token) {
            return res.json(false)
       }
       
       // Verify token
       const verified = jwt.verify(token, process.env.JWT_SECRET);
       if (verified) {
         return res.json(true);
       }
       return res.json(false);
       
   });
   
   // Update User
   const updateUser = asyncHandler (async (req, res) => {
       const user = await User.findById(req.user._id);
       
       if (user) {
        const { name, email, photo, phone, bio} = user;
        user.email = email;
        user.name = req.body.name || name;
        user.phone = req.body.phone || phone;
        user.photo = req.body.photo || photo;
        user.bio = req.body.bio || bio;
        
        const updateUser = await user.save()
        res.status(200).json({
            _id: updateUser._id, 
            name: updateUser.name, 
            email: updateUser.email, 
            photo: updateUser.photo, 
            phone: updateUser.phone, 
            bio: updateUser.bio,
        })
        
       }else {
           res.status(404)
           throw new Error("utilisateur non trouvé");
       }
   });
   
    const changepassword = asyncHandler (async (req, res)=> {
        const user = await User.findById(req.user._id);
        const {oldPassword, password} = req.body;
        
        if(!user) {
            res.status(400)
           throw new Error("Utilisateur introuvable, veuillez vous inscrire");
        }
        
        //Validate
        if(!oldPassword || !password) {
            res.status(400)
           throw new Error("veuillez ajouter l'ancien et le nouveau mot de passe");
        }
    
        //check if old password matches password in DB
        const passwordIsCorrect = await bcrypt.compare(oldPassword,user.password)
        
        //Save new password
        if (user && passwordIsCorrect) {
            user.password = password 
            await user.save() 
            res.status(200).send("changement de mot de passe réussi")
        } else {
            res.status(400);
            throw new Error("Ancien mot de passe est incorrect")
        }
    
   });
    
    const forgotpassword = asyncHandler (async (req, res) => {
        const {email} = req.body
        const user = await User.findOne({email})
        
        if (!user) {
            res.status(404)
            throw new Error("L'utilisateur n'existe pas")
        }
        
        //create reste token
        let resetToken = crypto.randomBytes(32).toString("hex") + user._id ;
        
        //Hash token before saving to DB
        const hashedToken = crypto
            .createHash("sha256")
            .update(resetToken)
            .digest("hex");
        
        // save token to DB
        await new Token({
            userId: user._id,
            token: hashedToken,
            createAt : Date.now(),
            expiresAt: Date.now() + 30 * (60 * 1000) // Thirty minutes
        }).save()
        
        //construct reset url
        const resetUrl = `${process.env.FRONTEND_URL}/
        resetpassword/${resetToken}`
        
        //Reset Email 
        const message = `
            <h2>Salut ${user.name}</h2>
            <p>Veuillez utiliser l'url ci-dessous pour réinitialiser votre mot de passe</p>
            <p>Ce lien de réinitialisation n'est valable que 30 minutes</p>
            <a href=${resetUrl} clicktracking=off>${resetUrl}</a> <br>
            <p>Cordialement</p>
            
        
        `
        
        res.send("Forgot Password");
        
    });

module.exports = {
    registerUser,
    loginUser,
    logout,
    getUser,
    loginStatus,
    updateUser,
    changepassword,
    forgotpassword,
};