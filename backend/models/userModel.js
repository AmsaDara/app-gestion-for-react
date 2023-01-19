const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const userSchema = mongoose.Schema({
    name: {
        type: String,
        required: [true, "SVP entrer votre nom"]
    },
    email: {
        type: String,
        required:[true, "SVP entrer votre email"],
        unique: true,
        trim: true,
        match: [
            /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
            "SVP entrer un email valide"
        ]
    },
    password: {
        type: String,
        required: [true, "SVP entrer un mot de passe"],
        minLength: [6, "le mot de passe doit comporter jusqu'à 6 caractères"],
        //maxLength: [23, "le mot de passe ne doit pas dépasser 23 caractères"]
    },
    photo: {
        type: String,
        required: [true, "SVP entrer une photo"],
        default: "https://i.ibb.co/4pDNDk1/avatar.png"
    },
    phone: {
        type: String,
        default: "+221 00 000 00 00"
    },
    bio: {
        type: String,
        maxLength: [250, "la biographie ne doit pas dépasser 250 caractères"],
        default: "bio"
    }
}, 

{
    timestamps: true,
}
);

// Encrypt password before saving to DB
userSchema.pre("save", async function(next) {
    if(!this.isModified("password")) {
        return next();
    }
    
    
    //hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(this.password, salt);
    this.password = hashedPassword;
    next();
})

const User = mongoose.model("User", userSchema)
module.exports = User