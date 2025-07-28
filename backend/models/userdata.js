const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    name:{
        type:String,
        require:true,
        maxlength:50,
        trim:true
    },

    email:{
        type:String,
        require:true,
        trim:true,
        unique:true
    },

    mobile:{
        type:Number,
        require:true,
        maxlength:10
    },

    password:{
        type:String,
        require:true
    },

    profileImage: {
        type: String, // base64 encoded image string
        required: false
      },
      resetToken: {
        type: String,
        default : ""
      },
    tokenExpiration: {
        type :Date,
    } 
})

module.exports = mongoose.model('User', userSchema);