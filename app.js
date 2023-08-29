//jshint esversion:6
require('dotenv').config();
const express= require("express");
const bodyParser = require("body-parser");
const ejs= require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport= require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate=require("mongoose-findorcreate");
 
 
const app = express();
 
 
app.use(express.static("public"));
app.set('view engine','ejs');
app.use(bodyParser.urlencoded({extended:true}));
 
// 1
app.use(session({                        
    secret: 'Let him cook.',
    resave: false,
    saveUninitialized: false
}));
 
// 2
app.use(passport.initialize());
app.use(passport.session());
 
 
mongoose.connect("mongodb://127.0.0.1:27017/userDB")
    .then(()=> console.log("Connected to userDB."))
    .catch((err)=> console.log(err))
 
 
 
const userSchema = new mongoose.Schema({
    email:String,
    password:String,
    googleId:String,
    secret:String
});
 
// 3 Plugin
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
 
const User = mongoose.model("User",userSchema);
 
// 4 Local strategy (User DB)
passport.use(User.createStrategy());
 
// USER Serialization & De-Serialization
passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    cb(null, { id: user.id, username: user.username});
  });
});
 
passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});
 
 
// Google Oauth2.0 config and Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    // console.log(profile);
    User.findOrCreate({ username:profile.displayName, googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
 
 
app.get("/",function(req,res){
    res.render("home");
});
 
//  This request triggers when user uses the sign up with google on register page
app.get("/auth/google", passport.authenticate('google', { scope: ["profile"] }));
 
 
//  this get req is triggered by google when it completes user authentication
app.get("/auth/google/secrets", passport.authenticate('google', { failureRedirect: "/login" }), function(req, res) {
    // Successful authentication, redirect to secrets page.
    res.redirect('/secrets');
});
 
 
 
app.get("/login",function(req,res){
    res.render("login");
});
 
 
app.get("/register",function(req,res){
    res.render("register");
});
 
 
app.get("/secrets",function(req,res){
    User.find({"secret": {$ne: null}})
        .then(function(foundUsers){
            res.render("secrets", {usersWithSecrets:foundUsers});
        })
        .catch((err)=>{
            console.log(err);
        })
});
 
 
app.get("/submit",function(req,res){
    if(req.isAuthenticated()){
        res.render("submit");
    }
    else{
        res.redirect("/login");
    }
});
 
 
app.post("/submit",function(req,res){
    const submittedSecret= req.body.secret;
 
    User.findById(req.user.id)
        .then(function(founudUser){
            founudUser.secret=submittedSecret;
            founudUser.save()
                .then(()=>{
                    res.redirect("/secrets");
                });
        })
        .catch((err)=>{
            console.log(err);
        })
});
 
app.get("/logout",function(req,res,next){
    req.logout(function(err){
        if(err){
            return next(err);
        }
        res.redirect("/");
    });
});
 
app.post("/register",function(req,res){
    User.register({username:req.body.username}, req.body.password, function(err,user){
        if(err){
            console.log(err);
            res.redirect("/register");
        }
        else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            });
        }
    });
});
 
 
 
app.post("/login",function(req,res){
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
 
    req.login(user,function(err){
        if(err){
            console.log(err);
        }
        else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            });
        }
    });
});
 
 
app.listen(3000,function(){
    console.log("Server started on port 3000.");
});