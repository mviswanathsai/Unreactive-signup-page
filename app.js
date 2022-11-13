
require('dotenv').config();

const express = require("express");
const mongoose = require("mongoose");
const ejs = require("ejs");
const bodyParser = require("body-parser");


const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

const GoogleStrategy = require('passport-google-oauth20').Strategy;
var GitHubStrategy = require('passport-github2').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(express.static("public"));

app.use(session({
  secret: "Our little secret in a big secret.",
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());



mongoose.connect("mongodb://localhost:27017/authenticationDB", {
  useNewUrlParser: true
});

const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  googleId: String,
  facebookId: String,
  githubId: String
})

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const user = mongoose.model("User", userSchema);

passport.use(user.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});
passport.deserializeUser(function(id, done) {
  user.findById(id, function(err, foundUser) {
    done(err, user);
  })
});

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileUrl: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    user.findOrCreate({
      googleId: profile.id
    }, function(err, user) {
      return cb(err, user);
    });
  }
));



passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({
      facebookId: profile.id
    }, function(err, user) {
      return cb(err, user);
    });
  }
));



passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_APP_ID,
    clientSecret: process.env.GITHUB_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/github/secrets"
  },
  function(accessToken, refreshToken, profile, done) {
    User.findOrCreate({
      githubId: profile.id
    }, function(err, user) {
      return done(err, user);
    });
  }
));

app.get("/", (req, res) => {
  res.render("index");
})

app.get("/authenticated", (req,res)=>{

  if(req.isAuthenticated()){
    res.render("authenticated");
  }
  else{
    res.redirect("/");
  }

})

app.post("/signup", (req, res) => {
  user.register({
    username: req.body.username
  }, req.body.password, function(err, user) {
    if (!err) {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/authenticated");
      })
    } else {
      console.log(err);
      res.redirect("/signup");
    }
  });
})

app.get("/signin", (req,res)=>{
  res.render("login");
})

app.post("/signin", (req,res)=>{

    const newUser = new user({
      username: req.body.username,
      password: req.body.password
    });

    req.login(newUser, function(err) {
      if (!err) {
        passport.authenticate("local")(req, res, function(err) {
          if (!err) {
            res.redirect("/authenticated");
          } else {
            res.redirect("/signin");
          }
        })
      } else {
        res.redirect("/signin");
        console.log(err);
      }
    })

})



app.get("/signout", (req, res) => {
  req.logout(function(err) {
    if (!err) {
      res.redirect("/")
    } else {
      console.log(err);
    }
  });

})



//Google OAuth

app.get("/auth/google",
    passport.authenticate("google", {
      scope: ["profile"]
    }));

app.get("/auth/google/secrets", passport.authenticate("google", {
        failureRedirect: "/"
      }), (req, res) => {
        res.redirect("/authenticated");
      })




//Facebook OAuth

app.get('/auth/facebook',
  passport.authenticate('facebook'));

 app.get("/auth/facebook/secrets", passport.authenticate("facebook", {
   failureRedirect: "/"
 }), (req,res)=>{
   res.redirect("/authenticated");
 })





//Github OAuth

app.get('/auth/github',
  passport.authenticate('github', {
    scope: ['user:email']
  }));

app.get("/auth/github/secrets", passport.authenticate("github", {failureRedirect: "/"}), (req,res)=>{
  res.redirect("/authenticated");
})


app.post("/signup", (req,res)=>{

  user.register({username: req.body.username}, req.body.password, function(err, user){
   if (err) {
     console.log(err);
     res.redirect("/");
   } else {
     passport.authenticate("local")(req, res, function(){
       res.redirect("/authenticated");
     });
   }
 });

})




app.listen(3000, () => {
  console.log("we are ready to go");
})
