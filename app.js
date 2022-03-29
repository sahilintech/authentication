require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");

app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
    secret: "Our little secret",
    resave: false,
    saveUninitialized: false,

}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: Array
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, cb) {
    process.nextTick(function () {
        cb(null, { id: user.id, username: user.username });
    });
});

passport.deserializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
}, function (accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
    });
}));

app.get("/auth/google", passport.authenticate("google", { scope: ["profile"] })
);

app.get("/auth/google/secrets", passport.authenticate("google", { failureRedirect: "/login" }), function (req, res) {
    res.redirect("/secrets");
})

app.get("/", function (req, res) {
    res.render("home");
})

app.get("/login", function (req, res) {
    res.render("login");
})

app.post("/login", function (req, res) {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    })
    req.login(user, function (err) {
        if (err)
            console.log(err);
        else
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            })
    })
})

app.get("/register", function (req, res) {
    res.render("register");
})

app.get("/secrets", function (req, res) {
    User.find({ secret: { $ne: null } }, function (err, foundItems) {
        console.log(foundItems);
        res.render("secrets", { secrets: foundItems });
    })
})

app.post("/register", function (req, res) {
    User.register({ username: req.body.username }, req.body.password, function (err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register");
        }
        else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            })
        }
    })
})

app.get("/logout", function (req, res) {
    req.logout();
    res.redirect("/");
})

app.get("/submit", function (req, res) {
    if (req.isAuthenticated)
        res.render("submit");
    else
        res.redirect("/login");
})

var i =0;

app.post("/submit", function (req, res) {
    const submittedSecret = req.body.secret;
    User.findById(req.user.id, function (err, foundUser) {
        if (err) {
            console.log(err);
        }
        else {
            if (foundUser) {
                foundUser.secret = submittedSecret;
            };
            foundUser.save(function () {
                res.redirect("/secrets");
            });
        }
    })
})

app.listen(3000, function () {
    console.log("Listening on port 3000");
})