
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const saltRounds = 10;

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");

app.use(bodyParser.urlencoded({ extended: true }));

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
    email: String,
    password: String
});


const User = new mongoose.model("User", userSchema);


app.get("/", function (req, res) {
    res.render("home");
})

app.get("/login", function (req, res) {
    res.render("login");
})

app.post("/login", function (req, res) {
    const userName = req.body.username;
    const password = req.body.password;
    User.findOne({ email: userName }, function (err, foundUser) {
        if (err)
            console.log(err);
        else {
            if (foundUser) {
                if (bcrypt.compareSync(password, foundUser.password))
                    res.render("secrets");
                else
                    res.send("Email and password does not match");
            }
        }
    })
})

app.get("/register", function (req, res) {
    res.render("register");
})

app.post("/register", function (req, res) {
    const userName = req.body.username;
    const password = req.body.password;
    User.findOne({ email: userName }, function (err, foundUser) {
        if (err)
            console.log(err);
        else {
            if (foundUser) {
                if (foundUser.email === userName) {
                    res.send("Email already registered");
                }
            }
            else {
                bcrypt.hash(password, saltRounds, function (err, hash) {

                    const newUser = new User({
                        email: req.body.username,
                        password: hash
                    })
                    newUser.save(function (err) {
                        if (err)
                            console.log(err);
                        else
                            res.render("secrets");
                    })
                })
            }
        }
    })

})

app.listen(3000, function () {
    console.log("Listening on port 3000");
})