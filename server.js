// Requiring packages and libraries
const express = require("express");
const cookieParser = require("cookie-parser");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");

dotenv.config();

const app = express();

// We don't need body-parser
// Expressversion 4.16+ have its own body-parser
app.use(express.json());
app.use(express.urlencoded());

app.set("view engine", "ejs");

app.use(cookieParser());

// Connecting to database
mongoose.connect(process.env.DB_CONNECT);

// Mongoose model
const userSchema = new mongoose.Schema({
    email: {
        type: String,
        unique: true,
        required: true
    },
    password: {
        type: String,
        required: true
    }
});

const User = mongoose.model("User", userSchema);



app.get("/", function(req, res) {
    res.render("home");
});

app.get("/signup", function(req, res) {
    res.render("signup");
});

app.get("/login", (req, res) => {
    res.render("login");
});

app.post("/signup", async (req, res) => {
    console.log(req.body);
    const {email, password} = req.body;
    // Checking if both fields are filled before submitting
    if(!(email && password)) {
        return res.status(400).send({error: "Please input both fields!"});
    }
    // Checking if email already exists
    // We can use only ({email}) instead of ({email: email})
    const emailExist = await User.findOne({email:email});
    if(emailExist) {
        return res.status(400).send("User already exists!");
    }
    // Generating salt
    const salt = await bcrypt.genSalt(10);
    // Hashing password
    const hashedPassword = await bcrypt.hash(password, salt);
    //Creating User
    const user = await User.create({
        email: email.toLowerCase(),
        password: hashedPassword
    });
    // To check if user is save, we can use code below 
    //res.json({id: user._id, email: email});
    res.redirect("login");
});



app.post("/login", async (req, res) => {
    const {email, password} = req.body;
    // Checking if email matches to the database
    const user = await User.findOne({email});
    if(!user) {
        return res.status(400).send("User not found!");
    }
    // Comparing password to the database
    const validPasssword = await bcrypt.compare(password, user.password);
    if(!validPasssword) {
        return res.status(400).send("Invalid Password!");
    }
    // Generating accesstoken
    const accessToken =  jwt.sign({id: user._id, email: user.email}, process.env.ACCESS_KEY, {expiresIn: '15s'});
    // Generating refreshtoken
    const refreshToken = jwt.sign({id: user._id, email: user.email}, process.env.REFRESH_KEY, {expiresIn: '1d'});
    // Sending refreshtoken as cookie
    res.cookie('jwt', refreshToken, {
        httpOnly: true,
        sameSite: 'None',
        secure: true,
        maxAge: 24*60*60*1000
    });
    // For checking if tokens are working
    //res.json({accessToken: accessToken, refreshToken: refreshToken});
    res.redirect("secret");
});

// Middleware for authorization
const authorization =  (req, res, next) => {
    const refreshToken = req.cookies.jwt;
    if(refreshToken) {
        jwt.verify(refreshToken, process.env.REFRESH_KEY, (err, user) => {
            if(err) {
                return res.status(406).json({message: "Unauthorized"});
            }
            else {
                const accessToken = jwt.sign({id: user._id, email: user.email}, process.env.ACCESS_KEY, {expiresIn: '15s'});
                //return res.json({accessToken});
                return next();
            }
        });
    }
    else {
        return res.status(406).json({message: 'Unauthorized'});
    }
}

app.get("/secret", authorization, (req, res) => {
    res.render("secret");
});

app.get("/logout", (req, res) => {
    return res.clearCookie("jwt").status(200).redirect("login");
})

// Can use => {} instead of function() {}
app.listen(3000, function() {
    console.log("Listening to port 3000...");
});