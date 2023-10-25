const express = require("express");
const app = express();
const jwt = require('jsonwebtoken')
app.use(express.json())


const JWT_SECRET = "Hardikisagoodb$oy"
const JWT_SECRET_REFRESH = "Hardikisbadb$oy"

const users = [
    {
        id: "1",
        username: "john",
        password: "John0908",
        isAdmin: true,
    },
    {
        id: "2",
        username: "jane",
        password: "Jane0908",
        isAdmin: false,
    }
];

let refreshTokens = []

app.post("/api/refresh", (req, res) => {
    // Take the refresh token from the user
    const refreshToken = req.body.token

    //send error if there is no token or it's invalid
    if(!refreshToken) return res.status(401).json("You are not authenticated");
    if(!refreshTokens.includes(refreshToken)){
        return res.status(403).json("Refresh token is not valid!")
    }
    jwt.verify(refreshToken, JWT_SECRET_REFRESH, (err, user) => {
        err & console.log(err);
        refreshTokens = refreshTokens.filter((token) => token !== refreshToken);

        const newAccessToken = jwt.sign({id: user.id, isAdmin: user.isAdmin}, JWT_SECRET, {expiresIn: "300s"})
        const newRefreshToken = jwt.sign({id: user.id, isAdmin: user.isAdmin}, JWT_SECRET_REFRESH)

        refreshTokens.push(newRefreshToken)

        res.status(200).json({
            accessToken: newAccessToken,
            refreshToken: newRefreshToken
        })
    })

    // if everthing is ok, create a new access token, refresh token and send to user
})

app.post("/api/login", (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => {
       return u.username === username && u.password === password;
    });
    if(user){
        // Generate an access token
        const accessToken = jwt.sign({id: user.id, isAdmin: user.isAdmin}, JWT_SECRET, {expiresIn: "300s"})
        const refreshToken = jwt.sign({id: user.id, isAdmin: user.isAdmin}, JWT_SECRET_REFRESH)
        refreshTokens.push(refreshToken)
        res.json({
            username: user.username,
            isAdmin: user.isAdmin,
            accessToken,
            refreshToken
        })
    }else{
        res.status(400).json("Invalid credentials!")
    }
});

const verify = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if(authHeader){
        const token = authHeader.split(" ")[1];
        jwt.verify(token, JWT_SECRET, (err, user) => {
            if(err){
                return res.status(403).json("Token is not valid!")
            }
            req.user = user;
            next();
        })
    }else{
        res.status(401).json("You are not authenticated")
    }
}

app.delete("/api/users/:userId", verify, (req, res) => {
    if(req.user.isAdmin || req.user.id === req.params.userId){
        res.status(200).json("User has been deleted.")
    }else{
        res.status(403).json("You're not allowed to delete this user!")
    }
})

app.post("/api/logout", verify, (req, res) => {
    const refreshToken = req.body.token;
    refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
    res.status(200).json("You logged out successfully");

})

app.listen(5001, () => console.log("Backend server is running"));