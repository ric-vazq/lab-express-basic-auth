const router = require("express").Router();
const User = require("../models/User.model");
const bcrypt = require("bcrypt");
const saltRounds = 12; 

/* GET home page */
router.get("/signup", (req, res, next) => {
  res.render("auth/signup");
});
router.post("/signup", (req, res, next) => {
    const { username, password } = req.body;

    User.findOne({username})
    .then(foundUser => {
        if(foundUser){
            res.render("auth/signup", {error: "Username taken"})
        }
        else {
            bcrypt
                .genSalt(saltRounds)
                .then(salt => bcrypt.hash(password, salt))
                .then(hashedPassword => {
                    return User.create({ username, password: hashedPassword})
                })
                .then(userDB => {
                res.redirect("/profile")
     })
     .catch(err => next(err))
        }
    })
})

module.exports = router;