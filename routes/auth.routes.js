const router = require("express").Router();
const User = require("../models/User.model");
const bcrypt = require("bcrypt");
const saltRounds = 12; 
const { isLoggedIn, isLoggedOut } = require('../middleware/route-guard');

/* GET home page */
router.get("/signup", isLoggedOut, (req, res, next) => {
  res.render("auth/signup");
});

router.post("/signup", isLoggedOut, (req, res, next) => {
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
});

router.get("/login", isLoggedOut, (req, res, next) => {
    res.render("auth/login")
});

router.post("/login", isLoggedOut, (req, res, next) => {
    console.log('SESSION =====> ', req.session);
    const { username, password } = req.body; 

    if (username === '' || password === ''){
        res.render('auth/login', {error: 'Please enter both, username and passord to login'});
        return; 
    }

    User.findOne({ username })
    .then(user => {
        if (!user){
            res.render('auth/login', {error: 'User not found and/or incorrect password'})
            return
        } else if (bcrypt.compare(password, user.password)){
            req.session.currentUser = user;
            res.redirect('/profile')
        } else {
            res.render('auth/login', {error: 'User not found and/or incorrect password'})
        }
    })
    .catch(err => next(err));
});
router.get("/profile", isLoggedIn, (req, res, next) => {
    res.render('user/profile', { userInSession: req.session.currentUser })
});
router.post('/logout', isLoggedIn, (req, res, next) => {
    req.session.destroy(err => {
        if (err) next(err);
        res.redirect('/')
    })
})

module.exports = router;
