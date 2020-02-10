const mongoose    = require('mongoose');                   // require mongoose
const session     = require("express-session");          // require session
const MongoStore  = require("connect-mongo")(session);   // require mongostore
const bcrypt      = require('bcrypt');

const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

// User model
const User = require('../models/user');

passport.serializeUser((user, callback) => {
  callback(null, user._id);
});

passport.deserializeUser((id, callback) => {
  User.findById(id)
    .then(user => {
      callback(null, user);
    })
    .catch(error => {
      callback(error);
    });
});

module.exports = app => {
  app.use(session({
    secret: process.env.SECRET,                         // reading from .env the SECRET variable
    //cookie: { maxAge: 60 * 1000 },                    // 60 seconds
    store: new MongoStore({
    mongooseConnection: mongoose.connection,
    resave: true,
    saveUninitialized: false,
    ttl: 24 * 60 * 60 // 1 day
    })
  }));

  passport.use(
    new LocalStrategy((username, password, callback) => {
      User.findOne({ username })
        .then(user => {
          if (!user) {
            return callback(null, false, { message: 'Incorrect username' });
          }
          if (!bcrypt.compareSync(password, user.password)) {
            return callback(null, false, { message: 'Incorrect password' });
          }
          callback(null, user);
        })
        .catch(error => {
          callback(error);
        });
    })
  );

}