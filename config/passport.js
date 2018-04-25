const LocalStrategy = require('passport-local').Strategy;
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');


//Load user model
const User = mongoose.model('users');


module.exports = function(passport){
  //local strategy, serialize, de-serialize
  //define local strategy
  passport.use(new LocalStrategy({usernameField : 'email'}, (email, password, done) => {
  //check user
  User.findOne(
    {
      email:email
    }
  )
  .then( user => {
      if(!user){
        return done(null, false, {message: 'No user found'}); //param 1 : error, param 2 : user (false cause no user,), param 3 : massage
      }
      //Match password
      bcrypt.compare(password, user.password, (err, isMatch) => {
        if(err) throw err;
        if(isMatch){
          return done(null, user);
        }else{
          return done(null, false, {message: 'Password Incorrect'});
        }
      });
    })
  }));

  passport.serializeUser(function(user, done) {
  done(null, user.id);
  });

  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) { //findById is mongoose
      done(err, user);
    });
  });
}
