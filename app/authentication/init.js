const async = require('async');
const crypto = require('crypto');
var LocalStrategy   = require('passport-local').Strategy;
var User            = require('../users').user;
var passport        = require('passport');
const logger = require("../config/logger-config");

function initPassport() {
  passport.serializeUser(function(user, done) {
        done(null, user.id);
  });

  // used to deserialize the user
  passport.deserializeUser(function(id, done) {
      User.findById(id, function(err, user) {
          done(err, user);
      });
  });

  ///////////////////////////////////////
  //Local signup strategy (login / password)
  ///////////////////////////////////////

  passport.use('local-signup', new LocalStrategy({
        // by default, local strategy uses username and password, we will override with email
        usernameField : 'email',
        passwordField : 'password',
        passReqToCallback : true // allows us to pass back the entire request to the callback
      },
      function(req, email, password, done) {
        // asynchronous
        // User.findOne wont fire unless data is sent back
        process.nextTick(
          function() {
            User.findOne({ 'email' :  email }, function(err, user) {
              if (err) {
                return done(err);
              }
              // check to see if theres already a user with that email
              if (user) {
                return done(null, false, req.flash('signupMessage', 'Cet email est déjà utilisé.'));
              } else {
                // if there is no user with that email
                // create the user
                var newUser = new User();
                newUser.email = email;
                newUser.local.password = newUser.generateHash(password);

                if (req.body.userType == 'free') {

                } else if (req.body.userType == 'member') {
                    newUser.member = true;
                } else if (req.body.userType == 'admin') {
                    newUser.admin = true;
                } else if (req.body.userType == 'corporate') {
                    newUser.corporate = true;
                }
                // save the user
                newUser.save(function(err) {
                  if (err)
                    throw err;
                  return done(null, newUser);
                });
              }
            });
          });
  }));

  ///////////////////////////////////////
  //Local signin strategy (login / password)
  ///////////////////////////////////////

  passport.use('local-login', new LocalStrategy({
        // by default, local strategy uses username and password, we will override with email
        usernameField : 'email',
        passwordField : 'password',
        passReqToCallback : true // allows us to pass back the entire request to the callback
    },
    function(req, email, password, done) { // callback with email and password from our form
        // find a user whose email is the same as the forms email
        // we are checking to see if the user trying to login already exists
        User.findOne({ 'email' :  email }, function(err, user) {
            // if there are any errors, return the error before anything else
            if (err)
                return done(err);
            // if no user is found, return the message
            if (!user)
                return done(null, false, req.flash('loginMessage', 'Utilisateur inconnu.')); // req.flash is the way to set flashdata using connect-flash

            // if the user is found but the password is wrong
            if (!user.validPassword(password))
                return done(null, false, req.flash('loginMessage', 'Mauvais mot de passe.')); // create the loginMessage and save it to session as flashdata

            // all is well, return successful user
            return done(null, user);
        });
    }));
}

function initAuthenticationRoute(app) {
  function loggedUserRoute(err, user, info) {
    if (err) {
      return next(err);
    }

    if (!user) {
      return res.redirect('/login');
    }
  }

  app.post('/login', passport.authenticate('local-login', {
        successRedirect : '/home', // redirect to the secure profile section
        failureRedirect : '/', // redirect back to the signup page if there is an error
        failureFlash : true // allow flash messages
  }));


  app.get('/signup', function(req, res) {
        // render the page and pass in any flash data if it exists
        res.render('views/authentication/signup', { message: req.flash('signupMessage') });
  });

  app.post('/signup', passport.authenticate('local-signup', {
        successRedirect : '/home', // redirect to the secure profile section.
        failureRedirect : '/signup', // redirect back to the signup page if there is an error
        failureFlash : true // allow flash messages
    }));

  app.get('/logout', function(req, res) {
    req.logout();
    res.redirect('/');
  });

  app.post('/forgot', function(req, res) {
      var email = req.body.email;
      logger.debug('Forgot email:' + email);

      async.waterfall([
        function(done) { //Check if an email is passed
          logger.debug('Test if email exist');
          if (!email || email === '') {
            req.flash('loginMessage', 'Veuillez renseigner votre email.');
            return res.redirect('/');
          }
          done();
        },
        function(done) { //generating a hash key
          logger.debug('Generate Crypto token');
          crypto.randomBytes(20, function(err, buf) {
            var token = buf.toString('hex');
            done(err, token);
          });
        },
        function(token, done) { //Update user with token
          logger.debug('Get the user and update token');
          User.findOne({ email: email }, function(err, user) {
            if (!user) {
              logger.debug('User not found');
              req.flash('loginMessage', 'Aucun utilisateur avec cet email');
              return res.redirect('/');
            }
            user.resetToken.resetPasswordToken = token;
            user.resetToken.resetPasswordExpires = Date.now() + 3600000; // 1 hour
            user.save(function(err) {
              done(err, token, user);
            });
          });
        },
        function(token, user, done) {
          logger.debug('Send email');
          app.mailer.send('views/mails/mail-reset-password', {
            to: 'charles.rathouis@gmail.com', //TODO: user mails
            subject:'Orthogym : réinitialisation du mot de passe',
            host:req.headers.host,
            token:token,
            email:email
          }, function (err, message) {
            if (err) {
              // handle error
              logger.error('Error sending email' + err);
            }
            done(err, 'done');
          });
        }
      ],
      function(err) {
        if (err) {
          req.flash('loginMessage', 'Une erreur est survenur' + err);
        } else {
          req.flash('loginMessage', 'Un email vous a été envoyé');
        }
        return res.redirect("/");
      })
  });

  //Loggin action, define different rendering depending of the profile of user
  app.get('/home', isLoggedIn, function(req, res) {
    if (req.user.member) {
      res.render('views/welcome/welcome-logged-member', {
          user : req.user // get the user out of session and pass to template
      });
    } else if (req.user.admin) {
      res.render('views/welcome/welcome-logged-admin', {
          user : req.user // get the user out of session and pass to template
      });
    } else if (req.user.corporate) {
      res.render('views/welcome/welcome-logged-corporate', {
          user : req.user // get the user out of session and pass to template
      });
    } else {
      res.render('views/welcome/welcome-logged-free', {
          user : req.user // get the user out of session and pass to template
      });
    }
  });
}
// route middleware to make sure a user is logged as free user
function isLoggedIn(req, res, next) {
    // if user is authenticated in the session, carry on
    if (req.isAuthenticated())
        return next();

    // if they aren't redirect them to the home page
    res.redirect('/');
}

function initAuthentication(app) {
  initAuthenticationRoute(app);
  initPassport();
}

module.exports = initAuthentication
