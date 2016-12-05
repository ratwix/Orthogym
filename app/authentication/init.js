const async = require('async');
const crypto = require('crypto');
const logger = require("../config/logger-config");
const configAuth = require('../config/auth-config');
var LocalStrategy   = require('passport-local').Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;
var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
var User            = require('../users').user;
var passport        = require('passport');


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
                return done(null, false, req.flash('signupMessageError', 'Cet email est déjà utilisé.'));
              } else {
                // if there is no user with that email
                // create the user
                var newUser = new User();
                newUser.email = email;
                newUser.local.password = newUser.generateHash(password);

                if (req.body.userType == 'free') {

                } else if (req.body.userType == 'member') {
                    newUser.role.member = true;
                } else if (req.body.userType == 'admin') {
                    newUser.role.admin = true;
                } else if (req.body.userType == 'corporate') {
                    newUser.role.corporate = true;
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
                return done(null, false, req.flash('loginMessageError', 'Utilisateur inconnu.')); // req.flash is the way to set flashdata using connect-flash

            // if the user is found but the password is wrong
            if (!user.validPassword(password))
                return done(null, false, req.flash('loginMessageError', 'Mauvais mot de passe.')); // create the loginMessage and save it to session as flashdata

            // all is well, return successful user
            return done(null, user);
        });
    }));
}

///////////////////////////////////////
// Facebook login
///////////////////////////////////////

passport.use(new FacebookStrategy({
        // pull in our app id and secret from our auth.js file
        clientID        : configAuth.facebookAuth.clientID,
        clientSecret    : configAuth.facebookAuth.clientSecret,
        callbackURL     : configAuth.facebookAuth.callbackURL,
        profileFields: ['id', 'displayName', 'emails', 'name']
    },
    // facebook will send back the token and profile
    function(token, refreshToken, profile, done) {
      // asynchronous
      process.nextTick(function() {
        // find the user in the database based on their facebook id
          logger.debug("Authentifié avec Facebook recherche d'un element dans la base");
          User.findOne({ 'facebook.id' : profile.id }, function(err, user) {
            // if there is an error, stop everything and return that
            // ie an error connecting to the database
            if (err)
                return done(err);
            // if the user is found, then log them in
            if (user) {
                logger.debug("Pas de user avec cet id dans la base");
                return done(null, user); // user found, return that user
            } else {
                // if there is no user found with that facebook id, check if a user with the same email already exists
                logger.debug("Recherche d'un user avec l'email " + profile.emails[0].value);
                var mail = profile.emails[0].value;
                User.findOne({'email' : mail}, function(err, user_mail) {
                  if (err)
                    return done(err);
                    //a user exist with the facebook email. Attach the facebook id to this email
                  if (user_mail) {
                    logger.debug("Il y a un user avec cet email : mise a jour");
                    user_mail.facebook.id = profile.id;
                    user_mail.facebook.token = token;
                    user_mail.facebook.name = profile.name.givenName + ' ' + profile.name.familyName;
                    user_mail.save(function(err) {
                        if (err)
                            throw err;
                        // if successful, return the new user
                        return done(null, user_mail);
                    });
                  } else { //no user found. Create a new user
                    logger.debug("Creation d'un nouvel user");
                    var newUser            = new User();
                    // set all of the facebook information in our user model
                    newUser.facebook.id    = profile.id; // set the users facebook id
                    newUser.facebook.token = token; // we will save the token that facebook provides to the user
                    newUser.facebook.name  = profile.name.givenName + ' ' + profile.name.familyName; // look at the passport user profile to see how names are returned
                    newUser.email = profile.emails[0].value; // facebook can return multiple emails so we'll take the first
                    // save our user to the database
                    newUser.save(function(err) {
                        if (err)
                            throw err;
                        // if successful, return the new user
                        return done(err, newUser);
                    });
                  }
                });
            }
          });
      });
  }));

  ///////////////////////////////////////
  // Google login
  ///////////////////////////////////////

  passport.use(new GoogleStrategy({
          // pull in our app id and secret from our auth.js file
          clientID        : configAuth.googleAuth.clientID,
          clientSecret    : configAuth.googleAuth.clientSecret,
          callbackURL     : configAuth.googleAuth.callbackURL,
      },
      // facebook will send back the token and profile
      function(token, refreshToken, profile, done) {
        // asynchronous
        process.nextTick(function() {
          // find the user in the database based on their facebook id
            logger.debug("Authentifié avec Google  recherche d'un element dans la base");
            User.findOne({ 'google.id' : profile.id }, function(err, user) {
              // if there is an error, stop everything and return that
              // ie an error connecting to the database
              if (err)
                  return done(err);
              // if the user is found, then log them in
              if (user) {
                  logger.debug("Pas de user avec cet id dans la base");
                  return done(null, user); // user found, return that user
              } else {
                  // if there is no user found with that facebook id, check if a user with the same email already exists
                  logger.debug("Recherche d'un user avec l'email " + profile.emails[0].value);
                  var mail = profile.emails[0].value;
                  User.findOne({'email' : mail}, function(err, user_mail) {
                    if (err)
                      return done(err);
                      //a user exist with the google email. Attach the facebook id to this email
                    if (user_mail) {
                      logger.debug("Il y a un user avec cet email : mise a jour");
                      user_mail.google.id = profile.id;
                      user_mail.google.token = token;
                      user_mail.google.name = profile.displayName;
                      user_mail.save(function(err) {
                          if (err)
                              throw err;
                          // if successful, return the new user
                          return done(null, user_mail);
                      });
                    } else { //no user found. Create a new user
                      logger.debug("Creation d'un nouvel user");
                      var newUser            = new User();
                      // set all of the facebook information in our user model
                      newUser.google.id    = profile.id; // set the users google id
                      newUser.google.token = token; // we will save the token that facebook provides to the user
                      newUser.google.name  = profile.displayName; // look at the passport user profile to see how names are returned
                      newUser.email = profile.emails[0].value; // facebook can return multiple emails so we'll take the first
                      // save our user to the database
                      newUser.save(function(err) {
                          if (err)
                              throw err;
                          // if successful, return the new user
                          return done(err, newUser);
                      });
                    }
                  });
              }
            });
        });
    }));

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
        res.render('views/authentication/signup', { message_error: req.flash('signupMessageError') });
  });

  app.post('/signup', passport.authenticate('local-signup', {
        successRedirect : '/home', // redirect to the secure profile section.
        failureRedirect : '/signup', // redirect back to the signup page if there is an error
        failureFlash : true // allow flash messages
    }));

  app.get('/auth/facebook', passport.authenticate('facebook', { scope : 'email' }));

  app.get('/auth/facebook/callback',
          passport.authenticate('facebook', {
              successRedirect : '/home',
              failureRedirect : '/'
  }));

  app.get('/auth/google', passport.authenticate('google', { scope : ['profile', 'email'] }));

  // the callback after google has authenticated the user
  app.get('/auth/google/callback',
          passport.authenticate('google', {
                  successRedirect : '/home',
                  failureRedirect : '/'
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
            req.flash('loginMessageError', 'Veuillez renseigner votre email.');
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
              req.flash('loginMessageError', 'Aucun utilisateur avec cet email');
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
          req.flash('loginMessageError', 'Une erreur est survenur' + err);
        } else {
          req.flash('loginMessageSuccess', 'Un email vous a été envoyé');
        }
        return res.redirect("/");
      })
  });

  //Reset token checking
  app.get('/reset/:token', function(req, res) {
    User.findOne({ "resetToken.resetPasswordToken": req.params.token, "resetToken.resetPasswordExpires": { $gt: Date.now() } }, function(err, user) {
      if (!user) {
        req.flash('loginMessageError', 'Demande invalide ou expiré.');
        return res.redirect('/');
      }
      res.render('views/authentication/authentication-reset-password', {
        user: user
      });
    });
  });

  //Reset password and send email
  app.post('/reset/:token', function(req, res) {
    async.waterfall([
      function(done) {
        User.findOne({ "resetToken.resetPasswordToken": req.params.token, "resetToken.resetPasswordExpires": { $gt: Date.now() } }, function(err, user) {
          if (!user) {
            logger.debug('Pas trouve utilisateur');
            req.flash('loginMessageError', 'Demande invalide ou expiré 2.');
            return res.redirect('/');
          }
          logger.debug('Changement du mot de passe');
          user.local.password = user.generateHash(req.body.password);
          user.resetToken.resetPasswordToken = undefined;
          user.resetToken.resetPasswordExpires = undefined;

          user.save(function(err) {
            req.logIn(user, function(err) {
              done(err, user);
            });
          });
        });
      },
      function(user, done) {
        logger.debug('Send email confirmation');
        app.mailer.send('views/mails/mail-reset-password-confirm', {
          to: 'charles.rathouis@gmail.com', //TODO: user mails
          subject:'Orthogym : réinitialisation du mot de passe',
          email:user.email
        }, function (err, message) {
          if (err) {
            // handle error
            logger.error('Error sending email' + err);
          }
          req.flash('loginMessageSuccess', 'Votre mot de passe a été réinitialisé.');
          done(err, 'done');
        });
      }
    ], function(err) {
      res.redirect('/');
    });
  });

  //Loggin action, define different rendering depending of the profile of user
  app.get('/home', isLoggedIn, function(req, res) {
    if (req.user.role.member) {
      res.render('views/welcome/welcome-logged-member', {
          user : req.user // get the user out of session and pass to template
      });
    } else if (req.user.role.admin) {
      res.render('views/welcome/welcome-logged-admin', {
          user : req.user // get the user out of session and pass to template
      });
    } else if (req.user.role.corporate) {
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
