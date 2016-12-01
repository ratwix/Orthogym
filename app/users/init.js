require('./model');
const passport = require('passport');

function initUser (app) {
  app.get('/freeTour', passport.authenticationMiddleware(), renderProfile)
  app.post('/login', passport.authenticate('local', {
    successRedirect: '/freeTour',
    failureRedirect: '/'
  }))
}

function renderWelcomeFree (req, res) {
  res.render('user/profile', {
    username: req.user.username
  })
}

module.exports = initUser
