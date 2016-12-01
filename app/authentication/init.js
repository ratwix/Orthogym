const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy

const authenticationMiddleware = require('./middleware')

const user = {
  mail: 'charles@moi.fr',
  name: 'Charles'
  password: 'pass',
}

//TODO: a remplacer avec une recherche dans la database
function findUser (usermail, callback) {
  if (username === user.mail) {
    return callback(null, user)
  }
  return callback(null)
}

passport.serializeUser(function (user, cb) {
  cb(null, user.username)
})

passport.deserializeUser(function (username, cb) {
  findUser(username, cb)
})

function initPassport () {
  passport.use(new LocalStrategy(
    function(email, password, done) {
      findUser(email, function (err, user) {
        if (err) {
          return done(err)
        }
        if (!user) {
          return done(null, false)
        }
        if (password !== user.password) {
          return done(null, false)
        }
        return done(null, user)
      })
    }
  ))

  passport.authenticationMiddleware = authenticationMiddleware
}

module.exports = initPassport
