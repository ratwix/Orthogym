const User = require('./model');

function initUser() {
  //Init model
  User.init();
}

module.exports = initUser
