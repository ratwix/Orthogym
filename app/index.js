const logger = require("./config/logger-config");
const express = require('express')
const path = require('path')
const app = express()
const expressConfig = require("./config/express-config");
const mongoose = require('mongoose')
const mongooseConfig = require('./config/database-config')

const port = 3000

logger.info("configuring express....");
expressConfig.init(app, express);
logger.info("Express configured");

logger.info("connect to database");
mongooseConfig.init(mongoose)

logger.debug("Init authentication");
require('./authentication').init(app);

logger.debug("Init users");
require('./users').init();
var User = require('./users').user;

//Main route definition
app.get('/', (request, response) => {
  if (request.isAuthenticated()) {
    response.redirect('/home');
  } else {
    response.render('views/welcome/welcome-non-autenticate', { message: request.flash('loginMessage') });
  }
})

//Error management
app.use((err, request, response, next) => {
  // log the error, for now just console.log
  console.log(err)
  response.status(500).send('Something broke!')
})

var server = app.listen(port, function() {
  var host = server.address().address;
  var port = server.address().port;
  logger.info('Example app listening at http://%s:%s', host, port);
})
