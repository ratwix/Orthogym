const exphbs  = require('express-handlebars');
const passport = require('passport')
const session = require('express-session');
const flash = require('connect-flash');
const cookieParser = require('cookie-parser');
const mailer = require('express-mailer');
const sessionFileStore = require('session-file-store')(session);


(function (expressConfig) {

  var logger = require("./logger-config");

  var path = require('path');
  var expressValidator = require('express-validator');

  expressConfig.init = function (app, express) {
    //Set up session management
    logger.debug("Enabling sessions");
    app.use(session({
      name: 'server-session-cookie-id',
      secret: 'orthogym session secret',
      saveUninitialized: true,
      resave: true,
//      store: new sessionFileStore()
    }));

    logger.debug("Initialize mailer");
    var mailConfig = require('./mail-config');
    mailer.extend(app, {
      from: mailConfig.from,
      host: mailConfig.smtp, // hostname
      secureConnection: true, // use SSL
      port: mailConfig.port, // port for secure SMTP
      transportMethod: 'SMTP', // default is SMTP. Accepts anything that nodemailer accepts
      auth: {
        user: mailConfig.user,
        pass: mailConfig.password
      }
    });

    //Set up handelbar
    app.engine('.hbs', exphbs({
      defaultLayout: 'main',
      extname: '.hbs',
      layoutsDir: path.join(__dirname, '../views/layouts')
    }))

    app.set('view engine', '.hbs')
    app.set('views', path.join(__dirname, '../'))

    //Enable GZip compression
    logger.debug("Enabling GZip compression.");
    var compression = require('compression');
    app.use(compression({
      threshold: 512
    }));

    logger.debug("Setting 'Public' folder with maxAge: 1 Day.");
    var publicFolder = path.dirname(module.parent.filename)  + "/public";
    var oneYear = 31557600000;
    app.use(express.static(publicFolder, { maxAge: oneYear }));

    logger.debug("Setting parse urlencoded request bodies into req.body.");
    var bodyParser = require('body-parser');
    app.use(bodyParser.urlencoded({ extended: true }));
    app.use(bodyParser.json());
    app.use(cookieParser());

    logger.debug("Initialize passport");
    app.use(passport.initialize())
    app.use(passport.session())

    logger.debug("Initialize flash");
    app.use(flash());

    logger.debug("Overriding 'Express' logger");
    app.use(require('morgan')("combined", { "stream": logger.stream }));
  };

})(module.exports);
