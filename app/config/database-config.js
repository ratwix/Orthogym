const logger = require("./logger-config");

(function (databaseConfig) {
  const database_url = 'mongodb://localhost/orthogym';

  databaseConfig.init = function (mongoose) {
    mongoose.connect(database_url, function (err) {
      if (err) {
        logger.error('Mongoose Connection error:' + err);
      }
    });

    mongoose.connection.on('open', function () {
      logger.info('Connected to database ' + database_url);
    });
  }
})(module.exports);
