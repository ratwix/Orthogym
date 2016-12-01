var mongoose = require('mongoose');
var bcrypt   = require('bcrypt-nodejs');

var userSchema = mongoose.Schema({
    email: { type: String, required: true, index: {unique: true}},
    local           : {
      password      : String,
      name          : String,
      lastName      : String
    },
    facebook        : {
      id            : String,
      token         : String,
      name          : String
    },
    google          : {
      id            : String,
      token         : String,
      name          : String
    },
    admin           : { type: Boolean, default: false },
    admin_content   : { type: Boolean, default: false },
    corporate       : { type: Boolean, default: false },
    member          : { type: Boolean, default: false }
});

// methods ======================
// generating a hash
userSchema.methods.generateHash = function(password) {
    return bcrypt.hashSync(password, bcrypt.genSaltSync(8), null);
};

// checking if password is valid
userSchema.methods.validPassword = function(password) {
    return bcrypt.compareSync(password, this.local.password);
};

// create the model for users and expose it to our app
module.exports = mongoose.model('User', userSchema);
