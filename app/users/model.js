const mongoose = require('mongoose');
mongoose.connect('mongodb://localhost/orthogym');
const Schema = mongoose.Schema;

var userSchema = new Schema({
    mail: { type: String, required: true, index: {unique: true}},
    name: { type: String, required: true },
    password: { type: String},
    lastName: String,
    password: String
})
