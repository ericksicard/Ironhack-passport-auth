require('dotenv').config();

const bodyParser      = require('body-parser');
const cookieParser    = require('cookie-parser');
const express         = require('express');
const favicon         = require('serve-favicon');
const hbs             = require('hbs');
const mongoose        = require('mongoose');
const logger          = require('morgan');
const path            = require('path');
const session         = require('express-session');
const bcrypt          = require('bcrypt');
const passport        = require('passport');
const LocalStrategy   = require('passport-local').Strategy;
const flash           = require('connect-flash');


// Set up the database
require('./configs/db-config');

const app_name = require('./package.json').name;
const debug = require('debug')(`${app_name}:${path.basename(__filename).split('.')[0]}`);

const app = express();

// use session here
require('./configs/sessions-config')(app);
// use password here
require('./configs/password-config');


// Middleware Setup
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
// initialize passport and passport session
app.use(passport.initialize());
app.use(passport.session());
// manage flash errors in Passport.
app.use(flash());


// Express View engine setup
app.use(require('node-sass-middleware')({
  src:  path.join(__dirname, 'public'),
  dest: path.join(__dirname, 'public'),
  sourceMap: true
}));
      

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'hbs');
app.use(express.static(path.join(__dirname, 'public')));
app.use(favicon(path.join(__dirname, 'public', 'images', 'favicon.ico')));



// default value for title local
app.locals.title = 'Express - Generated with IronGenerator';



const index = require('./routes/index');
const auth = require('./routes/auth-routes');
app.use(index);
app.use(auth);


module.exports = app;
