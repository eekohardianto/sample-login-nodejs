const LocalStrategy = require("passport-local").Strategy;

const mysql = require('mysql');
const bcrypt = require('bcrypt');
const dbconfig = require('./database');
const connection = mysql.createConnection(dbconfig.connection);

connection.query('USE' + dbconfig.database);

module.exports = function(passport) {
    passport.serializeUser(function(user, done){
        done(null, user.id);
    });

    passport.deserializeUser(function(id, done){
        connection.query("SELECT * FROM users WHERE id = ? ", [id], 
        function(err, rows){
            done(err, rows[0]);
        });
    });

    passport.use(
        'local-signup',
        new LocalStrategy({
            usernameField : 'username',
            passwordField : 'password',
            passReqToCallback: true
        },
        function(req, username, password, done){
            connection.query("SELECT * FROM users WHERE username = ? ", 
            [username], function(err, rows){
                if(err)
                    return done(err);
                if(rows.length){
                    return done(null, false, req.flash('signupMessage', 'that is already taken'));
                }
            })
        })
    )
}
