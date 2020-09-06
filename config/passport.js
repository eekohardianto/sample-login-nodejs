const LocalStrategy = require("passport-local").Strategy;

const mysql = require('mysql');
const bcrypt = require('bcryptjs');
const dbconfig = require('./database');
const connection = mysql.createConnection(dbconfig.connection);

connection.query('USE ' + dbconfig.database);

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
            usernameField : 'email',
            passwordField : 'password',
            passReqToCallback: true
        },
        function(req, email, password, done){
            connection.query("SELECT * FROM users WHERE email = ? ", 
            [email], function(err, rows){
                if(err)
                    return done(err);
                if(rows.length){
                    return done(null, false, req.flash('signupMessage', 'that is already taken'));
                }else{
                    var newUserMysql = {
                        email: email,
                        password: bcrypt.hashSync(password, 10)
                    };

                    var insertQuery = "INSERT INTO users (email, password) VALUES (?, ?)";
                    console.log(insertQuery);
                    connection.query(insertQuery, [newUserMysql.email, newUserMysql.password],
                        function(err, rows){
                            newUserMysql.id = rows.insertId;

                            return done(null, newUserMysql);

                        });
                }
            });
        })
    );
    
passport.use(
    'local-login',
    new LocalStrategy({
        usernameField : 'email',
        passwordField : 'password',
        passReqToCallback: true
    },
    function(req, email, password, done){
            connection.query("SELECT * FROM users WHERE email = ? ", [email],
            function(err, rows){
                if(err)
                    return done(err);
                if(!rows.length){
                    return done(null, false, req.flash('loginMessage', 'No User Found'));
                }
                if(!bcrypt.compareSync(password, rows[0].password))
                return done(null, false, req.flash('loginMessage', 'Wrong Password'));

                return done(null, rows[0]);
            });
        })
    );
};
