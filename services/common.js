const passport = require('passport');

exports.isAuth = (req, res, done) => {
  return passport.authenticate('jwt');
};


exports.sanitizeUser = (user) => {
  return { id: user.id, role: user.role };
};

exports.cookieExtractor = function (req) {
  let token = null;
  if (req && req.cookies) {
    token = req.cookies['jwt'];
  }
  //TODO : this is temporary token for testing without cookie
//  token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY1NjVhY2ZlNWI3ODQzNTY5NjFhMzRmYiIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNzAxMTc5MjAxfQ.BNtCK_fu4FdheKK0DfQX3GLIHTXCXOxoPHUtftT4Yu0"
 return token;
};