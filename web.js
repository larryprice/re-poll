var app = require('express')();
var mongoose = require('mongoose');
var bodyParser = require('body-parser');
var bcrypt = require('bcrypt');
var _ = require('underscore');

mongoose.connect('mongodb://localhost/dev');

var Session;

var db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', function() {
  var session = mongoose.Schema({
    expirationDate: Date
  });

  var poll = mongoose.Schema({
    sessionId: String,
    name: String,
    startDate: Date,
    endDate: Date,
    candidates: [String],
    passcode: String
  });

  var token = mongoose.Schema({
    sessionId: String,
    expirationDate: Date
  });

  Session = mongoose.model('session', session);
  Poll = mongoose.model('poll', poll);
  Token = mongoose.model('token', token);
});

app.use(bodyParser.json());

app.get('/', function(req, res) {
  res.send('Hello, World!');
});

app.put('/polls', function(req, res) {
  var start = Date.parse(req.body.startDate);
  var end = Date.parse(req.body.endDate);

  if (isNaN(start) || isNaN(end)) {
    res.status(400).send({
      error: "Invalid Date"
    });
    return;
  }
  if (!req.body.sessionId || !req.body.name || !req.body.candidates || !req.body.passcode) {
    res.status(400).send({
      error: "Invalid Poll objects"
    });
    return;
  }

  bcrypt.hash(req.body.passcode, 10, function(e, hash) {
    if (e) {
      res.send(e);
      return;
    }
    var poll = new Poll({
      sessionId: req.body.sessionId,
      name: req.body.name,
      startDate: start,
      endDate: end,
      candidates: req.body.candidates,
      passcode: hash
    });
    poll.save(function(err) {
      if (err) {
        res.status(500).send({
          error: err
        });
        return;
      }
      res.send(_.omit(poll.toObject(), ['passcode', '__v']));
    });
  });
});

app.put('/sessions/:id/token', function(req, res) {
  var authorization = new Buffer(req.headers.authorization.replace('Basic ', ''), 'base64').toString('utf8');

  var credentials = authorization.split(':', 2);

  console.log(credentials[0]);

  Poll.findOne({
    _id: credentials[0]
  }, function(err, poll) {
    if (err || !poll) {
      res.status(500).send({
        error: err
      });
      return;
    }
    bcrypt.compare(credentials[1], poll.passcode, function(e, r){
      if(e) {
        res.status(500).send({
          error: e
        });
        return;
      }
      var expires = new Date();
      expires.setDate(expires.getDate() + 30);
      var token = new Token({ sessionId: req.body.id, expirationDate: expires});
      token.save(function(terr){
        if(terr) {
          res.status(500).send({
            error: terr
          });
          return;
        }
        res.send(token);
      });
    })
  });
});

app.get('/polls', function(req, res) {
  Poll.find({}, {passcode: 0, __v: 0}, function(err, polls) {
    if (err) {
      res.status(500).send({
        error: err
      });
      return;
    }
    res.send(polls);
  });

});

app.get('/polls/:id', function(req, res) {
  Poll.findOne({
    _id: req.params.id
  }, {passcode: 0, __v: 0}, function(err, polls) {
    if (err) {
      res.status(500).send({
        error: err
      });
      return;
    }
    res.send(polls);
  });

});

// app.delete('/polls', function(req, res){
//
// })

app.put('/sessions', function(req, res) {
  var expires = new Date();
  expires.setDate(expires.getDate() + 30);
  var session = new Session({
    expirationDate: expires
  })
  session.save(function(err) {
    if (err) {
      res.status(500).send({
        error: err
      });
      return;
    }
    res.send(session.id);
  })
});

app.listen(3000, function() {
  console.log('Example app listening on port 3000');
});
