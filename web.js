var app = require('express')();
var mongoose = require('mongoose');
var bodyParser = require('body-parser');
var bcrypt = require('bcrypt');
var _ = require('underscore');

mongoose.connect(process.env.MONGOLAB_URI || 'mongodb://localhost/dev');

var Session, Poll, Token, Candidate;

var db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', function() {
	var session = mongoose.Schema({
		expirationDate: Date
	});

	var candidate = mongoose.Schema({
		name: String
	});

	var poll = mongoose.Schema({
		sessionId: String,
		name: String,
		startDate: Date,
		endDate: Date,
		candidates: [candidate],
		passcode: String
	});

	var token = mongoose.Schema({
		sessionId: String,
		expirationDate: Date
	});

	Session = mongoose.model('session', session);
	Candidate = mongoose.model('candidate', candidate);
	Poll = mongoose.model('poll', poll);
	Token = mongoose.model('token', token);
});

app.use(bodyParser.json());

app.get('/', function(req, res) {
	res.send('Hello, World!');
});

var parseBasicAuth = function(req) {
	if (!req.headers || !req.headers.authorization) {
		return false;
	}
	var b = new Buffer(req.headers.authorization.replace('Basic ', ''), 'base64').toString('utf8');
	return b.split(':', 2);
}

var withSessionAuth = function(req, res, callback) {
	var creds = parseBasicAuth(req);
	if (!creds) {
		res.status(401);
		return;
	}
	Session.findOne({
		_id: creds[0]
	}, function(err, session) {
		if (err) {
			res.status(400).send({
				error: err
			});
			return;
		}
		var expires = new Date();
		expires.setDate(expires.getDate() + 30);
		session.expirationDate = expires;
		session.save(function(e) {
			if (e) {
				res.status(400).send({
					error: e
				});
				return;
			}
			callback(req, res, session);
		});
	});
};

// var withTokenAuth = function(req, res, callback) {
//   if (!req.headers || !req.headers.authorization) {
// 		return false;
// 	}
// 	var creds = req.headers.authorization.replace('Token ', '');
// 	if (!creds) {
// 		res.status(401);
// 		return;
// 	}
// 	Token.findOne({
// 		_id: creds
// 	}, function(err, token) {
// 		if (err) {
// 			res.status(400).send({
// 				error: err
// 			});
// 			return;
// 		} else if (!token) {
//       res.status(400).send({error: "No such token"});
//       return;
//     }
//     Session.findOne({_id: token.sessionId}, function(e, session) {
//       if (e) {
//   			res.status(400).send({
//   				error: err
//   			});
//   			return;
//       } else if (!session) {
//         res.status(400).send({error: "No such token"});
//         return;
//       }
//   		var expires = new Date();
//   		expires.setDate(expires.getDate() + 30);
//   		session.expirationDate = expires;
//   		session.save(function(se) {
//   			if (se) {
//   				res.status(400).send({
//   					error: se
//   				});
//   				return;
//   			}
//   			callback(req, res, session);
//   		});
//     });
// 	});
// };

app.put('/polls', function(req, res) {
	var start = Date.parse(req.body.startDate);
	var end = Date.parse(req.body.endDate);

	if (isNaN(start) || isNaN(end)) {
		res.status(400).send({
			error: "Invalid start or end dates"
		});
		return;
	}
	var rawCandidates = JSON.parse(req.body.candidates);
	if (!req.body.sessionId || !req.body.name || !rawCandidates || !req.body.passcode) {
		res.status(400).send({
			error: "Invalid poll object"
		});
		return;
	}

	var candidates = [];
	for (var i = 0; i < rawCandidates.length; ++i) {
		var item = rawCandidates[i];
		if (!item.name) {
			res.status(400).send({
				error: "Invalid Candidate object: " + item
			});
			return;
		}
		candidates.push(new Candidate({
			name: item.name
		}));
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
			candidates: candidates,
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

	Poll.findOne({
		_id: credentials[0]
	}, function(err, poll) {
		if (err || !poll) {
			res.status(500).send({
				error: err
			});
			return;
		}
		bcrypt.compare(credentials[1], poll.passcode, function(e, r) {
			if (e) {
				res.status(500).send({
					error: e
				});
				return;
			} else if (!r) {
				res.status(400).send({
					error: "Invalid passcode"
				});
				return;
			}
			var expires = new Date();
			expires.setDate(expires.getDate() + 30);
			var token = new Token({
				sessionId: req.body.id,
				expirationDate: expires
			});
			token.save(function(terr) {
				if (terr) {
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
	Poll.find({}, {
		passcode: 0,
		__v: 0
	}, function(err, polls) {
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
	}, {
		passcode: 0,
		__v: 0
	}, function(err, polls) {
		if (err) {
			res.status(500).send({
				error: err
			});
			return;
		}
		res.send(polls);
	});
});

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
		res.send(session);
	});
});

app.listen(process.env.PORT || 3000, function() {
	console.log('RePoll listening...');
});
