var app = require('express')(),
	mongoose = require('mongoose'),
	bodyParser = require('body-parser'),
	bcrypt = require('bcrypt'),
	morgan = require('morgan'),
  cors = require('cors'),
	_ = require('underscore');

mongoose.connect(process.env.MONGOLAB_URI || 'mongodb://localhost/dev');

var Session, Poll, Token, Candidate, Ballot;

var db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', function() {
	var session = mongoose.Schema({
		expirationDate: {type: Date, required: true}
	});

	var candidate = mongoose.Schema({
		name: {type: String, required: true}
	});

	var poll = mongoose.Schema({
		sessionId: {type: mongoose.Schema.Types.ObjectId, required: true},
		name: {type: String, unique: true, required: true},
		startDate: {type: Date, required: true},
		endDate: {type: Date, required: true},
		candidates: [candidate],
		passcode: {type: String, required: true}
	});

	var token = mongoose.Schema({
		sessionId: {type: String, required: true},
		expirationDate: {type: Date, required: true},
		pollId: {type: mongoose.Schema.Types.ObjectId, required: true}
	});

	var ballot = mongoose.Schema({
		tokenId: {type: mongoose.Schema.Types.ObjectId, required: true},
		pollId: {type: mongoose.Schema.Types.ObjectId, required: true},
		candidates: [candidate]
	});

	Session = mongoose.model('session', session);
	Candidate = mongoose.model('candidate', candidate);
	Poll = mongoose.model('poll', poll);
	Token = mongoose.model('token', token);
	Ballot = mongoose.model('ballot', ballot);
});

app.use(cors());
app.use(bodyParser.json());
app.use(morgan('combined'));

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
		res.status(401).send("Requires basic auth");
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
		} else if (!session) {
			res.status(400).send({
				error: "Requires session authentication"
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

var withTokenAuth = function(req, res, callback) {
	if (!req.headers || !req.headers.authorization) {
		return false;
	}
	var creds = req.headers.authorization.replace('Token ', '');
	if (!creds) {
		res.status(401);
		return;
	}
	Token.findOne({
		_id: creds
	}, function(err, token) {
		if (err) {
			res.status(400).send({
				error: err
			});
			return;
		} else if (!token) {
			res.status(400).send({
				error: "No such token"
			});
			return;
		}
		Session.findOne({
			_id: token.sessionId
		}, function(e, session) {
			if (e) {
				res.status(400).send({
					error: err
				});
				return;
			} else if (!session) {
				res.status(401).send({
					error: "Could not find valid session for the given token"
				});
				return;
			}
			var expires = new Date();
			expires.setDate(expires.getDate() + 30);
			session.expirationDate = expires;
			session.save(function(se) {
				if (se) {
					res.status(400).send({
						error: se
					});
					return;
				}
				callback(req, res, token);
			});
		});
	});
};

app.put('/polls', function(request, result) {
	withSessionAuth(request, result, function(req, res, session) {
		var start = Date.parse(req.body.startDate);
		var end = Date.parse(req.body.endDate);

		if (isNaN(start) || isNaN(end)) {
			res.status(400).send({
				error: "Invalid start or end dates"
			});
			return;
		}
		var rawCandidates = req.body.candidates;
		if (typeof(rawCandidates) === "string") {
			try {
				rawCandidates = JSON.parse(req.body.candidates);
			} catch (r) {}
		}

		if (!req.body.name || !rawCandidates || !req.body.passcode) {
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
				res.status(500).send({error: e});
				return;
			}

			var poll = new Poll({
				sessionId: session.id,
				name: req.body.name,
				startDate: start,
				endDate: end,
				candidates: candidates,
				passcode: hash
			});
			poll.save(function(err) {
				if (err) {
					res.status(500).send({
						error: err.errmsg
					});
					return;
				}
				res.send(_.omit(poll.toObject(), ['passcode', '__v']));
			});
		});
	});
});

app.put('/sessions/:id/token', function(req, res) {
	Session.findOne({
		_id: req.params.id
	}, function(se, session) {
		if (se) {
			res.status(500).send({
				error: se
			});
			return;
		} else if (!session) {
			res.status(400).send({
				error: "Could not find session with id " + req.params.id
			});
			return;
		}

		if (!req.headers.authorization) {
			res.status(401).send({
				error: "Requires basic authorization header"
			});
			return;
		}

		var authorization = new Buffer(req.headers.authorization.replace('Basic ', ''), 'base64').toString('utf8');
		var credentials = authorization.split(':', 2);

		Poll.findOne({
			_id: credentials[0]
		}, function(err, poll) {
			if (err) {
				res.status(500).send({
					error: err
				});
				return;
			} else if (!poll) {
				res.status(400).send({
					error: "Could not find poll with id " + credentials[0]
				});
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
					sessionId: session.id,
					expirationDate: expires,
					pollId: poll.id
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
});

app.get('/polls', function(request, result) {
	withSessionAuth(request, result, function(req, res, session) {
		Poll.find({}, {
			passcode: 0,
			candidates: 0,
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
});

app.get('/polls/:id', function(request, response) {
	withTokenAuth(request, response, function(req, res, token) {
		if (token.pollId != req.params.id) {
			res.status(401).send({
				error: "Token does not match poll ID"
			});
			return;
		}
		Poll.findOne({
			_id: token.pollId,
		}, {
			passcode: 0,
			__v: 0
		}, function(err, poll) {
			if (err) {
				res.status(500).send({
					error: err
				});
				return;
			} else if (!poll) {
				res.status(400).send({
					error: err
				});
				return;
			}
			res.send(poll);
		});
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

app.put("/ballots", function(request, response) {
	withTokenAuth(request, response, function(req, res, token) {
		Poll.findOne({
			_id: token.pollId
		}, function(pe, poll) {
			if (pe) {
				res.status(500).send({
					error: pe
				});
				return;
			} else if (!poll) {
				res.status(400).send({
					error: "Could not find a poll for the given token"
				});
				return;
			}

			var ballot = new Ballot({
				tokenId: token.id,
				pollId: poll.id,
				candidates: []
			})
			ballot.save(function(err) {
				if (err) {
					res.status(500).send({
						error: err
					});
					return;
				}
				res.send(ballot);
			});
		});
	});
});

app.post("/ballots/:id", function(request, response) {
	withTokenAuth(request, response, function(req, res, token) {
		Ballot.findOne({
			_id: req.params.id
		}, function(be, ballot) {
			if (be) {
				res.status(500).send({
					error: be
				});
				return;
			} else if (!ballot) {
				res.status(400).send({
					error: "Could not find ballot with ID " + req.params.id
				});
				return;
			}

			// get poll candidates
			Poll.findOne({
				_id: ballot.pollId
			}, function(pe, poll) {
				if (pe) {
					res.status(500).send({
						error: pe
					});
					return;
				} else if (!poll) {
					res.status(400).send({
						error: "No such poll " + ballot.pollId
					});
					return;
				}

				if (req.body.candidates) {
					var validBallot = req.body.candidates.every(function(c) {
						return poll.candidates.some(function(cc) {
							return cc.id === c._id;
						});
					});

					if (validBallot) {
						ballot.candidates = req.body.candidates;
					} else {
						res.status(400).send("Invalid candidates " + JSON.stringify(req.body.candidates));
						return;
					}
				}

				ballot.save(function(e) {
					if (e) {
						res.status(500).send({
							error: e
						});
						return;
					}
					res.send(ballot);
				});
			});
		});
	});
});

app.get("/ballots/:id", function(request, response) {
	withTokenAuth(request, response, function(req, res, token) {
		Ballot.findOne({
			_id: req.params.id
		}, function(be, ballot) {
			if (be) {
				res.status(500).send({
					error: be
				});
				return;
			} else if (!ballot) {
				res.status(400).send({
					error: "Could not find ballot with ID " + req.params.id
				});
				return;
			}
			res.send(ballot);
		});
	});
});

app.get("/polls/:id/results", function(request, response) {
	withTokenAuth(request, response, function(req, res, token) {
		Poll.findOne({
			_id: req.params.id
		}, function(e, poll) {
			if (e) {
				res.status(500).send({
					error: e
				});
				return;
			} else if (!poll) {
				res.status(400).send({
					error: "Unknown poll with id " + req.params.id
				});
				return;
			}
			Ballot.find({
				pollId: poll.id,
				candidates: {$exists: true, $ne: []}
			}, function(err, ballots) {
				if (err) {
					res.status(500).send({
						error: err
					});
					return;
				}

				var getTally = function(candidates, ballots) {
					var results = {};
					candidates.forEach(function(c) {
						results[c.id] = {};
						results[c.id].id = c.id;
						results[c.id].name = c.name;
						results[c.id].count = 0;
					});

					ballots.forEach(function(ballot) {
						var candidate = ballot.candidates[0];
						if (!candidate) return;
						++results[candidate.id].count;
					});

					return Object.keys(results).map(function(key) {
						return results[key];
					}).sort(function(lhs, rhs) {
						return lhs.count > rhs.count;
					});
				};

				var getLosers = function(votes) {
					return votes.filter(function(v) {
						return v.count === votes[0].count;
					});
				}

				var majority = ballots.length / 2, results = [];
				var candidateList = poll.candidates;

				while (ballots.length > 0) {
					var result = getTally(candidateList, ballots);
					results.push(JSON.parse(JSON.stringify(result)));
					console.log(result[result.length-1].count, majority)
					if (result[result.length-1].count > majority) {
						break;
					}

					// remove losers
					var losers = getLosers(result);
					ballots.forEach(function(ballot) {
						ballot.candidates = ballot.candidates.filter(function(c) {
							return !losers.some(function(l) {
								return l.id === c.id
							});
						});
					});
					candidateList = candidateList.filter(function(c) {
						return !losers.some(function(l) {
							return l.id === c.id
						});
					})

					// remove empty ballots
					ballots = ballots.filter(function(b) {
						return b.candidates.length > 0;
					});
				}
console.log("hmmmm let's look at the results:", results);
				res.send(results);
			});
		});
	});
});

app.listen(process.env.PORT || 3000, function() {
	console.log('RePoll listening...');
});
