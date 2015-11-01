var util = require('util'),
    Strategy = require('passport-strategy');

/*
 * passport.js TLS client certificate strategy
 */
function ClientCertStrategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }
  if (!verify) throw new Error('Client cert authentication strategy requires a verify function');

  Strategy.call(this);
  this.name = 'client-cert';
  this._verify = verify;
  this._passReqToCallback = options.passReqToCallback;
  this._renegotiation = options.renegotiation;
}

util.inherits(ClientCertStrategy, Strategy);

ClientCertStrategy.prototype.authenticate = function(req, options) {
  var self = this;

  if (self._renegotiation) {
    req.connection.renegotiate({
      requestCert: true,
      rejectUnauthorized: true
    }, function(err) {
      if (err) {
        self.fail();
        return;
      }

      continueVerify(req, self);
    });

  } else {
    continueVerify(req, self);
  }
};

function continueVerify(req, self) {
  // Requests must be authorized
  // (i.e. the certificate must be signed by at least one trusted CA)
  if(!req.client.authorized) {
    self.fail();
  } else {
    var clientCert = req.connection.getPeerCertificate();

    // The cert must exist and be non-empty
    if(!clientCert || Object.getOwnPropertyNames(clientCert).length === 0) {
      self.fail();
    } else {

      var verified = function verified(err, user) {
        if (err) { return self.error(err); }
        if (!user) { return self.fail(); }
        self.success(user);
      };

      if (self._passReqToCallback) {
        self._verify(req, clientCert, verified);
      } else {
        self._verify(clientCert, verified);
      }
    }
  }
}

exports.Strategy = ClientCertStrategy;
