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
  this._successReturnToOrRedirect = options.successReturnToOrRedirect;
  this._successRedirect = options.successRedirect;
  this._failureRedirect = options.failureRedirect;
}

util.inherits(ClientCertStrategy, Strategy);

ClientCertStrategy.prototype.authenticate = function(req, options) {
  var self = this;

  if (self._successReturnToOrRedirect) {
    options.successReturnToOrRedirect = self._successReturnToOrRedirect;
  }

  if (self._successRedirect) {
    options.successRedirect = self._successRedirect;
  }

  if (self._failureRedirect) {
    options.failureRedirect = self._failureRedirect;
  }

  if (self._renegotiation) {
    req.connection.renegotiate({
      requestCert: true,
      rejectUnauthorized: false
    }, function(err) {
      if (err) {
        return self.fail();
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
  if (!req.client.authorized && req.headers.ssl_client_cert == '(null)') {
    return self.fail();
  }

  if (req.connection.getPeerCertificate) {
    var clientCert = req.connection.getPeerCertificate();
  } else {
    var clientCert = formatCert(req.headers.ssl_client_cert);
  }

  // The cert must exist and be non-empty
  if (!clientCert) {
    return self.fail();
  }

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

function formatCert(cert) {
  return cert.replace(/( )(?!CERT)/g, '\n');
}

exports.Strategy = ClientCertStrategy;
