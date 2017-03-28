const util = require('util');
const url = require('url');

const passport = require('passport-strategy');

const request = require('request');
const crypto = require('crypto');
const qs = require('qs');

function Strategy(options = {}, verify) {
  if (!verify) { throw new TypeError('VistaPrintStrategy requires a verify callback'); }
  if (!options.requestTokenURL) { throw new TypeError('VistaPrintStrategy requires a requestTokenURL option'); }
  if (!options.userAuthorizationURL) { throw new TypeError('VistaPrintStrategy requires a userAuthorizationURL option'); }
  if (!options.authorizationTokenURL) { throw new TypeError('VistaPrintStrategy requires a authorizationTokenURL option'); }
  if (!options.profileServiceURL) { throw new TypeError('VistaPrintStrategy requires a profileServiceURL option'); }
  if (!options.authFailureUri) { throw new TypeError('VistaPrintStrategy requires a authFailureUri option'); }
  if (!options.authSuccessUri) { throw new TypeError('VistaPrintStrategy requires a authSuccessUri option'); }

  Object.assign(Strategy.prototype, options);

  this._verify = verify;

  passport.Strategy.call(this);
  this.name = 'vistaprint';
}

// Inherit from `passport.Strategy`.
util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function(req, options) {
  const apikey = this.consumerKey;
  const secret = this.consumerSecret;
  const ts = Math.floor(Date.now() / 1000);

  if (req.query && req.query.request_token) {
    if (req.query.response !== 'granted') {
      return this.fail(req.query.response, 403);
    }

    const requestToken = req.query.request_token;
    const auth = crypto
        .createHash('sha256')
        .update(`${secret}${apikey}${requestToken}${ts}`)
        .digest('base64');

    request(this.userAuthorizationURL, {
      qs: {
        apikey,
        requesttoken: requestToken,
        ts,
        auth,
      },
    }, (err, resp, body) => {
      if (err) return this.fail(err.message, 403);
      if (resp.statusCode === 500) return this.fail('Could not login', 403);

      const verified = (err, user, info = {}) => {
        if (err) { return this.error(err); }
        if (!user) { return this.fail(info); }

        this.success(user, info);
      };

      // get the profile info
      var evaAccountId;
      try {
        evaAccountId = JSON.parse(body);
      } catch(e) {
        return this.fail('There was an error processing response from EVA.');
      }

      const timestamp = new Date().toISOString();
      const apiVersion = 1;
      const auth = crypto
          .createHmac('sha256', new Buffer(secret, 'base64').toString('binary'))
          .update(`apikey=${apikey},timestamp=${timestamp}`)
          .digest('base64');
      const hash = encodeURIComponent(auth);

      request(`${this.profileServiceURL}${evaAccountId}`, {
        headers: {
          Authorization: `apikey=${apikey},timestamp=${timestamp},version=${apiVersion},hashcode=${hash}`,
        },
      }, (err, resp, body) => {
        if (err) return this.fail(err.message, 403);

        const json = JSON.parse(body);
        const email = json.Email;
        const profile = {id: evaAccountId, email};

        const arity = this._verify.length;
        if (arity === 6) {
          this.fail('Params are not allowed', 500);
          // this._verify(req, null, null, params, profile, verified);
        }
        else {
          this._verify(req, null, null, profile, verified);
        }
      });
    });
  }
  else {
    const auth = crypto
        .createHash('sha256')
        .update(`${secret}${apikey}${ts}`)
        .digest('base64');

    request(this.requestTokenURL, {
      qs: {
        apikey,
        ts,
        auth,
      },
    }, (err, resp, body) => {
      if (err) return this.error(err);
      if (resp.statusCode === 500) return this.fail('Could not login', 403);

      const requestToken = JSON.parse(body);
      const redirectAuth = crypto
          .createHash('sha256')
          .update(`${secret}${apikey}${requestToken}${ts}`)
          .digest('base64');

      const redirectFailureUri = req.query.redirectTo;

      const queryString = {
        api_key: apikey,
        request_token: requestToken,
        ts,
        auth: redirectAuth,
        response_uri: this.authSuccessUri,
        failure_uri: redirectFailureUri || this.authFailureUri,
      };

      this.redirect(`${this.authorizationTokenURL}?${qs.stringify(queryString)}`);
    });
  }
};

module.exports = Strategy;
