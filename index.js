const util = require('util');

const passport = require('passport-strategy');

const request = require('request');
const crypto = require('crypto');
const qs = require('qs');

function Strategy(options = {}, verify) {
  if (!verify) { throw new TypeError('VistaPrintStrategy requires a verify callback'); }
  if (!options.requestTokenURL) { throw new TypeError('VistaPrintStrategy requires a requestTokenURL option'); }
  if (!options.userAuthorizationURL) { throw new TypeError('VistaPrintStrategy requires a userAuthorizationURL option'); }
  if (!options.authorizationTokenURL) { throw new TypeError('VistaPrintStrategy requires a authorizationTokenURL option'); }
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

      const evaAccountId = JSON.parse(body);

      const verified = (err, user, info = {}) => {
        if (err) { return this.error(err); }
        if (!user) { return this.fail(info); }

        // if (state) { info.state = state; }

        this.success(user, info);
      };

      const profile = {id: evaAccountId};

      const arity = this._verify.length;
      if (arity === 6) {
        this.fail('Params are not allowed', 500);
        // this._verify(req, null, null, params, profile, verified);
      }
      else {
        this._verify(req, null, null, profile, verified);
      }
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

/**
 * Retrieve user profile from Twitter.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `id`        (equivalent to `user_id`)
 *   - `username`  (equivalent to `screen_name`)
 *
 * Note that because Twitter supplies basic profile information in query
 * parameters when redirecting back to the application, loading of Twitter
 * profiles *does not* result in an additional HTTP request, when the
 * `skipExtendedUserProfile` option is enabled.
 *
 * @param {string} token
 * @param {string} tokenSecret
 * @param {object} params
 * @param {function} done
 * @access protected
 */
Strategy.prototype.userProfile = function(token, tokenSecret, params, done) {
  if (!this._skipExtendedUserProfile) {
    var json;

    var url = uri.parse(this._userProfileURL);
    url.query = url.query || {};
    if (url.pathname.indexOf('/users/show.json') == (url.pathname.length - '/users/show.json'.length)) {
      url.query.user_id = params.user_id;
    }
    if (this._includeEmail == true) {
      url.query.include_email = true;
    }
    if (this._includeStatus == false) {
      url.query.skip_status = true;
    }
    if (this._includeEntities == false) {
      url.query.include_entities = false;
    }

    this._oauth.get(uri.format(url), token, tokenSecret, function (err, body, res) {
      if (err) {
        if (err.data) {
          try {
            json = JSON.parse(err.data);
          } catch (_) {}
        }

        if (json && json.errors && json.errors.length) {
          var e = json.errors[0];
          return done(new APIError(e.message, e.code));
        }
        return done(new InternalOAuthError('Failed to fetch user profile', err));
      }

      try {
        json = JSON.parse(body);
      } catch (ex) {
        return done(new Error('Failed to parse user profile'));
      }

      var profile = Profile.parse(json);
      profile.provider = 'twitter';
      profile._raw = body;
      profile._json = json;
      // NOTE: The "X-Access-Level" header is described here:
      //       https://dev.twitter.com/oauth/overview/application-permission-model
      //       https://dev.twitter.com/oauth/overview/application-permission-model-faq
      profile._accessLevel = res.headers['x-access-level'];

      done(null, profile);
    });
  } else {
    var profile = { provider: 'twitter' };
    profile.id = params.user_id;
    profile.username = params.screen_name;

    done(null, profile);
  }
};

// Expose constructor.
module.exports = Strategy;
