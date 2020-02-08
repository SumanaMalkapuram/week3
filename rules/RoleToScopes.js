function (user, context, callback) {
  var _ = require('lodash');

  var roleToscopeMapping = {
    user: ["openid", "profile", "offline_access", "read:user-apis"],
    admin: ["openid", "profile","offline_access", "read:admin-apis", "read:user-apis"],
    other: ["openid", "profile", "offline_access"]
  };
  
  var role = 'other';
  
  if (user && !!user.user_metadata && !!user.user_metadata.role) {
    var given_role = user.user_metadata.role;
    // check if the given role is supported in the mapping else default to DEFAULT_ROLE
    role = _.has(roleToscopeMapping, given_role)? given_role: role;
  }

  var req = context.request;
  var requested_scopes = (req.query && req.query.scope) || (req.body && req.body.scope);
  requested_scopes = (requested_scopes && requested_scopes.split(" ")) || [];

  context.accessToken.scope = _.intersection(requested_scopes, roleToscopeMapping[role]);
  callback(null, user, context);
}