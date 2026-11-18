// Operator-initiated cutover to at-rest storage format v1 (MongoDB).
// Never run by the server. Back up first, then:
//   mongosh "$MONGODB_URI" scripts/at_rest_cutover.mongo.js
// Same semantics as scripts/at_rest_cutover.sql; re-runnable.
const legacyBearer = { $not: /^h1\$/ };

printjson(db.tokens.deleteMany({ $or: [
  { access_token: legacyBearer },
  { refresh_token: { $type: "string", $not: /^h1\$/ } },
] }));
printjson(db.authorization_codes.deleteMany({ code: legacyBearer }));
printjson(db.device_authorizations.deleteMany({ device_code: legacyBearer }));
printjson(db.clients.updateMany(
  { client_secret: { $not: /^c1\$/ }, token_endpoint_auth_method: { $ne: "none" } },
  { $set: { client_secret: "legacy-invalidated" } }));
printjson(db.clients.updateMany(
  { registration_access_token: { $nin: ["", null], $not: /^h1\$/ } },
  { $set: { registration_access_token: "" } }));
