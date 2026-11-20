// Operator-initiated cutover to at-rest storage format v1 (MongoDB).
// Never run by the server. Back up first, then:
//   mongosh "$MONGODB_URI" scripts/at_rest_cutover.mongo.js
// Same semantics as scripts/at_rest_cutover.sql.
//
// Atomicity: all steps run in ONE multi-document transaction, so a failure
// leaves the database untouched. Transactions need a replica set / sharded
// cluster; on a standalone mongod the script aborts before changing anything.
// See "Partial-failure recovery" in docs/security/at-rest-hardening.md.
const legacyBearer = { $not: /^h1\$/ };

const session = db.getMongo().startSession();
const sdb = session.getDatabase(db.getName());
try {
  session.startTransaction({
    readConcern: { level: "snapshot" },
    writeConcern: { w: "majority" },
  });
  printjson(sdb.tokens.deleteMany({ $or: [
    { access_token: legacyBearer },
    { refresh_token: { $type: "string", $not: /^h1\$/ } },
  ] }));
  printjson(sdb.authorization_codes.deleteMany({ code: legacyBearer }));
  printjson(sdb.device_authorizations.deleteMany({ device_code: legacyBearer }));
  printjson(sdb.clients.updateMany(
    { client_secret: { $not: /^c1\$/ }, token_endpoint_auth_method: { $ne: "none" } },
    { $set: { client_secret: "legacy-invalidated" } }));
  printjson(sdb.clients.updateMany(
    { registration_access_token: { $nin: ["", null], $not: /^h1\$/ } },
    { $set: { registration_access_token: "" } }));
  session.commitTransaction();
  print("at-rest cutover committed");
} catch (e) {
  try { session.abortTransaction(); } catch (_) {}
  print("at-rest cutover ABORTED, nothing changed: " + e);
  throw e;
} finally {
  session.endSession();
}
