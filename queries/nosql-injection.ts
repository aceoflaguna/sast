import { defineQuery } from "../src/query";

const COLL = String.raw`(coll|collection|db|mongo|model|users?|accounts?)\w*`;
export default defineQuery({
  id: "nosql-injection",
  title: "NoSQL (operator) injection",
  severity: "high",
  cwe: "CWE-943",
  description: "A request-controlled value (which may be an object like {\"$ne\": null}) is used in a MongoDB-style query filter.",
  taint: {
    sinks: {
      javascript: [{ callee: new RegExp(String.raw`(^|\.)${COLL}(\(\))?\.(find|findOne|findOneAndUpdate|findOneAndDelete|findById|updateOne|updateMany|deleteOne|deleteMany|countDocuments|aggregate|where)$`, "i"), args: [0], label: "MongoDB query filter" }],
      python: [{ callee: new RegExp(String.raw`(^|\.)${COLL}(\(\))?\.(find|find_one|update_one|update_many|delete_one|delete_many|aggregate|count_documents|find_one_and_\w+)$`, "i"), args: [0], label: "MongoDB query filter" }],
      php: [{ callee: new RegExp(String.raw`(^|\.)\$?${COLL}(\(\))?\.(find|findOne|updateOne|updateMany|deleteOne|deleteMany|aggregate|count)$`, "i"), args: [0], label: "MongoDB query filter" }],
      java: [{ callee: /^(BasicDBObject|Document|BsonDocument)\.parse$/, label: "JSON → query document" }],
      // Go values are typed (a string can't smuggle {"$ne": null}); the real risks are JSON/extended-JSON → filter and $where.
      go: [{ callee: /^bson\.UnmarshalExtJSON$/, args: [0], label: "extended JSON → query document" }, { callee: /^bson\.Raw$|^bson\.RawValue$/, label: "raw BSON filter" }],
      csharp: [
        { callee: /^(BsonDocument\.Parse|BsonSerializer\.Deserialize|BsonDocument\.TryParse)$/, args: [0], label: "JSON → BsonDocument filter" },
        { callee: new RegExp(String.raw`(^|\.)${COLL}\.(Find|FindSync|FindAsync|DeleteOne|DeleteMany|UpdateOne|UpdateMany|CountDocuments|Aggregate)$`, "i"), args: [0], label: "MongoDB query filter" },
      ],
    },
    sanitizers: {
      javascript: [/^(String|Number|sanitize|mongoSanitize|mongo-sanitize)$/, /\.toString$/],
      python: [/^(str|int)$/],
      php: [/^(strval|intval)$/],
    },
  },
  message: (f) => `Request data used directly as a query filter (${f.label}); coerce to a primitive type first.`,
});
