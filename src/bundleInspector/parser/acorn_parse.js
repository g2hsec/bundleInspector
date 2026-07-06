// Native ESTree parser backend (opt-in). Reads a JS file path from argv[2], parses with
// acorn (ESTree, same spec esprima emits), and writes a JSON AST to stdout.
//
// Requires `acorn` to be resolvable by Node (e.g. `npm install acorn` in the project, or a
// directory on NODE_PATH). Enabled only when BUNDLEINSPECTOR_NATIVE_PARSER=1; the Python
// side always falls back to esprima if this script errors, so detection never degrades.
const fs = require("fs");

let acorn;
try {
  acorn = require("acorn");
} catch (e) {
  process.stderr.write("ACORN_UNAVAILABLE: " + e.message);
  process.exit(3);
}

let src;
try {
  src = fs.readFileSync(process.argv[2], "utf8");
} catch (e) {
  process.stderr.write("READ_FAIL: " + e.message);
  process.exit(4);
}

function parseWith(sourceType) {
  return acorn.parse(src, {
    ecmaVersion: "latest",
    sourceType,
    locations: true,
    ranges: true,
    allowReturnOutsideFunction: true,
    allowAwaitOutsideFunction: true,
    allowImportExportEverywhere: true,
    allowSuperOutsideMethod: true,
    allowHashBang: true,
  });
}

let ast;
try {
  ast = parseWith("module");
} catch (e) {
  try {
    ast = parseWith("script");
  } catch (e2) {
    process.stderr.write("PARSE_FAIL: " + e2.message);
    process.exit(2);
  }
}

// JSON-safe: BigInt -> string, RegExp value -> null (the ESTree `regex` node is kept).
const out = JSON.stringify(ast, (k, v) => {
  if (typeof v === "bigint") return v.toString();
  if (v instanceof RegExp) return null;
  return v;
});
process.stdout.write(out);
