// Builds the browser copy of the zkPassport SDK and vendors the QR code library
// into static/js, the same way openpgp.min.js is vendored. Run from verifier/:
//   npm run build:browser
const fs = require("node:fs")
const path = require("node:path")
const esbuild = require("esbuild")

const out = path.join(__dirname, "..", "..", "static", "js")
const modules = path.join(__dirname, "..", "node_modules")
const version = (name) => JSON.parse(fs.readFileSync(path.join(modules, name, "package.json"), "utf8")).version

// The SDK loads its proving libraries lazily inside verify(), which the
// browser never calls, so they are replaced with an empty module. This keeps
// the bundle at about 1.6 MB instead of 17 MB.
const stubProvers = {
  name: "stub-provers",
  setup(build) {
    build.onResolve({ filter: /^@aztec\/bb\.js(-v4)?$|^@noir-lang\/noir_js$/ }, () => ({ path: "stub", namespace: "stub" }))
    build.onLoad({ filter: /.*/, namespace: "stub" }, () => ({ contents: "export default {}", loader: "js" }))
  },
}

async function main() {
  const sdkVersion = version("@zkpassport/sdk")
  await esbuild.build({
    stdin: { contents: 'import { ZKPassport } from "@zkpassport/sdk"; window.ZKPassport = ZKPassport;', resolveDir: path.join(__dirname, "..") },
    bundle: true,
    minify: true,
    platform: "browser",
    format: "iife",
    target: ["es2020"],
    plugins: [stubProvers],
    banner: { js: `/* @zkpassport/sdk ${sdkVersion}, built by verifier/scripts/build-browser-sdk.js with the proving libraries stubbed out. Do not edit; rebuild instead. */` },
    outfile: path.join(out, "zkpassport-sdk.min.js"),
  })

  const qrVersion = version("qrcode-generator")
  const qr = fs.readFileSync(path.join(modules, "qrcode-generator", "dist", "qrcode.js"), "utf8")
  fs.writeFileSync(path.join(out, "qrcode.min.js"), `/* qrcode-generator ${qrVersion}, copied by verifier/scripts/build-browser-sdk.js. */\n${qr}`)

  for (const file of ["zkpassport-sdk.min.js", "qrcode.min.js"]) {
    console.log(file, (fs.statSync(path.join(out, file)).size / 1024).toFixed(0), "KB")
  }
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
