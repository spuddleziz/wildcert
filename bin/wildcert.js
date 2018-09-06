#!/usr/bin/env node
require('source-map-support').install({
  handleUncaughtExceptions: false
});
const filepath = require("path");
const WCLI = require(filepath.resolve(filepath.join(__dirname, "..", "build", "CLI.js"))).WildcertCLI;

WCLI.run();
