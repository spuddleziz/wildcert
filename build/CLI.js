"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
require('source-map-support').install({
    handleUncaughtExceptions: false
});
var program = require("commander");
var Wildcert_1 = require("./Wildcert");
var WildcertConfig_1 = require("./WildcertConfig");
//the wildcert cli class is the entry point for the command line interface and will process the supplied options...
var WildcertCLI = /** @class */ (function () {
    function WildcertCLI() {
    }
    WildcertCLI.run = function () {
        console.log("Running Wildcert CLI");
        program
            .arguments("<config_file>")
            .action(WildcertCLI.runWildcert)
            .parse(process.argv);
    };
    WildcertCLI.runWildcert = function (configfile) {
        console.log("Loading Wildcert Config File: " + configfile);
        var wc = new Wildcert_1.Wildcert(WildcertConfig_1.WildcertConfig.ConfigFromFile(configfile));
        wc.run();
    };
    return WildcertCLI;
}());
exports.WildcertCLI = WildcertCLI;
//# sourceMappingURL=CLI.js.map