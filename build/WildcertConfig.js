"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var _ = require("lodash");
var ConfigValidator = require("./WildcertConfigValidators");
var fs = require("fs");
/*

Parse the selected config file or load sensible defaults


 */
var PRODUCTION_ACME_ADDRESS = "https://acme-v02.api.letsencrypt.org/directory";
var STAGING_ACME_ADDRESS = "https://acme-staging-v02.api.letsencrypt.org/directory";
function createDefaultOptions() {
    //create a single instance copy of the default options
    return {
        "expiryThreshold": 5,
        "greenlock": {
            "production": false,
            "rsaKeySize": 2048,
            "debug": false
        }
    };
}
var WildcertConfig = /** @class */ (function () {
    function WildcertConfig(inConfigObj) {
        //this._configObj = createDefaultOptions();
        //we have the default options lets now mix over the provided config data then we can verify each section as required
        //this._configObj = _.defaultsDeep(this._configObj, inConfigObj);
        this._configObj = ConfigValidator.Validate(inConfigObj);
    }
    WildcertConfig.ConfigFromOptions = function () {
    };
    WildcertConfig.ConfigFromFile = function (configPath) {
        if (fs.statSync(configPath).isFile()) {
            //try load and parse config...
            var loadedConf = fs.readFileSync(configPath, "utf8");
            var parsedConf = JSON.parse(loadedConf);
            return new WildcertConfig(parsedConf);
        }
        else {
            throw new Error("Specified config file path " + configPath + " is not a file.");
        }
    };
    WildcertConfig.prototype.getGreenlockObject = function () {
        //take the supplied config and turn it into a valid greenlock usable object...
        var robj = _.cloneDeep(this._configObj.greenlock);
        robj.version = "draft-12";
        if (robj.production === true) {
            console.log("Using production acme server");
            robj.server = PRODUCTION_ACME_ADDRESS;
        }
        else {
            console.log("Using staging acme server");
            robj.server = STAGING_ACME_ADDRESS;
        }
        delete robj.production;
        robj.skipDryRun = true;
        robj.skipChallengeTest = true;
        //now set the renewal points...
        robj.renewWithin = this.getRenewWithin();
        robj.renewBy = this.getRenewBy();
        robj.agreeToTerms = function (opts, agreeCb) {
            // opts = { email, domains, tosUrl }
            agreeCb(null, opts.tosUrl);
        };
        return robj;
    };
    WildcertConfig.prototype.getDNSConfig = function () {
        return this._configObj.dns;
    };
    WildcertConfig.prototype.getServerConfig = function () {
        return this._configObj.server;
    };
    WildcertConfig.prototype.getEmail = function () {
        return this._configObj.email;
    };
    WildcertConfig.prototype.getDomains = function () {
        return this._configObj.domains;
    };
    WildcertConfig.prototype.getRenewWithin = function () {
        return this._configObj.expiryThreshold * 2 * 24 * 60 * 60 * 1000;
    };
    WildcertConfig.prototype.getRenewBy = function () {
        return this._configObj.expiryThreshold * 24 * 60 * 60 * 1000;
    };
    return WildcertConfig;
}());
exports.WildcertConfig = WildcertConfig;
//# sourceMappingURL=WildcertConfig.js.map