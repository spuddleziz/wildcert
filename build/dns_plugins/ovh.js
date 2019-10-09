"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var utils_1 = require("./utils");
var OVHError = /** @class */ (function () {
    function OVHError() {
    }
    return OVHError;
}());
var OVHDNSPlugin = /** @class */ (function () {
    function OVHDNSPlugin(config) {
        this._config = config;
        this._ovh = require('ovh')({
            appKey: this._config.appKey,
            appSecret: this._config.appSecret,
            consumerKey: this._config.consumerKey,
            endpoint: this._config.endpoint
        });
        this._domainMap = {};
    }
    OVHDNSPlugin.prototype.init = function () {
        var _this = this;
        return this._ovh.requestPromised('GET', '/domain')
            .then(function (domains) {
            domains.forEach(function (element) {
                utils_1.putDomainInMap(_this._domainMap, element);
            });
        })
            .catch(function (error) {
            console.log("[ovh] Error: (" + error.error + ") " + error.message);
        });
    };
    OVHDNSPlugin.prototype.getOptions = function () {
        return this._config;
    };
    OVHDNSPlugin.prototype.set = function (args, domain, challenge, keyAuthorisation, cb) {
        var foundDomain = utils_1.getDomainAndNameFromMap(this._domainMap, domain);
        console.log("Found domain: " + foundDomain);
    };
    OVHDNSPlugin.prototype.get = function (args, domain, challenge, cb) {
    };
    OVHDNSPlugin.prototype.remove = function (args, domain, challenge, cb) {
        this._ovh.request('POST', '/domain', function (err, domains) {
            console.log(domains);
        });
    };
    OVHDNSPlugin.prototype.setIPv4 = function (host, ips) {
        return this._ovh.request('POST', '/domain', function (err, domains) {
            console.log(domains);
        });
    };
    OVHDNSPlugin.prototype.setIPv6 = function (host, ips) {
        return this._ovh.request('POST', '/domain', function (err, domains) {
            console.log(domains);
        });
    };
    OVHDNSPlugin.prototype.setRecord = function (domain, type, name, value, ttl) {
        return this._ovh.request('POST', '/domain', function (err, domains) {
            console.log(domains);
        });
    };
    OVHDNSPlugin.prototype.getRecord = function (domain, type, name) {
        return this._ovh.request('POST', '/domain', function (err, domains) {
            console.log(domains);
        });
    };
    OVHDNSPlugin.prototype.removeRecord = function (domain, type, name) {
        return this._ovh.request('POST', '/domain', function (err, domains) {
            console.log(domains);
        });
    };
    return OVHDNSPlugin;
}());
exports.default = OVHDNSPlugin;
//# sourceMappingURL=ovh.js.map