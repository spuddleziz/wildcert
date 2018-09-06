"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var request = require("request-promise");
var _ = require("lodash");
var utils_1 = require("./utils");
var Promise = require("bluebird");
var GoDaddyDNSPlugin = /** @class */ (function () {
    function GoDaddyDNSPlugin(config) {
        this._config = config;
        this._domainMap = {};
    }
    GoDaddyDNSPlugin.prototype.init = function () {
        var _this = this;
        this._domainMap = {};
        return getGoDaddyDomainsList({
            apiKey: this._config.apikey,
            secret: this._config.secret
        }).then(function (resp) {
            if (!resp || !Array.isArray(resp) || resp.length === 0) {
                return Promise.reject(new Error("No domains could be returned."));
            }
            //now build the domain map...
            resp.forEach(function (domItem) {
                //take the domain split it and populate the
                utils_1.putDomainInMap(_this._domainMap, domItem.domain);
            });
        });
    };
    GoDaddyDNSPlugin.prototype.get = function (args, domain, challenge, cb) {
    };
    GoDaddyDNSPlugin.prototype.remove = function (args, domain, challenge, cb) {
        var isRoot = false;
        var foundDomain = utils_1.getDomainAndNameFromMap(this._domainMap, domain);
        if (!foundDomain || !foundDomain.name || !foundDomain.domain) {
            return cb(new Error("The requested domain " + domain + " is not available in the godaddy instance configured"));
        }
        //console.log(args, domain, challenge)
        console.log("Looking for " + domain + " and found " + foundDomain.name + " with domain " + foundDomain.domain);
        var acmePath = "";
        if (foundDomain.name === foundDomain.domain) {
            acmePath = utils_1.ACME_RECORD_PREFIX;
            isRoot = true;
        }
        else {
            acmePath = utils_1.ACME_RECORD_PREFIX + "." + foundDomain.name;
        }
        this.removeRecord(foundDomain.domain, "TXT", acmePath).then(function (resp) {
            //do something with response?
        }).then(function () {
            cb(null);
        }).catch(function (ex) {
            cb(ex);
        });
    };
    GoDaddyDNSPlugin.prototype.set = function (args, domain, challenge, keyAuthorisation, cb) {
        //get base domain...
        var _this = this;
        var isRoot = false;
        var foundDomain = utils_1.getDomainAndNameFromMap(this._domainMap, domain);
        if (!foundDomain || !foundDomain.name || !foundDomain.domain) {
            return cb(new Error("The requested domain " + domain + " is not available in the godaddy instance configured"));
        }
        //console.log(args, domain, challenge)
        console.log("Looking for " + domain + " and found " + foundDomain.name + " with domain " + foundDomain.domain);
        var acmePath = "";
        if (foundDomain.name === foundDomain.domain) {
            acmePath = utils_1.ACME_RECORD_PREFIX;
            isRoot = true;
        }
        else {
            acmePath = utils_1.ACME_RECORD_PREFIX + "." + foundDomain.name;
        }
        //build the digest auth key
        var keyAuthDigest = utils_1.makeChallengeKeyAuthDigest(keyAuthorisation);
        getGoDaddyNSForDomain({
            apiKey: this._config.apikey,
            secret: this._config.secret,
            domain: foundDomain.domain,
            name: (isRoot === true ? "@" : foundDomain.name)
        }).then(function (nameservers) {
            return _this.setRecord(foundDomain.domain, "TXT", acmePath, keyAuthDigest, 600).then(function () {
                console.log("Record set. Waiting 5 seconds before checking propagation");
                return Promise.delay(5000);
            }).then(function () {
                if (!nameservers || !Array.isArray(nameservers) || nameservers.length === 0) {
                    console.log("Cant find Authoritative Nameservers so waiting for the default timeout.");
                    return Promise.delay(10 * 60 * 1000);
                }
                //lets resolve the nameserver addresses
                var nsList = _.map(nameservers, "data");
                return utils_1.lookupIPs(nsList).then(function (nsIPs) {
                    if (!nsIPs || !Array.isArray(nsIPs) || nsIPs.length === 0) {
                        console.log("Cant lookup IPs of Authoritative Nameservers so waiting for the default timeout.");
                        return Promise.delay(10 * 60 * 1000);
                    }
                    console.log("Waiting for DNS Propagation using authoritative nameservers: " + nsIPs.join(", "));
                    return utils_1.checkAuthoritativeServerDNSRecord(nsIPs, "TXT", acmePath + "." + foundDomain.domain, keyAuthDigest, 10 * 60 * 1000);
                });
            }).then(function () {
                console.log("DNS Propagated waiting a further 5 seconds before proceeding.");
                return Promise.delay(5000).then(function () {
                    cb(null);
                });
            }).catch(function (ex) {
                cb(ex);
            });
        });
    };
    GoDaddyDNSPlugin.prototype.setIPv4 = function (host, ips) {
        var foundDomain = utils_1.getDomainAndNameFromMap(this._domainMap, host);
        if (!foundDomain || !foundDomain.name || !foundDomain.domain) {
            return Promise.reject(new Error("The requested domain " + host + " is not available in the godaddy instance configured"));
        }
        //console.log(args, domain, challenge)
        console.log("Looking for " + host + " and found " + foundDomain.name + " with domain " + foundDomain.domain);
        if (foundDomain.name === foundDomain.domain) {
            foundDomain.name = "@";
        }
        return setMultipleGoDaddyRecords({
            apiKey: this._config.apikey,
            secret: this._config.secret,
            domain: foundDomain.domain,
            name: foundDomain.name,
            values: ips,
            type: "A",
            ttl: 600
        });
    };
    GoDaddyDNSPlugin.prototype.setIPv6 = function (host, ips) {
        var foundDomain = utils_1.getDomainAndNameFromMap(this._domainMap, host);
        if (!foundDomain || !foundDomain.name || !foundDomain.domain) {
            return Promise.reject(new Error("The requested domain " + host + " is not available in the godaddy instance configured"));
        }
        //console.log(args, domain, challenge)
        console.log("Looking for " + host + " and found " + foundDomain.name + " with domain " + foundDomain.domain);
        if (foundDomain.name === foundDomain.domain) {
            foundDomain.name = "@";
        }
        return setMultipleGoDaddyRecords({
            apiKey: this._config.apikey,
            secret: this._config.secret,
            domain: foundDomain.domain,
            name: foundDomain.name,
            values: ips,
            type: "AAAA",
            ttl: 600
        });
    };
    GoDaddyDNSPlugin.prototype.removeRecord = function (domain, type, name) {
        console.log("Removing Record " + name + " of type " + type + " from domain " + domain);
        return removeGoDaddyRecord({
            apiKey: this._config.apikey,
            secret: this._config.secret,
            domain: domain,
            name: name,
            type: type,
        });
    };
    GoDaddyDNSPlugin.prototype.setRecord = function (domain, type, name, value, ttl) {
        console.log("Setting Record " + name + " of type " + type + " in domain " + domain + " with a value of " + value + " and ttl " + ttl);
        return setGoDaddyRecord({
            apiKey: this._config.apikey,
            secret: this._config.secret,
            domain: domain,
            name: name,
            value: value,
            type: type,
            ttl: ttl
        });
    };
    GoDaddyDNSPlugin.prototype.getRecord = function (domain, type, name) {
        console.log("Getting Record " + name + " of type " + type + " from domain " + domain);
        return getGoDaddyRecord({
            apiKey: this._config.apikey,
            secret: this._config.secret,
            domain: domain,
            name: name,
            type: type,
        });
    };
    GoDaddyDNSPlugin.prototype.getOptions = function () {
        return this._config;
    };
    return GoDaddyDNSPlugin;
}());
exports.default = GoDaddyDNSPlugin;
function getGoDaddyDomainsList(req) {
    var options = {
        method: 'GET',
        url: "https://api.godaddy.com/v1/domains",
        headers: {
            'authorization': "sso-key " + req.apiKey + ":" + req.secret,
            'content-type': 'application/json'
        },
        json: true
    };
    return Promise.resolve(request(options));
}
function setMultipleGoDaddyRecords(req) {
    if (!utils_1.validateDNSRecordType(req.type))
        return Promise.reject(new Error("Supplied record type " + req.type + " is invalid."));
    if (!req.values || !Array.isArray(req.values) || req.values.length === 0) {
        return Promise.reject(new Error("To set multiple values for a specified domain please pass an array of values using the values key."));
    }
    var data = [];
    req.values.forEach(function (val) {
        data.push({ type: req.type, name: req.name, ttl: req.ttl, data: val });
    });
    var options = {
        method: 'PUT',
        url: "https://api.godaddy.com/v1/domains/" + req.domain + "/records/" + req.type + "/" + req.name.replace('@', '%40'),
        headers: {
            'authorization': "sso-key " + req.apiKey + ":" + req.secret,
            'content-type': 'application/json'
        },
        body: data,
        json: true
    };
    return Promise.resolve(request(options));
}
function setGoDaddyRecord(req) {
    if (!utils_1.validateDNSRecordType(req.type))
        return Promise.reject(new Error("Supplied record type " + req.type + " is invalid."));
    var options = {
        method: 'PUT',
        url: "https://api.godaddy.com/v1/domains/" + req.domain + "/records/" + req.type + "/" + req.name.replace('@', '%40'),
        headers: {
            'authorization': "sso-key " + req.apiKey + ":" + req.secret,
            'content-type': 'application/json'
        },
        body: [{ type: req.type, name: req.name, ttl: req.ttl, data: req.value }],
        json: true
    };
    return Promise.resolve(request(options));
}
function removeGoDaddyRecord(req) {
    if (!utils_1.validateDNSRecordType(req.type))
        return Promise.reject(new Error("Supplied record type " + req.type + " is invalid."));
    var options = {
        method: 'DELETE',
        url: "https://api.godaddy.com/v1/domains/" + req.domain + "/records/" + req.type + "/" + req.name.replace('@', '%40'),
        headers: {
            'authorization': "sso-key " + req.apiKey + ":" + req.secret,
            'content-type': 'application/json'
        },
        json: true
    };
    return Promise.resolve(request(options));
}
function getGoDaddyRecord(req) {
    if (!utils_1.validateDNSRecordType(req.type))
        return Promise.reject(new Error("Supplied record type " + req.type + " is invalid."));
    var options = {
        method: 'GET',
        url: "https://api.godaddy.com/v1/domains/" + req.domain + "/records/" + req.type + "/" + req.name.replace('@', '%40'),
        headers: {
            'authorization': "sso-key " + req.apiKey + ":" + req.secret,
            'content-type': 'application/json'
        },
        json: true
    };
    return Promise.resolve(request(options));
}
function getGoDaddyNSForDomain(req) {
    var options = {
        method: 'GET',
        url: "https://api.godaddy.com/v1/domains/" + req.domain + "/records/NS/" + req.name.replace('@', '%40'),
        headers: {
            'authorization': "sso-key " + req.apiKey + ":" + req.secret,
            'content-type': 'application/json'
        },
        json: true
    };
    return Promise.resolve(request(options));
}
//# sourceMappingURL=godaddy.js.map