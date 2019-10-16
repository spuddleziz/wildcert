"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var request = require('request-promise');
var _ = require("lodash");
var utils_1 = require("./utils");
var Promise = require("bluebird");
function cleanupOvh(inputRecords, ips, subDomain) {
    var removeMap = {};
    var createArr = [];
    var existsMap = {};
    inputRecords.forEach(function (item) {
        var target = item.subdomain + "::" + item.target;
        if (!existsMap.hasOwnProperty(target)) {
            existsMap[target] = { id: item.id, target: item.target };
        }
        else {
            removeMap["" + item.id] = true;
        }
    });
    ips.forEach(function (ip) {
        var target = subDomain + "::" + ip;
        if (!existsMap.hasOwnProperty(target)) {
            existsMap[target] = { id: 0, target: ip };
            createArr.push({ subDomain: subDomain, target: ip });
        }
        else {
            if (existsMap[target].target === ip) {
                //the ip is already correctly set - no action needed
            }
            else {
                removeMap["" + existsMap[target].id] = true;
                createArr.push({ subDomain: subDomain, target: ip });
            }
        }
    });
    //ids to remove:
    var idsToRemove = Object.keys(removeMap);
    return {
        idsToRemove: idsToRemove,
        createArr: createArr
    };
}
var OVHDNSPlugin = /** @class */ (function () {
    function OVHDNSPlugin(config) {
        var _consumerKey = null;
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
        var _this = this;
        var foundDomain = utils_1.getDomainAndNameFromMap(this._domainMap, domain);
        if (!foundDomain || !foundDomain.domain || !foundDomain.name) {
            return cb(new Error("The requested domain " + domain + " is not available in the ovh instance configured"));
        }
        console.log("Looking for " + domain + " and found " + foundDomain.name + " with domain " + foundDomain.domain);
        //Required for greenlock to properly issue the certificate
        args.challenge.isWildcard = foundDomain.isWildcard ? true : false;
        args.acmePrefix = foundDomain.acmePath + "." + foundDomain.domain;
        var keyAuthDigest = utils_1.makeChallengeKeyAuthDigest(keyAuthorisation);
        return this.setRecord(foundDomain.domain, "TXT", foundDomain.acmePath, keyAuthDigest, 600)
            .then(function () {
            //We need to makesure the TXT record has populated
            //To do this, we need to find the authorative NS for the domain
            //This could be sub.sub.domain.tld, sub.domain.tld etc
            console.log("[ovh] Query for NS records");
            var domComps = domain.split('.');
            var minDomLen = domComps.length - 2; //Make sure we don't query for anything below domain.tld
            var subdomainQueryArr = [];
            for (var i = 0; i <= minDomLen; i++) {
                //For OVH,we need to query the domain using the domain separate from the sub
                //Therefore, this creates a list of subdomain components, e.g. "blah.sub", "blah" and "" (denoting @)
                subdomainQueryArr.push(domComps.slice(i, minDomLen - i).join('.'));
            }
            return new Promise(function (outerRes, outerRej) {
                var found = false;
                Promise.each(subdomainQueryArr, function (curSubdomain) {
                    if (found)
                        return; //Flow control, ignore anything but the first found NS result which will be best authorative
                    else {
                        return _this.getRecord(foundDomain.domain, "NS", curSubdomain)
                            .then(function (records) {
                            console.log("[ovh] Info: Queried \"" + curSubdomain + "\" on " + foundDomain.domain + " and found", records);
                            found = true; //No more queries
                            outerRes(records);
                        })
                            .catch(function (err) {
                            if (err == undefined) {
                                console.log("[ovh] Info: Queried \"" + curSubdomain + "\" on " + foundDomain.domain + " and received an (expected) empty response");
                            }
                            else {
                                console.log("[ovh] Unexpected format encountered during auth NS search", err);
                            }
                            return; //Don't require catch, kind of expected
                        });
                    }
                });
            })
                .then(function (records) {
                var nsHostnames = _.map(records, "target");
                return utils_1.lookupIPs(nsHostnames).then(function (nsIPs) {
                    //Make sure the auth NS has the expected challenge
                    var uniqueNSIPs = [];
                    nsIPs.map(function (ip) {
                        if (!uniqueNSIPs.includes(ip))
                            uniqueNSIPs.push(ip);
                    });
                    console.log("[ovh] Found unique NS IPs", uniqueNSIPs);
                    return utils_1.checkAuthoritativeServerDNSRecord(uniqueNSIPs, "TXT", foundDomain.acmePath + "." + foundDomain.domain, keyAuthDigest, 10 * 60 * 1000);
                });
            })
                .catch(function (error) {
                console.log("[ovh] An error occurred while resolving auth ns", error);
                return;
            });
        })
            .then(function () {
            console.log("[ovh] Authed ns has the expected records, waiting 5 seconds");
            return Promise.delay(5000).then(function () {
                console.log("[ovh] Sending callback");
                cb(null);
            });
        })
            .catch(function (err) {
            console.log("[ovh] Couldn't find the expected TXT record");
            cb(err);
        });
    };
    OVHDNSPlugin.prototype.get = function (args, domain, challenge, cb) {
        //Empty on the godaddy plugin
    };
    OVHDNSPlugin.prototype.remove = function (args, domain, challenge, cb) {
        console.log("Removing record from " + domain + " on OVH");
        var foundDomain = utils_1.getDomainAndNameFromMap(this._domainMap, domain);
        if (!foundDomain || !foundDomain.name || !foundDomain.domain) {
            return cb(new Error("[ovh] The requested domain " + domain + " is not available in the OVH instance configured"));
        }
        //Required for greenlock to properly issue the certificate
        args.challenge.isWildcard = foundDomain.isWildcard ? true : false;
        args.acmePrefix = foundDomain.acmePath + "." + foundDomain.domain;
        this.removeRecord(domain, "TXT", foundDomain.acmePath)
            .then(function () { return cb(); })
            .catch(function (err) { return cb(new Error("[ovh]" + err)); });
    };
    OVHDNSPlugin.prototype.setIPv4 = function (host, ips) {
        var _this = this;
        console.log("[ovh] Setting IPv4 addresses");
        var foundDomain = utils_1.getDomainAndNameFromMap(this._domainMap, host);
        if (!foundDomain || !foundDomain.name || !foundDomain.domain) {
            console.log("[ovh] The requested domain is not available");
            return Promise.reject(new Error("The requested domain " + host + " is not available in the OVH instance configured"));
        }
        console.log("Looking for " + host + " and found " + foundDomain.name + " with domain " + foundDomain.domain);
        var subsToCreate = [];
        if (foundDomain.isRoot) {
            subsToCreate.push(""); //Root on OVH is just ""
            if (foundDomain.isWildcard)
                subsToCreate.push("*");
        }
        else {
            subsToCreate.push(foundDomain.name);
        }
        return Promise.all(subsToCreate.map(function (sub) {
            return _this.getRecord(foundDomain.domain, "A", sub)
                .then(function (records) {
                var todo = cleanupOvh(records, ips, sub);
                return _this.removeRecordsByID(todo.idsToRemove, foundDomain.domain).then(function () {
                    return Promise.all(todo.createArr.map(function (item) {
                        return _this.setRecord(foundDomain.domain, "A", item.subDomain, item.target, 600);
                    }));
                });
            })
                .catch(function (e) {
                console.log(e);
                return Promise.reject(new Error("[ovh] An error occurred while cleaning up records for " + sub + " on " + foundDomain.domain));
            });
        }));
    };
    OVHDNSPlugin.prototype.setIPv6 = function (host, ips) {
        var _this = this;
        var foundDomain = utils_1.getDomainAndNameFromMap(this._domainMap, host);
        if (!foundDomain || !foundDomain.name || !foundDomain.domain) {
            return Promise.reject(new Error("The requested domain " + host + " is not available in the godaddy instance configured"));
        }
        console.log("Looking for " + host + " and found " + foundDomain.name + " with domain " + foundDomain.domain);
        var subsToCreate = [];
        if (foundDomain.isRoot) {
            subsToCreate.push(""); //Root on OVH is just ""
            if (foundDomain.isWildcard)
                subsToCreate.push("*");
        }
        else {
            subsToCreate.push(foundDomain.name);
        }
        return Promise.all(subsToCreate.map(function (sub) {
            return _this.getRecord(foundDomain.domain, "AAAA", sub)
                .then(function (records) {
                var todo = cleanupOvh(records, ips, sub);
                return _this.removeRecordsByID(todo.idsToRemove, foundDomain.domain).then(function () {
                    return Promise.all(todo.createArr.map(function (item) {
                        return _this.setRecord(foundDomain.domain, "AAAA", item.subDomain, item.target, 600);
                    }));
                });
            })
                .catch(function (e) {
                console.log(e);
                return Promise.reject(new Error("[ovh] An error occurred while cleaning up records for " + sub + " on " + foundDomain.domain));
            });
        }));
    };
    OVHDNSPlugin.prototype.setRecord = function (domain, type, name, value, ttl) {
        var _this = this;
        if (name == domain)
            name = ""; //The root domain. This is required because OVH expects root domain records to have a blank name
        console.log("[ovh] Adding a new " + type + " record for " + domain + " with the name " + name + " with destination " + value + " and TTL " + ttl);
        return this._ovh.requestPromised('POST', "/domain/zone/" + domain + "/record", {
            fieldType: type,
            subDomain: name,
            target: value,
            ttl: ttl
        })
            .catch(function (err) {
            return Promise.reject("[ovh] Error: " + err.message);
        })
            .then(function (record) {
            console.log("[ovh] Made DNS change");
            //Refresh call just applies the edited zone, returns void
            return _this.applyDNSChanges(domain);
        });
    };
    OVHDNSPlugin.prototype.getRecord = function (domain, type, name) {
        var _this = this;
        return this._ovh.requestPromised('GET', "/domain/zone/" + domain + "/record", {
            fieldType: type,
            subDomain: name
        })
            .then(function (idlist) {
            switch (idlist.length) {
                case 1: return _this._ovh.requestPromised('GET', "/domain/zone/" + domain + "/record/" + idlist[0])
                    .then(function (record) {
                    return [record];
                });
                case 0: return Promise.reject("[ovh] " + type + " record named " + name + " is not listed on " + domain);
                default:
                    return Promise.all(idlist.map(function (id) { return _this._ovh.requestPromised('GET', "/domain/zone/" + domain + "/record/" + id); }))
                        .then(function (results) {
                        console.log("[ovh] Qeried zone record ids " + idlist + " and received", results);
                        return results;
                    });
                    return;
            }
        })
            .catch(function (err) {
            console.log(err);
            return Promise.reject("[ovh] Error while getting DNS Zone " + err.message);
        });
    };
    OVHDNSPlugin.prototype.removeRecordsByID = function (ids, domain) {
        var _this = this;
        var promArr = ids.map(function (id) {
            return _this.removeRecordByID.call(_this, parseInt(id), domain);
        });
        return Promise.all(promArr);
    };
    OVHDNSPlugin.prototype.removeRecordByID = function (id, domain) {
        var _this = this;
        return this._ovh.requestPromised('DELETE', "/domain/zone/" + domain + "/record/" + id)
            .then(function () {
            console.log("[ovh] Removed " + id + " record from " + domain);
            return _this.applyDNSChanges;
        })
            .catch(function (err) {
            return Promise.reject("[ovh] Error: Failed to delete record ID " + id + " from zone " + domain);
        });
    };
    OVHDNSPlugin.prototype.removeRecord = function (domain, type, name) {
        var _this = this;
        return this.getRecord(domain, type, name)
            .then(function (records) {
            switch (records.length) {
                case 1:
                    var record_1 = records[0];
                    return _this._ovh.requestPromise('DELETE', "/domain/zone/" + record_1.zone + "/record/" + record_1.id)
                        .then(function () {
                        console.log("[ovh] Removed " + name + " " + type + " record from " + domain);
                        return _this.applyDNSChanges;
                    })
                        .catch(function (err) {
                        return Promise.reject("[ovh] Error: Failed to delete record ID " + record_1.id + " from zone " + record_1.zone);
                    });
                case 0:
                    return Promise.reject("[ovh] Couldn't find " + type + " record with name " + name + " on " + domain);
                default:
                    return Promise.reject("[ovh] Multiple " + type + " records of name " + name + " marked for deletion on " + domain + ", unsupported");
            }
        });
    };
    OVHDNSPlugin.prototype.applyDNSChanges = function (domain) {
        return this._ovh.requestPromised('POST', "/domain/zone/" + domain + "/refresh")
            .then(function (res) {
            console.log("[ovh] DNS changes saved");
            return;
        })
            .catch(function (err) {
            return Promise.reject("[ovh] Error: " + err.message);
        });
    };
    return OVHDNSPlugin;
}());
exports.default = OVHDNSPlugin;
//# sourceMappingURL=ovh.js.map