"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var Promise = require("bluebird");
var dns_1 = require("dns");
exports.ACME_RECORD_PREFIX = "_acme-challenge";
function makeChallengeKeyAuthDigest(keyAuthorisation) {
    return require('crypto').createHash('sha256').update(keyAuthorisation || '').digest('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/g, '');
}
exports.makeChallengeKeyAuthDigest = makeChallengeKeyAuthDigest;
function validateDNSRecordType(type) {
    switch (type) {
        case "A":
        case "AAAA":
        case "TXT":
        case "SRV":
        case "CNAME":
            return true;
        default:
            return false;
    }
}
exports.validateDNSRecordType = validateDNSRecordType;
function reverseDomain(domain) {
    return domain.split(".").reverse().join(".");
}
exports.reverseDomain = reverseDomain;
function putDomainInMap(domainMap, domainToAdd) {
    var rdom = reverseDomain(domainToAdd);
    domainMap[rdom] = domainToAdd;
}
exports.putDomainInMap = putDomainInMap;
function getDomainAndNameFromMap(domainMap, requestDomain) {
    //recursively step up the domain and look in the map for it...
    var builtDom = "";
    var domSplit = requestDomain.split(".");
    var domSplitLen = domSplit.length - 1;
    var picked = null;
    for (var i = domSplitLen; i >= 0; i--) {
        builtDom += (i < domSplitLen ? "." : "") + domSplit[i];
        picked = domainMap[builtDom];
        if (picked && typeof picked === "string") {
            picked = picked.toLowerCase();
            requestDomain = requestDomain.toLowerCase();
            var isRoot = false;
            var name_1 = "";
            if (picked === requestDomain) {
                isRoot = true;
            }
            else {
                name_1 = requestDomain.replace("." + picked, "");
            }
            return getAcmePathForDomain({
                domain: picked,
                name: name_1,
                isRoot: isRoot,
                acmePath: "",
                isWildcard: false
            }, requestDomain);
        }
    }
    return null;
}
exports.getDomainAndNameFromMap = getDomainAndNameFromMap;
function getAcmePathForDomain(foundDomain, requestDomain) {
    if (foundDomain.isRoot && (!foundDomain.name || foundDomain.name === "")) {
        foundDomain.acmePath = exports.ACME_RECORD_PREFIX;
    }
    else {
        //handle the wildcard...
        if (foundDomain.name[0] === "*") {
            if (foundDomain.name.length > 1 && foundDomain.name[1] === ".") {
                //fine
                foundDomain.isWildcard = true;
                foundDomain.acmePath = exports.ACME_RECORD_PREFIX + "." + foundDomain.name.slice(2);
            }
            else if (foundDomain.name.length === 1) {
                //fine
                foundDomain.isWildcard = true;
                foundDomain.acmePath = exports.ACME_RECORD_PREFIX;
                foundDomain.isRoot = true;
            }
            else {
                //throw
            }
        }
        else {
            //standard
            foundDomain.acmePath = exports.ACME_RECORD_PREFIX + "." + foundDomain.name;
        }
    }
    return foundDomain;
}
function processLoop(mainFn, compareFn, delay) {
    return new Promise(function (resolve, reject) {
        function next() {
            mainFn().then(function (val) {
                // add to result array
                if (compareFn(val)) {
                    // found a val < 100, so be done with the loop
                    resolve(val);
                }
                else {
                    // run another iteration of the loop after delay
                    if (delay) {
                        setTimeout(next, delay);
                    }
                    else {
                        next();
                    }
                }
            }, reject);
        }
        // start first iteration of the loop
        if (delay) {
            setTimeout(next, delay);
        }
        else {
            next();
        }
    });
}
function checkAuthoritativeServerDNSRecord(dnsServers, recordType, hostname, expectedValue, maxTimout) {
    //make a resolver
    var timeoutTime = new Date().getTime() + maxTimout;
    var dnsResolver = new dns_1.Resolver();
    return Promise.each(dnsServers, function (lookupServer) {
        console.log("Using NS " + lookupServer + " for propagation check");
        dnsResolver.setServers([lookupServer]);
        function doAsyncResolve(hostname, recordType) {
            return new Promise(function (resolve, reject) {
                console.log("Attempting to get record type " + recordType + " for " + hostname);
                dnsResolver.resolve(hostname, recordType, function (err, res) {
                    if (err) {
                        console.error("Error Doing NS Propagation check against " + lookupServer + ": " + err.message + ". Polling will continue until the TTL has expired.");
                        return [];
                    }
                    if (res && Array.isArray(res) && res.length > 0) {
                        //It's possible that there could have multiple records returned
                        for (var i = 0; i < res.length; i++) {
                            if (res[i] == expectedValue)
                                return resolve(res[i]);
                        }
                        return reject(new Error("Couldn't find expected value"));
                    }
                    return [];
                });
            });
        }
        return processLoop(function () {
            return doAsyncResolve(hostname, recordType);
        }, function (results) {
            //look at the results and see if the value is correct
            console.log("[resolver] Returned these values", results);
            if (new Date().getTime() >= timeoutTime) {
                console.log("Timeout occurred waiting for DNS values to match expected.");
                return true;
            }
            if (results && Array.isArray(results) && results.length > 0) {
                var resLen = results.length;
                var count = 0;
                for (var ind = 0; ind < resLen; ind++) {
                    if (results[ind] === expectedValue) {
                        count++;
                    }
                }
                if (count === resLen) {
                    console.log("DNS values match across the board " + count + " : " + resLen);
                    return true;
                }
            }
            return false;
        }, 5000);
    });
}
exports.checkAuthoritativeServerDNSRecord = checkAuthoritativeServerDNSRecord;
function lookupIPs(hostlist) {
    var dnsResolver = new dns_1.Resolver();
    function doAsyncResolve(hostname) {
        return new Promise(function (resolve, reject) {
            dnsResolver.resolve4(hostname, function (err, res) {
                if (err)
                    return reject(err);
                return resolve(res);
            });
        });
    }
    var iplist = [];
    return Promise.map(hostlist, function (item) {
        return doAsyncResolve(item).then(function (res) {
            iplist.push.apply(iplist, res);
            return true;
        });
    }).then(function () {
        return Promise.resolve(iplist);
    });
}
exports.lookupIPs = lookupIPs;
//# sourceMappingURL=utils.js.map