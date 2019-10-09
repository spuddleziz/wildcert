"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
require('source-map-support').install({
    handleUncaughtExceptions: false
});
var Promise = require("bluebird");
var Greenlock = require("greenlock");
var _ = require("lodash");
var Wildcert = /** @class */ (function () {
    function Wildcert(config) {
        this._dnsPluginEnabled = false;
        this._serverPluginEnabled = false;
        this._config = config;
    }
    Wildcert.prototype.run = function () {
        var _this = this;
        return Promise.all([
            this.prepareDNSPlugin(),
            this.prepareServerPlugin()
        ]).then(function () {
            return _this.prepareAndCreateGreenlock();
        }).then(function () {
            return _this.checkCurrentCertificates();
        }).then(function (doRequests) {
            if (!doRequests) {
                console.log("Not renewing/registering certificates as they haven't expired yet.");
                return false;
            }
            return _this.doCertificateRequests();
        });
    };
    Wildcert.prototype.prepareServerPlugin = function () {
        var serverConf = this._config.getServerConfig();
        if (!serverConf)
            return Promise.resolve();
        try {
            var plugin = require("./server_plugins/" + serverConf.plugin);
            if (plugin && typeof plugin === "function") {
                plugin = {
                    "default": plugin
                };
            }
            if (!plugin || !plugin.hasOwnProperty("default")) {
                return Promise.reject(new Error("The requested Server plugin " + serverConf.plugin + " doesn't exist or is in the incorrect format."));
            }
            else {
                //lets try load it
                var pluginInstance = new plugin.default(serverConf.config);
                if (!pluginInstance || !pluginInstance.run || typeof pluginInstance.run !== "function") {
                    return Promise.reject(new Error("The requested Server plugin " + serverConf.plugin + " doesn't exist or is in the incorrect format."));
                }
                this._serverPluginInstance = pluginInstance;
                this._serverPluginEnabled = true;
                console.log("Server Plugin now ready");
                if (pluginInstance.init && typeof pluginInstance.init === "function") {
                    return pluginInstance.init();
                }
                return Promise.resolve();
            }
        }
        catch (ex) {
            return Promise.reject(ex);
        }
    };
    Wildcert.prototype.prepareDNSPlugin = function () {
        var _this = this;
        var dnsConf = this._config.getDNSConfig();
        if (!dnsConf)
            return Promise.resolve();
        //attempt to load the plugin...
        try {
            var plugin = require("./dns_plugins/" + dnsConf.plugin);
            if (plugin && typeof plugin === "function") {
                plugin = {
                    "default": plugin
                };
            }
            if (!plugin || !plugin.hasOwnProperty("default")) {
                return Promise.reject(new Error("The requested DNS plugin " + dnsConf.plugin + " doesn't exist or is in the incorrect format."));
            }
            else {
                //lets try load it
                var pluginInstance = new plugin.default(dnsConf.config);
                if (!pluginInstance || !pluginInstance.init || typeof pluginInstance.init !== "function") {
                    return Promise.reject(new Error("The requested DNS plugin " + dnsConf.plugin + " doesn't exist or is in the incorrect format."));
                }
                console.log("Valid plugin class");
                this._dnsPluginInstance = pluginInstance;
                this._dnsPluginEnabled = true;
                console.log("DNS Plugin ready.");
                return this._dnsPluginInstance.init().then(function () {
                    //if ip updates are enabled we need to immediately set the ip on all domains...
                    if (dnsConf.setIP === true) {
                        //lets go ahead and iterate the domains so we can set the IPs for them all...
                        var doIP4_1 = false;
                        var doIP6_1 = false;
                        if ((!dnsConf.ip4List && !dnsConf.ip6List) || (!Array.isArray(dnsConf.ip4List) && !Array.isArray(dnsConf.ip6List)) || (dnsConf.ip4List.length === 0 && dnsConf.ip6List.length === 0)) {
                            console.log("Cannot update ips for domains if no ips have been set, either V4 or V4. Continuing, but if using an HTTP-01 challenge this will liekyl fail if the A or AAAA records aren't pointing to this host.");
                            return;
                        }
                        if (dnsConf.ip4List && Array.isArray(dnsConf.ip4List) && dnsConf.ip4List.length > 0) {
                            doIP4_1 = true;
                        }
                        if (dnsConf.ip6List && Array.isArray(dnsConf.ip6List) && dnsConf.ip6List.length > 0) {
                            doIP6_1 = true;
                        }
                        return Promise.each(_this._config.getDomains(), function (domain) {
                            console.log("Setting IP Addresses for domain " + domain);
                            if (doIP4_1 && doIP6_1) {
                                return Promise.all([
                                    _this._dnsPluginInstance.setIPv4(domain, dnsConf.ip4List),
                                    _this._dnsPluginInstance.setIPv6(domain, dnsConf.ip6List)
                                ]);
                            }
                            else if (doIP6_1) {
                                return _this._dnsPluginInstance.setIPv6(domain, dnsConf.ip6List);
                            }
                            else {
                                return _this._dnsPluginInstance.setIPv4(domain, dnsConf.ip4List);
                            }
                        });
                    }
                    return;
                });
            }
        }
        catch (ex) {
            return Promise.reject(ex);
        }
    };
    Wildcert.prototype.prepareAndCreateGreenlock = function () {
        var _this = this;
        return Promise.resolve().then(function () {
            return _this.buildGreenlockObject();
        }).then(function () {
            console.log("Creating Greenlock Instance");
            _this._greenlockInstance = Greenlock.create(_this._greenlockObject);
            return true;
        });
    };
    Wildcert.prototype.buildGreenlockObject = function () {
        //load the required store plugin...
        this._greenlockObject = this._config.getGreenlockObject();
        console.log("Loading Greenlock Store Plugin " + this._greenlockObject.store.plugin);
        this._storePluginInstance = loadPluginWithConfig(this._greenlockObject.store.plugin, this._greenlockObject.store.config);
        this._greenlockObject.store = this._storePluginInstance;
        //now load the challenge plugins...
        for (var challengeTypeKey in this._greenlockObject.challenges) {
            if (!this._greenlockObject.challenges.hasOwnProperty(challengeTypeKey))
                continue;
            switch (challengeTypeKey) {
                case "dns-01":
                    //dns is a special case - if this is set to "wildcert" then internally we do the challenge auth method as we will be manually updating DNS as required otherwise its a standard approach
                    if (typeof this._greenlockObject.challenges[challengeTypeKey] === "string" && this._greenlockObject.challenges[challengeTypeKey] === "wildcert") {
                        //if using the internal wildcert method and there is no dns config section then we need to throw here...
                        if (!this._dnsPluginEnabled) {
                            throw new Error("If using the internal wildcert DNS challenge method the \"dns\" section must be configured in the config");
                        }
                        this._greenlockObject.challenges[challengeTypeKey] = this._dnsPluginInstance;
                    }
                    else {
                        this._greenlockObject.challenges[challengeTypeKey] = loadPluginWithConfig(this._greenlockObject.challenges[challengeTypeKey].plugin, this._greenlockObject.challenges[challengeTypeKey].config);
                    }
                    break;
                case "http-01":
                    this._greenlockObject.challenges[challengeTypeKey] = loadPluginWithConfig(this._greenlockObject.challenges[challengeTypeKey].plugin, this._greenlockObject.challenges[challengeTypeKey].config);
                    break;
                case "tls-sni-01":
                    this._greenlockObject.challenges[challengeTypeKey] = loadPluginWithConfig(this._greenlockObject.challenges[challengeTypeKey].plugin, this._greenlockObject.challenges[challengeTypeKey].config);
                    break;
                default:
                    throw new Error("The configured challenge method " + challengeTypeKey + " is not supported");
            }
        }
        return true;
    };
    Wildcert.prototype.doCertificateRequests = function () {
        var _this = this;
        return Promise.resolve().then(function () {
            return _this._greenlockInstance.register({
                domains: _this._config.getDomains(),
                email: _this._config.getEmail(),
                agreeTos: true,
                challengeType: "dns-01"
            }).then(function (cert) {
                console.log("Domain Certificate Registration Process Complete.");
                if (_this._serverPluginEnabled === true) {
                    console.log("Running Server Plugin Now.");
                    return _this._serverPluginInstance.run(cert);
                }
                return;
            }).catch(function (ex) {
                //console.error(ex);
            });
        });
    };
    Wildcert.prototype.checkCurrentCertificates = function () {
        var _this = this;
        return Promise.resolve().then(function () {
            var domainList = _this._config.getDomains();
            return _this._greenlockInstance.check({ domains: domainList }).then(function (results) {
                if (results) {
                    var doRegister_1 = false;
                    if (Array.isArray(results) && results.length > 0) {
                        return Promise.each(results, function (result) {
                            if (checkCertificateExpiry(result, _this._config.getRenewWithin(), domainList) === true) {
                                doRegister_1 = true;
                            }
                        }).then(function () {
                            return doRegister_1;
                        });
                    }
                    else {
                        return checkCertificateExpiry(results, _this._config.getRenewWithin(), domainList);
                    }
                }
                return true;
            });
        });
    };
    return Wildcert;
}());
exports.Wildcert = Wildcert;
function checkCertificateExpiry(certResult, renewWithin, reqDomains) {
    if (certResult && certResult.hasOwnProperty("altnames") && Array.isArray(certResult.altnames) && !_.isEqual(certResult.altnames.sort(), reqDomains.sort())) {
        console.log("The domains included in the certificate have changed so a new certificate will need to be requested. Have: [" + certResult.altnames.sort().join(", ") + "] | Requesting: [" + reqDomains.sort().join(", ") + "]");
        return true;
    }
    else if (certResult && certResult.hasOwnProperty("expiresAt") && certResult.expiresAt - renewWithin >= new Date().getTime()) {
        var renewalCountdown = ((certResult.expiresAt - renewWithin - new Date().getTime()) / 1000 / 60 / 60 / 24).toFixed(0);
        console.log("Certificate due for rewnewal in " + renewalCountdown + " days. Expiry Date: " + new Date(certResult.expiresAt));
        return false;
    }
    return true;
}
function loadPluginWithConfig(plugin, config) {
    return require(plugin).create(config);
}
//# sourceMappingURL=Wildcert.js.map