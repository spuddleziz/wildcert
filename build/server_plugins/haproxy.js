"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var Promise = require("bluebird");
var utils_1 = require("./utils");
var fst = require("fs");
var fs = Promise.promisifyAll(fst);
var HAProxyPlugin = /** @class */ (function () {
    function HAProxyPlugin(config) {
        this._config = config;
    }
    HAProxyPlugin.prototype.run = function (cert) {
        //create the certificate chain, save it then reload the service as required...
        var _this = this;
        return Promise.resolve().then(function () {
            var fullKeyChain = utils_1.generateFullKeyChain(cert);
            console.log("Writing Certificate Chain to " + _this._config.certpath);
            return fs.writeFileAsync(_this._config.certpath, fullKeyChain);
        }).then(function () {
            if (_this._config.reload === true) {
                console.log("Reloading HAProxy Service Now");
                return utils_1.reloadService("haproxy");
            }
            return true;
        });
    };
    return HAProxyPlugin;
}());
exports.default = HAProxyPlugin;
//# sourceMappingURL=haproxy.js.map