"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var child_process = require("child_process");
var Promise = require("bluebird");
function generateFullKeyChain(certBundle) {
    if (!certBundle.hasOwnProperty("cert") || !certBundle.hasOwnProperty("chain") || !certBundle.hasOwnProperty("privkey")) {
        throw new Error("Unable to generate full chain for certificate as the required fields are missing");
    }
    var fullKeyChain = certBundle.cert.trim() + "\n" + certBundle.chain.trim() + "\n" + certBundle.privkey.trim();
    return fullKeyChain;
}
exports.generateFullKeyChain = generateFullKeyChain;
function reloadService(serviceName) {
    return new Promise(function (resolve, reject) {
        child_process.exec("systemctl reload " + serviceName + ".service", function (err, stdout, stderr) {
            if (err) {
                console.error("Error trying to reload service: " + err.message);
            }
            resolve(true);
        });
    });
}
exports.reloadService = reloadService;
//# sourceMappingURL=utils.js.map