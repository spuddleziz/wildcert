import {IServerPlugin} from "./server_plugins/interface";

require('source-map-support').install({
  handleUncaughtExceptions: false
});

//the wildcert class runs the process from cradle to grave -  builds the config then uses that to build the greenlock object...
import {WildcertConfig} from "./WildcertConfig";
import * as Promise from "bluebird";
import IDNSPlugin from "./dns_plugins/interface";
import * as Greenlock from "greenlock";
import * as _ from "lodash";

export class Wildcert {

  private _config:WildcertConfig;

  private _greenlockObject;

  private _storePluginInstance;
  private _dnsPluginInstance:IDNSPlugin;
  private _serverPluginInstance:IServerPlugin;
  private _dnsPluginEnabled:boolean = false;
  private _serverPluginEnabled:boolean = false;

  private _greenlockInstance;

  constructor(config:WildcertConfig) {

    this._config = config;

  }

  public run() {

    return Promise.all([
      this.prepareDNSPlugin(),
      this.prepareServerPlugin()
    ]).then(() => {

      return this.prepareAndCreateGreenlock();

    }).then(() => {

      return this.checkCurrentCertificates();

    }).then((doRequests) => {

      if (!doRequests) {
        console.log("Not renewing/registering certificates as they haven't expired yet.");
        return false;
      }

      return this.doCertificateRequests();

    })

  }

  private prepareServerPlugin():Promise<any> {

    let serverConf = this._config.getServerConfig();

    if (!serverConf) return Promise.resolve();

    try {

      let plugin = require("./server_plugins/" + serverConf.plugin);

      if (plugin && typeof plugin === "function") {

        plugin = {
          "default": plugin
        };

      }

      if (!plugin || !plugin.hasOwnProperty("default")) {

        return Promise.reject(new Error(`The requested Server plugin ${serverConf.plugin} doesn't exist or is in the incorrect format.`));

      } else {

        //lets try load it

        let pluginInstance:IServerPlugin = new plugin.default(serverConf.config);

        if (!pluginInstance || !pluginInstance.run || typeof pluginInstance.run !== "function") {

          return Promise.reject(new Error(`The requested Server plugin ${serverConf.plugin} doesn't exist or is in the incorrect format.`));

        }

        this._serverPluginInstance = pluginInstance;

        this._serverPluginEnabled = true;

        console.log("Server Plugin now ready");

        if ((<any>pluginInstance).init && typeof (<any>pluginInstance).init === "function") {

          return (<any>(<any>pluginInstance).init)();

        }

        return Promise.resolve();

      }

    } catch (ex) {

      return Promise.reject(ex);

    }

  }

  private prepareDNSPlugin():Promise<any> {

    let dnsConf = this._config.getDNSConfig();

    if (!dnsConf) return Promise.resolve();

    //attempt to load the plugin...

    try {

      let plugin = require("./dns_plugins/" + dnsConf.plugin);

      if (plugin && typeof plugin === "function") {

        plugin = {
          "default": plugin
        };

      }

      if (!plugin || !plugin.hasOwnProperty("default")) {

        return Promise.reject(new Error(`The requested DNS plugin ${dnsConf.plugin} doesn't exist or is in the incorrect format.`));

      } else {

        //lets try load it

        let pluginInstance:IDNSPlugin = new plugin.default(dnsConf.config);

        if (!pluginInstance || !pluginInstance.init || typeof pluginInstance.init !== "function") {

          return Promise.reject(new Error(`The requested DNS plugin ${dnsConf.plugin} doesn't exist or is in the incorrect format.`));

        }
        console.log("Valid plugin class");
        this._dnsPluginInstance = pluginInstance;

        this._dnsPluginEnabled = true;

        console.log("DNS Plugin ready.");

        return this._dnsPluginInstance.init().then(() => {

          //if ip updates are enabled we need to immediately set the ip on all domains...

          if (dnsConf.setIP === true) {

            //lets go ahead and iterate the domains so we can set the IPs for them all...

            let doIP4 = false;

            let doIP6 = false;

            if ((!dnsConf.ip4List && !dnsConf.ip6List) || (!Array.isArray(dnsConf.ip4List) && !Array.isArray(dnsConf.ip6List)) || (dnsConf.ip4List.length === 0 && dnsConf.ip6List.length === 0)) {

              console.log("Cannot update ips for domains if no ips have been set, either V4 or V6. Continuing, but if using an HTTP-01 challenge this will likely fail if the A or AAAA records aren't pointing to this host.");

              return;

            }

            if (dnsConf.ip4List && Array.isArray(dnsConf.ip4List) && dnsConf.ip4List.length > 0) {

              doIP4 = true;

            }

            if (dnsConf.ip6List&& Array.isArray(dnsConf.ip6List) && dnsConf.ip6List.length > 0) {

              doIP6 = true;

            }

            return Promise.each(this._config.getDomains(), (domain:string) => {

              console.log(`Setting IP Addresses for domain ${domain}`);

              if (doIP4 && doIP6) {

                return Promise.all([
                  this._dnsPluginInstance.setIPv4(domain, dnsConf.ip4List),
                  this._dnsPluginInstance.setIPv6(domain, dnsConf.ip6List)
                ]);

              } else if (doIP6) {

                return this._dnsPluginInstance.setIPv6(domain, dnsConf.ip6List);

              } else {

                return this._dnsPluginInstance.setIPv4(domain, dnsConf.ip4List);

              }

            });

          }

          return;

        });

      }

    } catch (ex) {

      return Promise.reject(ex);

    }

  }

  private prepareAndCreateGreenlock() {

    return Promise.resolve().then(() => {

      return this.buildGreenlockObject();

    }).then(() => {

      console.log("Creating Greenlock Instance");

      this._greenlockInstance = Greenlock.create(this._greenlockObject);

      return true;

    });

  }

  private buildGreenlockObject() {

    //load the required store plugin...

    this._greenlockObject = this._config.getGreenlockObject();

    console.log(`Loading Greenlock Store Plugin ${this._greenlockObject.store.plugin}`);

    this._storePluginInstance = loadPluginWithConfig(this._greenlockObject.store.plugin, this._greenlockObject.store.config);

    this._greenlockObject.store = this._storePluginInstance;

    //now load the challenge plugins...

    for (let challengeTypeKey in this._greenlockObject.challenges) {

      if (!this._greenlockObject.challenges.hasOwnProperty(challengeTypeKey)) continue;

      switch(challengeTypeKey) {

        case "dns-01":
          //dns is a special case - if this is set to "wildcert" then internally we do the challenge auth method as we will be manually updating DNS as required otherwise its a standard approach
          if (typeof this._greenlockObject.challenges[challengeTypeKey] === "string" && this._greenlockObject.challenges[challengeTypeKey] === "wildcert") {

            //if using the internal wildcert method and there is no dns config section then we need to throw here...

            if (!this._dnsPluginEnabled) {

              throw new Error(`If using the internal wildcert DNS challenge method the "dns" section must be configured in the config`);

            }

            this._greenlockObject.challenges[challengeTypeKey] = this._dnsPluginInstance;

          } else {

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
          throw new Error(`The configured challenge method ${challengeTypeKey} is not supported`);

      }

    }

    return true;

  }

  private doCertificateRequests() {

    return Promise.resolve().then(() => {

      return this._greenlockInstance.register({

        domains : this._config.getDomains(),
        email   : this._config.getEmail(),
        agreeTos: true,
        challengeType : "dns-01"

      }).then((cert) => {

        console.log("Domain Certificate Registration Process Complete.");

        if (this._serverPluginEnabled === true) {

          console.log("Running Server Plugin Now.");

          return this._serverPluginInstance.run(cert);

        }

        return;

      }).catch((ex) => {

        //console.error(ex);

      });

    })

  }

  private checkCurrentCertificates() {

    return Promise.resolve().then(() => {

      let domainList = this._config.getDomains();

      return this._greenlockInstance.check({domains: domainList}).then((results) => {

        if (results) {

          let doRegister = false;

          if (Array.isArray(results) && results.length > 0) {

            return Promise.each(results, (result) => {

              if (checkCertificateExpiry(result, this._config.getRenewWithin(), domainList) === true) {

                doRegister = true;

              }

            }).then(() => {

              return doRegister;

            });

          } else {

            return checkCertificateExpiry(results, this._config.getRenewWithin(), domainList)

          }

        }

        return true;

      });

    });

  }

}



function checkCertificateExpiry(certResult, renewWithin, reqDomains:string[]) {

  if (certResult && certResult.hasOwnProperty("altnames") && Array.isArray(certResult.altnames) && !_.isEqual(certResult.altnames.sort(), reqDomains.sort())) {

    console.log(`The domains included in the certificate have changed so a new certificate will need to be requested. Have: [${certResult.altnames.sort().join(", ")}] | Requesting: [${reqDomains.sort().join(", ")}]`);

    return true;

  } else if (certResult && certResult.hasOwnProperty("expiresAt") && certResult.expiresAt - renewWithin >= new Date().getTime()) {

    let renewalCountdown = ((certResult.expiresAt - renewWithin - new Date().getTime()) / 1000 / 60 / 60 / 24).toFixed(0);

    console.log(`Certificate due for rewnewal in ${renewalCountdown} days. Expiry Date: ${new Date(certResult.expiresAt)}`);

    return false;

  }

  return true;

}



function loadPluginWithConfig(plugin, config) {

  return require(plugin).create(config);

}
