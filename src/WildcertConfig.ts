import * as _ from "lodash";
import * as ConfigValidator from "./WildcertConfigValidators"
import * as fs from "fs"
/*

Parse the selected config file or load sensible defaults


 */



const PRODUCTION_ACME_ADDRESS:string = "https://acme-v02.api.letsencrypt.org/directory";
const STAGING_ACME_ADDRESS:string    = "https://acme-staging-v02.api.letsencrypt.org/directory";



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


export class WildcertConfig {

  public static ConfigFromOptions() {



  }

  public static ConfigFromFile(configPath:string):WildcertConfig {

    if (fs.statSync(configPath).isFile()) {

      //try load and parse config...

      let loadedConf = fs.readFileSync(configPath, "utf8");

      let parsedConf = JSON.parse(loadedConf);

      return new WildcertConfig(parsedConf);

    } else {

      throw new Error(`Specified config file path ${configPath} is not a file.`);

    }

  }

  private _configObj;

  constructor(inConfigObj) {

    //this._configObj = createDefaultOptions();

    //we have the default options lets now mix over the provided config data then we can verify each section as required

    //this._configObj = _.defaultsDeep(this._configObj, inConfigObj);

    this._configObj = ConfigValidator.Validate(inConfigObj);

  }

  getGreenlockObject() {

    //take the supplied config and turn it into a valid greenlock usable object...

    let robj = _.cloneDeep(this._configObj.greenlock);

    robj.version = "draft-12";

    if (robj.production === true) {

      console.log("Using production acme server");

      robj.server = PRODUCTION_ACME_ADDRESS;

    } else {

      console.log("Using staging acme server");

      robj.server = STAGING_ACME_ADDRESS;

    }

    delete robj.production;

    //now set the renewal points...

    robj.renewWithin = this.getRenewWithin();

    robj.renewBy = this.getRenewBy();

    robj.agreeToTerms = function (opts, agreeCb) {
      // opts = { email, domains, tosUrl }
      agreeCb(null, opts.tosUrl);
    };

    return robj;

  }

  getDNSConfig() {

    return this._configObj.dns;

  }

  getServerConfig() {

    return this._configObj.server;

  }

  getEmail():string {

    return this._configObj.email;

  }

  getDomains():string[] {

    return this._configObj.domains;

  }

  getRenewWithin():number {

    return this._configObj.expiryThreshold * 2 * 24 * 60 * 60 * 1000

  }

  getRenewBy():number {

    return this._configObj.expiryThreshold * 24 * 60 * 60 * 1000

  }

}


