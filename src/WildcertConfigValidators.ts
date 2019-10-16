import * as Joi from "joi"
import * as Greenlock from "greenlock";
import {type} from "os";
import {IpOptions} from "joi";

/*

this validates the provided configuration options against a Joi Schema

 */

const FILEPATH_RE = /^(.*\/)([^\/]*)$/

function getCleanObjectKeys(inObj):string[] {

  let keyList:string[] = [];

  for (let key in inObj) {

    if (inObj.hasOwnProperty(key)) {

      keyList.push(key);

    }

  }

  return keyList;

}


function createDefaultStoreConfigForGreenLock() {

  return {
    "plugin": "le-store-certbot",
    "config": {
      "debug": false,
      "configDir": "/etc/letsencrypt"
    }
  }

}

const GreenlockStoreConfigValidators = {

  "le-store-certbot": Joi.object({
    "debug": Joi.bool().default(false),
    "configDir": Joi.string().regex(FILEPATH_RE).required().default("/etc/letsencrypt")
  })

};

const GreenlockDNS01ChallengeConfigValidators = {



};

const GreenlockHTTP01ChallengeConfigValidators = {



};

const GreenlockTLSSNI01ChallengeConfigValidators = {



};

const GreenlockConfigValidator = Joi.object().keys({

  "production": Joi.bool().default(false).required(),
  "rsaKeySize": Joi.number().min(2048).multiple(512).default(2048).required(),
  "store"     : Joi.object().keys({
    "plugin": Joi.string().allow(getCleanObjectKeys(GreenlockStoreConfigValidators)).required(),
    "config": Joi.object().unknown(true),
  }).required().default(createDefaultStoreConfigForGreenLock, "Default Greenlock Store Config"),
  "challenges": Joi.object().keys({
    "dns-01": Joi.alternatives().try(Joi.string().valid("wildcert"), Joi.object().keys({
      "plugin": Joi.string().allow(getCleanObjectKeys(GreenlockDNS01ChallengeConfigValidators)).required(),
      "config": Joi.object().unknown(true),
    })),
    "http-01": Joi.object().keys({
      "plugin": Joi.string().allow(getCleanObjectKeys(GreenlockHTTP01ChallengeConfigValidators)).required(),
      "config": Joi.object().unknown(true),
    }),
    "tls-sni-01": Joi.object().keys({
      "plugin": Joi.string().allow(getCleanObjectKeys(GreenlockTLSSNI01ChallengeConfigValidators)).required(),
      "config": Joi.object().unknown(true),
    })
  }).min(1).max(3).required(),
  "challengeType": Joi.string().valid("dns-01", "http-01", "tls-sni-01").optional(),
  "debug": Joi.bool().default(false)

});

const DNSPluginConfigValidators = {

  "godaddy": Joi.object().keys({
    "apikey": Joi.string().token().required(),
    "secret": Joi.string().token().required()
  }),
  'ovh': Joi.object().keys({
    'appKey': Joi.string().token().required(),
    'appSecret': Joi.string().token().required(),
    'consumerKey': Joi.string().token().required(),
    'endpoint': Joi.string().required()
  })

};

const ServerPluginConfigValidators = {

  "haproxy": Joi.object().keys({
    "certpath": Joi.string().regex(FILEPATH_RE).required(),
    "reload": Joi.boolean().default(false).required()
  })

};

const BaseConfigSchema = Joi.object({

  "domains"         : Joi.array().min(1).single().description("The Domains to renew certificates for").items(Joi.string().regex(/^(\*\.)?([a-zA-Z0-9][a-zA-Z_\-0-9]{0,61}[a-zA-Z]?\.)+[a-zA-Z]{2,}$/)).required(),
  "email"           : Joi.string().email().required(),
  "expiryThreshold" : Joi.number().integer().positive().max(30).min(5),
  "greenlock"       : GreenlockConfigValidator.required(),
  "dns"             : Joi.object().keys({
    "plugin"  : Joi.string().allow(getCleanObjectKeys(DNSPluginConfigValidators)).required(),
    "config"  : Joi.object().unknown(true),
    "setIP"   : Joi.boolean().default(false),
    "ip4List" : Joi.array().single().sparse().items(Joi.string().ip({ version : ["ipv4"], cidr: "forbidden" })).optional(),
    "ip6List" : Joi.array().single().sparse().items(Joi.string().ip({ version : ["ipv6"], cidr: "forbidden" })).optional(),
  }).optional(),
  "server" : Joi.object().keys({
    "plugin" : Joi.string().allow(getCleanObjectKeys(ServerPluginConfigValidators)).required(),
    "config" : Joi.object().unknown(true),
  }).optional()

});

function checkPluginConfigValidator(validators, plugin, config):any {

  if (!config || config === null || config === undefined || typeof config !== "object") {

    throw new Error(`The config supplied for plugin ${plugin} is missing`);

  }

  if (!validators.hasOwnProperty(plugin)) {

    throw new Error(`The selected plugin ${plugin} has no corresponding config validator`);

  }

  let result = validators[plugin].validate(config);

  if (result) {

    if (result.error && result.error.details && Array.isArray(result.error.details) && result.error.details.length > 0) {

      //there was an error validating the supplied plugin config

      throw new Error(result.error.annotate());

    } else {

      //we have a valid value

      return result.value;

    }

  } else {

    throw new Error("There was an unknown error validating the supplied config")

  }

}

function checkNodePluginConfigValidator(validators, plugin, config):any {

  try {

    require.resolve(plugin)

  } catch (ex) {

    throw new Error(`The selected store plugin ${plugin} is not installed as a module on this system, please install it using $ sudo npm install -g ${plugin}`);

  }

  return checkPluginConfigValidator(validators, plugin, config)

}

function validateGreenlock(config):any {

  //check that the store plugin is allowed and validate its config

  let greenlockConfig = config.greenlock;

  greenlockConfig.store.config =  checkNodePluginConfigValidator(GreenlockStoreConfigValidators, greenlockConfig.store.plugin, greenlockConfig.store.config);

  if (greenlockConfig.hasOwnProperty("challengeType") && typeof greenlockConfig.challengeType === "string" && !greenlockConfig.challenges.hasOwnProperty(greenlockConfig.challengeType)) {

    throw new Error(`The requested default challengeType ${greenlockConfig.challengeType} has no corresponding configured challenge plugin`);

  }

  console.log("Loading and Validating Challenge Plugin Configs");

  for (let challengeTypeKey in greenlockConfig.challenges) {

    if (!greenlockConfig.challenges.hasOwnProperty(challengeTypeKey)) continue;

    switch(challengeTypeKey) {

      case "dns-01":
        //dns is a special case - if this is set to "wildcert" then internally we do the challenge auth method as we will be manually updating DNS as required otherwise its a standard approach
        if (typeof greenlockConfig.challenges[challengeTypeKey] === "string" && greenlockConfig.challenges[challengeTypeKey] === "wildcert" && !config.hasOwnProperty("dns")) {

          //if using the internal wildcert method and there is no dns config section then we need to throw here...

          throw new Error(`If using the internal wildcert DNS challenge method the "dns" section must be configured in the config`);

        } else if (typeof greenlockConfig.challenges[challengeTypeKey] !== "string") {

          greenlockConfig.challenges[challengeTypeKey].config = checkNodePluginConfigValidator(GreenlockDNS01ChallengeConfigValidators, greenlockConfig.challenges[challengeTypeKey].plugin, greenlockConfig.challenges[challengeTypeKey].config);

        }
        break;
      case "http-01":
        greenlockConfig.challenges[challengeTypeKey].config = checkNodePluginConfigValidator(GreenlockHTTP01ChallengeConfigValidators, greenlockConfig.challenges[challengeTypeKey].plugin, greenlockConfig.challenges[challengeTypeKey].config);
        break;
      case "tls-sni-01":
        greenlockConfig.challenges[challengeTypeKey].config = checkNodePluginConfigValidator(GreenlockTLSSNI01ChallengeConfigValidators, greenlockConfig.challenges[challengeTypeKey].plugin, greenlockConfig.challenges[challengeTypeKey].config);
        break;
      default:
        throw new Error(`The configured challenge method ${challengeTypeKey} is not supported`);

    }

  }

  config.greenlock = greenlockConfig;

  return config;

}

function validateDNS(config):any {

  if (!config.hasOwnProperty("dns")) return config;

  console.log("Validating DNS Plugin Config");

  //there is a configured dns section lets test it...

  config.dns.config = checkPluginConfigValidator(DNSPluginConfigValidators, config.dns.plugin, config.dns.config);

  return config;

}

function validateServer(config):any {

  if (!config.hasOwnProperty("server")) return config;

  console.log("Validating Server Plugin Config");

  //there is a configured dns section lets test it...

  config.server.config = checkPluginConfigValidator(ServerPluginConfigValidators, config.server.plugin, config.server.config);

  return config;

}

export function Validate(inConfig:any):any {

  let result = BaseConfigSchema.validate(inConfig);

  if (result) {

    if (result.error && result.error.details && Array.isArray(result.error.details) && result.error.details.length > 0) {

      //there was an error validating the supplied config

      throw new Error(result.error.annotate());

    } else {

      //we have a valid value - however there are further validation steps to perform against the config...

      let config = validateGreenlock(result.value);

      config = validateDNS(config);

      config = validateServer(config);

      return config;

    }

  } else {

    throw new Error("There was an unknown error validating the supplied config")

  }

}
