import IDNSPlugin from "./interface";
import * as request from "request-promise";
import * as _ from "lodash";
import {
  ACME_RECORD_PREFIX, checkAuthoritativeServerDNSRecord,
  getDomainAndNameFromMap, lookupIPs,
  makeChallengeKeyAuthDigest,
  putDomainInMap,
  validateDNSRecordType
} from "./utils";
import * as Promise from "bluebird";

export default class GoDaddyDNSPlugin implements IDNSPlugin {

  private _config;
  private _domainMap;

  constructor(config) {

    this._config = config;

    this._domainMap = {};

  }

  init():Promise<any> {

    this._domainMap = {};

    return getGoDaddyDomainsList({

      apiKey: this._config.apikey,
      secret: this._config.secret

    }).then((resp) => {

      if (!resp || !Array.isArray(resp) || resp.length === 0) {

        return Promise.reject(new Error("No domains could be returned."));

      }

      //now build the domain map...

      resp.forEach((domItem) => {

        //take the domain split it and populate the

        putDomainInMap(this._domainMap, domItem.domain);

      });

    })

  }

  get(args, domain, challenge, cb) {



  }

  remove(args, domain, challenge, cb) {

    let isRoot = false;

    let foundDomain = getDomainAndNameFromMap(this._domainMap, domain);

    if (!foundDomain || !foundDomain.name || !foundDomain.domain) {

      return cb(new Error(`The requested domain ${domain} is not available in the godaddy instance configured`));

    }

    //console.log(args, domain, challenge)

    console.log(`Looking for ${domain} and found ${foundDomain.name} with domain ${foundDomain.domain}`);

    let acmePath = "";

    if (foundDomain.name === foundDomain.domain) {

      acmePath = ACME_RECORD_PREFIX;

      isRoot = true;

    } else {

      acmePath = ACME_RECORD_PREFIX + "." + foundDomain.name;

    }

    this.removeRecord(foundDomain.domain, "TXT", acmePath).then((resp) => {

      //do something with response?

    }).then(() => {

      cb(null)

    }).catch((ex) => {

      cb(ex);

    });

  }

  set(args, domain, challenge, keyAuthorisation, cb) {

    //get base domain...

    let isRoot = false;

    let foundDomain = getDomainAndNameFromMap(this._domainMap, domain);

    if (!foundDomain || !foundDomain.name || !foundDomain.domain) {

      return cb(new Error(`The requested domain ${domain} is not available in the godaddy instance configured`));

    }

    //console.log(args, domain, challenge)

    console.log(`Looking for ${domain} and found ${foundDomain.name} with domain ${foundDomain.domain}`);

    let acmePath = "";

    if (foundDomain.name === foundDomain.domain) {

      acmePath = ACME_RECORD_PREFIX;

      isRoot = true;

    } else {

      acmePath = ACME_RECORD_PREFIX + "." + foundDomain.name;

    }

    //build the digest auth key

    let keyAuthDigest = makeChallengeKeyAuthDigest(keyAuthorisation);

    getGoDaddyNSForDomain({
      apiKey: this._config.apikey,
      secret: this._config.secret,
      domain: foundDomain.domain,
      name : (isRoot === true ? "@" : foundDomain.name)
    }).then((nameservers) => {

      return this.setRecord(foundDomain.domain, "TXT", acmePath, keyAuthDigest, 600).then(() => {

        console.log("Record set. Waiting 5 seconds before checking propagation");

        return Promise.delay(5000);

      }).then(() => {

        if (!nameservers || !Array.isArray(nameservers) || nameservers.length === 0) {

          console.log("Can't find Authoritative Nameservers so waiting for the default timeout.");

          return Promise.delay(10 * 60 * 1000);

        }

        //lets resolve the nameserver addresses

        let nsList = _.map(nameservers, "data");

        return lookupIPs(nsList).then<any>((nsIPs:any) => {

          if (!nsIPs || !Array.isArray(nsIPs) || nsIPs.length === 0) {

            console.log("Can't lookup IPs of Authoritative Nameservers so waiting for the default timeout.");

            return Promise.delay(10 * 60 * 1000);

          }

          console.log(`Waiting for DNS Propagation using authoritative nameservers: ${nsIPs.join(", ")}`);

          return checkAuthoritativeServerDNSRecord(nsIPs, "TXT", acmePath + "." + foundDomain.domain, keyAuthDigest, 10 * 60 * 1000);

        });

      }).then(() => {

        console.log("DNS Propagated waiting a further 5 seconds before proceeding.");

        return Promise.delay(5000).then(() => {

          cb(null)

        });

      }).catch((ex) => {

        cb(ex);

      })

    });

  }

  setIPv4(host:string, ips:string[]):Promise<any> {

    let foundDomain = getDomainAndNameFromMap(this._domainMap, host);

    if (!foundDomain || !foundDomain.name || !foundDomain.domain) {

      return Promise.reject(new Error(`The requested domain ${host} is not available in the godaddy instance configured`));

    }

    //console.log(args, domain, challenge)

    console.log(`Looking for ${host} and found ${foundDomain.name} with domain ${foundDomain.domain}`);

    if (foundDomain.name === foundDomain.domain) {

      foundDomain.name = "@";

    }

    return setMultipleGoDaddyRecords({

      apiKey: this._config.apikey,
      secret: this._config.secret,
      domain: foundDomain.domain,
      name : foundDomain.name,
      values: ips,
      type: "A",
      ttl: 600

    });

  }

  setIPv6(host:string, ips:string[]):Promise<any> {

    let foundDomain = getDomainAndNameFromMap(this._domainMap, host);

    if (!foundDomain || !foundDomain.name || !foundDomain.domain) {

      return Promise.reject(new Error(`The requested domain ${host} is not available in the godaddy instance configured`));

    }

    //console.log(args, domain, challenge)

    console.log(`Looking for ${host} and found ${foundDomain.name} with domain ${foundDomain.domain}`);

    if (foundDomain.name === foundDomain.domain) {

      foundDomain.name = "@";

    }

    return setMultipleGoDaddyRecords({

      apiKey: this._config.apikey,
      secret: this._config.secret,
      domain: foundDomain.domain,
      name : foundDomain.name,
      values: ips,
      type: "AAAA",
      ttl: 600

    });

  }

  removeRecord(domain, type, name):Promise<any> {

    console.log(`Removing Record ${name} of type ${type} from domain ${domain}`);

    return removeGoDaddyRecord({

      apiKey: this._config.apikey,
      secret: this._config.secret,
      domain: domain,
      name : name,
      type: type,

    });

  }

  setRecord(domain, type, name, value, ttl):Promise<any> {

    console.log(`Setting Record ${name} of type ${type} in domain ${domain} with a value of ${value} and ttl ${ttl}`);

    return setGoDaddyRecord({

      apiKey: this._config.apikey,
      secret: this._config.secret,
      domain: domain,
      name : name,
      value: value,
      type: type,
      ttl: ttl

    });

  }

  getRecord(domain, type, name):Promise<any> {

    console.log(`Getting Record ${name} of type ${type} from domain ${domain}`);

    return getGoDaddyRecord({

      apiKey: this._config.apikey,
      secret: this._config.secret,
      domain: domain,
      name : name,
      type: type,

    });

  }

  getOptions() {
    return this._config;
  }


}


function getGoDaddyDomainsList(req):Promise<any> {

  let options = {
    method: 'GET',
    url: `https://api.godaddy.com/v1/domains`,
    headers: {
      'authorization': `sso-key ${req.apiKey}:${req.secret}`,
      'content-type': 'application/json'
    },
    json: true
  };
  return Promise.resolve(request(options))

}


function setMultipleGoDaddyRecords(req):Promise<any> {

  if (!validateDNSRecordType(req.type)) return Promise.reject(new Error(`Supplied record type ${req.type} is invalid.`));

  if (!req.values || !Array.isArray(req.values) || req.values.length === 0) {

    return Promise.reject(new Error(`To set multiple values for a specified domain please pass an array of values using the values key.`));

  }

  let data = [];

  req.values.forEach((val) => {

    data.push({ type : req.type, name : req.name, ttl : req.ttl, data: val });

  });

  let options = {
    method: 'PUT',
    url: `https://api.godaddy.com/v1/domains/${req.domain}/records/${req.type}/${req.name.replace('@', '%40')}`,
    headers: {
      'authorization': `sso-key ${req.apiKey}:${req.secret}`,
      'content-type': 'application/json'
    },
    body: data,
    json: true
  };
  return Promise.resolve(request(options))

}

function setGoDaddyRecord(req):Promise<any> {

  if (!validateDNSRecordType(req.type)) return Promise.reject(new Error(`Supplied record type ${req.type} is invalid.`));

  let options = {
    method: 'PUT',
    url: `https://api.godaddy.com/v1/domains/${req.domain}/records/${req.type}/${req.name.replace('@', '%40')}`,
    headers: {
      'authorization': `sso-key ${req.apiKey}:${req.secret}`,
      'content-type': 'application/json'
    },
    body: [ { type : req.type, name : req.name, ttl : req.ttl, data: req.value } ],
    json: true
  };
  return Promise.resolve(request(options))

}

function removeGoDaddyRecord(req):Promise<any> {

  if (!validateDNSRecordType(req.type)) return Promise.reject(new Error(`Supplied record type ${req.type} is invalid.`));

  let options = {
    method: 'DELETE',
    url: `https://api.godaddy.com/v1/domains/${req.domain}/records/${req.type}/${req.name.replace('@', '%40')}`,
    headers: {
      'authorization': `sso-key ${req.apiKey}:${req.secret}`,
      'content-type': 'application/json'
    },
    json: true
  };
  return Promise.resolve(request(options))

}

function getGoDaddyRecord(req):Promise<any> {

  if (!validateDNSRecordType(req.type)) return Promise.reject(new Error(`Supplied record type ${req.type} is invalid.`));

  let options = {
    method: 'GET',
    url: `https://api.godaddy.com/v1/domains/${req.domain}/records/${req.type}/${req.name.replace('@', '%40')}`,
    headers: {
      'authorization': `sso-key ${req.apiKey}:${req.secret}`,
      'content-type': 'application/json'
    },
    json: true
  };
  return Promise.resolve(request(options))

}

function getGoDaddyNSForDomain(req):Promise<any> {

  let options = {
    method: 'GET',
    url: `https://api.godaddy.com/v1/domains/${req.domain}/records/NS/${req.name.replace('@', '%40')}`,
    headers: {
      'authorization': `sso-key ${req.apiKey}:${req.secret}`,
      'content-type': 'application/json'
    },
    json: true
  };
  return Promise.resolve(request(options));

}

