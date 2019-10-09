import IDNSPlugin from "./interface";
import { readlink } from "fs";
import {
    ACME_RECORD_PREFIX, checkAuthoritativeServerDNSRecord,
    getDomainAndNameFromMap, lookupIPs,
    makeChallengeKeyAuthDigest,
    putDomainInMap,
    validateDNSRecordType
} from "./utils";
import * as Promise from "bluebird";

class OVHError
{
    public message:string;
    public error: string;
}

export default class OVHDNSPlugin implements IDNSPlugin
{

    private _config;
    private _ovh;
    private _domainMap;
    private _consumerKey;

    constructor(config)
    {
        this._config = config;
        this._ovh = require('ovh')({
            appKey: this._config.appKey,
            appSecret: this._config.appSecret,
            consumerKey: this._config.consumerKey,
            endpoint: this._config.endpoint
        });
        this._domainMap = {};
    }

    init():Promise<any> {
        return this._ovh.requestPromised('GET','/domain')
        .then((domains) => {
            domains.forEach(element => {
                putDomainInMap(this._domainMap,element);
            });
        })
        .catch((error:OVHError) => {
            console.log(`[ovh] Error: (${error.error}) ${error.message}`);
        });
    }

    getOptions() {
        return this._config;
    }

    set(args: any, domain: string, challenge: string, keyAuthorisation: string, cb: string) {
        let foundDomain = getDomainAndNameFromMap(this._domainMap, domain);
        console.log(`Found domain: ${foundDomain}`);        
    }

    get(args: any, domain: any, challenge: any, cb: any) {

    }

    remove(args: any, domain: any, challenge: any, cb: any) {
        this._ovh.request('POST','/domain', (err,domains) => {
            console.log(domains);
        });
    }
    setIPv4(host: string, ips: string[]):Promise<any> {
        return this._ovh.request('POST','/domain', (err,domains) => {
            console.log(domains);
        });
    }
    setIPv6(host: string, ips: string[]) : Promise<any> {
        return this._ovh.request('POST','/domain', (err,domains) => {
            console.log(domains);
        });
    }
    setRecord(domain: any, type: any, name: any, value: any, ttl: any) : Promise<any> {
        return this._ovh.request('POST','/domain', (err,domains) => {
            console.log(domains);
        });
    }
    getRecord(domain: any, type: any, name: any) : Promise<any>{
        return this._ovh.request('POST','/domain', (err,domains) => {
            console.log(domains);
        });
    }
    removeRecord(domain: any, type: any, name: any): Promise<any> {
        return this._ovh.request('POST','/domain', (err,domains) => {
            console.log(domains);
        });
    }

    
}