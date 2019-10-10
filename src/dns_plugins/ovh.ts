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
import { 
    DomainMap,
    OVHError,
    OVHZoneRecord
 } from "../types";


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

    set(args: any, domain: string, challenge: string, keyAuthorisation: string, cb: any) {
        let isRoot = false;
        let foundDomain = getDomainAndNameFromMap(this._domainMap, domain);
        if(!foundDomain || !foundDomain.domain || !foundDomain.name )
        {
            return cb(new Error(`The requested domain ${domain} is not available in the ovh instance configured`));
        }
        console.log(`Looking for ${domain} and found ${foundDomain.name} with domain ${foundDomain.domain}`);

        let acmePath = "";
        if (foundDomain.name === foundDomain.domain) {
            acmePath = ACME_RECORD_PREFIX;
            isRoot = true;
        } else {
            acmePath = ACME_RECORD_PREFIX + "." + foundDomain.name;
        }

        let keyAuthDigest = makeChallengeKeyAuthDigest(keyAuthorisation);
        this.setRecord(foundDomain.domain,"TXT",acmePath,keyAuthDigest,600)
        .then();
    }

    get(args: any, domain: string, challenge: any, cb: any) {

    }

    remove(args: any, domain: string, challenge: any, cb: any) {
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
    setRecord(domain: string, type: string, name: string, value: string, ttl: number) : Promise<any> {
        return this._ovh.requestPromised('POST',`/domain/zone/${domain}/record`,{
            zoneName: domain,
            fieldType: type,
            subDomain: name,
            target: value,
            ttl: ttl
        })
        .catch((err:OVHError) => {
            return Promise.reject(`[ovh] Error: ${err.message}`);
        })
        .then((record: OVHZoneRecord) => {
            //Refresh call just applies the edited zone, returns void
            return this._ovh.requestPromised('POST',`/domain/zone/${domain}/refresh`,{
                zoneName: domain
            })
            .catch((err:OVHError) => {
                return Promise.reject(`[ovh] Error: ${err.message}`);
            })
        });
    }
    getRecord(domain: string, type: string, name: string) : Promise<any>{
        return this._ovh.requestPromised('GET',`/domain/zone/${domain}/record`,{
            zoneName: domain,
            fieldType: type,
            subdomain: name
        })
    }
    removeRecord(domain: string, type: any, name: any): Promise<any> {
        return this._ovh.request('POST','/domain', (err,domains) => {
            console.log(domains);
        });
    }

    
}