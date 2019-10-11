var request = require('request-promise');
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
    OVHZoneRecord,
    OVHConfig,
    AuthToken
 } from "../types";


export default class OVHDNSPlugin implements IDNSPlugin
{

    private _config:OVHConfig;
    private _ovh;
    private _domainMap:DomainMap;

    constructor(config)
    {
        let _consumerKey:string = null;
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
        .then(() => {
            return this.getRecord(foundDomain.domain,"NS",foundDomain.name)
                .then((dnsList:OVHZoneRecord[]) =>{
                    console.log(dnsList);
                    //let nsList = _.map(nameservers, "data");
                    //return lookupIPs(nsList)
                    cb(null)
                })
                .catch((err) => {
                    return Promise.reject(`[ovh] An error occurred whilst getting the nameserver records on ${foundDomain.domain}`);
                })
            
        })
        .catch((err) => cb(err));
    }
    
    get(args: any, domain: string, challenge: any, cb: any) {
        //Empty on the godaddy plugin
    }

    remove(args: any, domain: string, challenge: any, cb: any) {
        console.log(`Removing record from ${domain} on OVH`);
        let foundDomain = getDomainAndNameFromMap(this._domainMap, domain);
        if (!foundDomain || !foundDomain.name || !foundDomain.domain) {
            return cb(new Error(`The requested domain ${domain} is not available in the godaddy instance configured`));
        }

        let acmePath = "";
        if (foundDomain.name === foundDomain.domain) {
            acmePath = ACME_RECORD_PREFIX;
        } else {
            acmePath = ACME_RECORD_PREFIX + "." + foundDomain.name;
        }
        this.removeRecord(domain,"TXT",acmePath)
        .then(cb())
        .catch((err:string) => cb(err));
    }

    setIPv4(host: string, ips: string[]):Promise<any> {
        console.log(`[ovh] Setting IPv4 addresses`);
        let foundDomain = getDomainAndNameFromMap(this._domainMap, host);
        if (!foundDomain || !foundDomain.name || !foundDomain.domain) {
            console.log(`[ovh] The requested domain is not available`)
            return Promise.reject(new Error(`The requested domain ${host} is not available in the ovh instance configured`));
        }
        
        console.log(`Looking for ${host} and found ${foundDomain.name} with domain ${foundDomain.domain}`);
        
        //Queue the OVH requests for all IPs
        let multiReq = ips.map((ip: string) => {
            this.setRecord(foundDomain.domain,"A",foundDomain.name,ip,600);
        });
        return Promise.all(multiReq); //Return a promise which completes when all OVH requests are done
        
    }

    setIPv6(host: string, ips: string[]) : Promise<any> {
        let foundDomain = getDomainAndNameFromMap(this._domainMap, host);
        if (!foundDomain || !foundDomain.name || !foundDomain.domain) {
            return Promise.reject(new Error(`The requested domain ${host} is not available in the godaddy instance configured`));
        }
        
        console.log(`Looking for ${host} and found ${foundDomain.name} with domain ${foundDomain.domain}`);
        
        //Queue the OVh requests for all IPs
        let multiReq = ips.map((ip: string) => {
            this.setRecord(foundDomain.domain,"AAAA",foundDomain.name,ip,600);
        });
        return Promise.all(multiReq); //Return a promise which completes when all OVH requests are done
    }

    setRecord(domain: string, type: string, name: string, value: string, ttl: number) : Promise<any> {
        if(name == domain)
        {
            //When using OVH, the provided name is a subdomain and therefore should simply be blank when it's for the current domain
            name = '';
        }
        console.log(`[ovh] Adding a new ${type} record for ${domain} with the name ${name} with destination ${value} and TTL ${ttl}`);
        return this._ovh.requestPromised('POST',`/domain/zone/${domain}/record`,{
            fieldType: type,
            subDomain: name,
            target: value,
            ttl: ttl
        })
        .catch((err:OVHError) => {
            return Promise.reject(`[ovh] Error: ${err.message}`);
        })
        .then((record: OVHZoneRecord) => {
            console.log(`[ovh] Made DNS change`)
            //Refresh call just applies the edited zone, returns void
            return this.applyDNSChanges(domain);
        });
    }

    getRecord(domain: string, type: string, name: string) : Promise<OVHZoneRecord[]>{
        return this._ovh.requestPromised('GET',`/domain/zone/${domain}/record`,{
            fieldType: type,
            subdomain: name
        })
        .then((idlist :number[]) => {
            switch(idlist.length)
            {
                case 1: return this._ovh.requestPromised('GET',`/domain/zone/${domain}/record/${idlist[0]}`)
                    .then((record:OVHZoneRecord) => {
                        return [record];
                    });

                case 0: return Promise.reject(`[ovh] ${type} record named ${name} is not listed on ${domain}`);
                default: 
                    return Promise.all(idlist.map((id) => this._ovh.requestPromised('GET',`/domain/zone/${domain}/record/${id}`)))
                        .then((results:any) => {
                            console.log(results);
                            return results;
                        });
                return ;
            }
        })
        .catch((err:OVHError) => {
            return Promise.reject(`[ovh] Error: ${err.message}`);
        })
    }

    removeRecord(domain: string, type: string, name: string): Promise<any> {
        return this.getRecord(domain,type,name)
            .then((records: OVHZoneRecord[]) => {
                switch(records.length)
                {
                    case 1:
                        let record = records[0];
                        return this._ovh.requestPromise('DELETE',`/domain/zone/${record.zone}/record/${record.id}`)
                            .then(() => {
                                return this.applyDNSChanges;
                            })
                            .catch((err:OVHError) => {
                                return Promise.reject(`[ovh] Error: Failed to delete record ID ${record.id} from zone ${record.zone}`);
                            });

                    case 0:
                        return Promise.reject(`[ovh] Couldn't find ${type} record with name ${name} on ${domain}`);

                    default:
                        return Promise.reject(`[ovh] Multiple ${type} records of name ${name} marked for deletion on ${domain}, unsupported`)


                }
            });
    }

    applyDNSChanges(domain:string):Promise<void>{
        return this._ovh.requestPromised('POST',`/domain/zone/${domain}/refresh`)
        .then((res) => {
            console.log(`[ovh] DNS changes saved`);
            return Promise.resolve();
        })
        .catch((err:OVHError) => {
            return Promise.reject(`[ovh] Error: ${err.message}`);
        })
    }

    
}