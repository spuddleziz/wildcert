import * as dot from "dot-object";
import * as Promise from "bluebird";
import {Resolver} from "dns";
import { DomainMap } from "../types";


export const ACME_RECORD_PREFIX = "_acme-challenge";

export function makeChallengeKeyAuthDigest(keyAuthorisation:string):string {

  return require('crypto').createHash('sha256').update(keyAuthorisation||'').digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');

}



export function validateDNSRecordType(type:string):boolean {

  switch(type) {
    case "A":
    case "AAAA":
    case "TXT":
    case "SRV":
    case "CNAME":
      return true;
    default:
      return false;
  }

}

export function reverseDomain(domain:string):string {

  return domain.split(".").reverse().join(".");

}

export function putDomainInMap(domainMap: DomainMap, domainToAdd: string): void {

  let rdom = reverseDomain(domainToAdd);

  domainMap[rdom] = domainToAdd;

}

export interface FoundDomainAndName {
  domain:string
  name:string
}

export function getDomainAndNameFromMap(domainMap:DomainMap , requestDomain:string):FoundDomainAndName {

  //recursively step up the domain and look in the map for it...

  let builtDom = "";

  let domSplit = requestDomain.split(".");

  let domSplitLen = domSplit.length - 1;

  let picked = null;

  for (let i = domSplitLen; i >= 0; i--) {

    builtDom += (i < domSplitLen ? "." : "") + domSplit[i];

    picked = domainMap[builtDom];

    if (picked && typeof picked === "string") {

      return {

        domain: picked,
        name : requestDomain.replace("." + picked, "")

      }

    }

  }

  return null;

}

function processLoop(mainFn, compareFn, delay) {
  return new Promise(function (resolve, reject) {

    function next() {
      mainFn().then(function (val) {
        // add to result array
        if (compareFn(val)) {
          // found a val < 100, so be done with the loop
          resolve(val);
        } else {
          // run another iteration of the loop after delay
          if (delay) {
            setTimeout(next, delay);
          } else {
            next();
          }
        }
      }, reject);
    }

// start first iteration of the loop
    if (delay) {
      setTimeout(next, delay);
    } else {
      next();
    }
  });
}



export function checkAuthoritativeServerDNSRecord(dnsServers:string[], recordType:string, hostname:string, expectedValue:string, maxTimout:number) {

  //make a resolver

  let timeoutTime = new Date().getTime() + maxTimout;

  let dnsResolver = new Resolver();

  return Promise.each(dnsServers, (lookupServer:string) => {

    console.log(`Using NS ${lookupServer} for propagation check`);

    dnsResolver.setServers([lookupServer]);

    function doAsyncResolve(hostname: string, recordType: string) {

      return new Promise((resolve, reject) => {

        console.log(`Attempting to get record type ${recordType} for ${hostname}`);

        dnsResolver.resolve(hostname, recordType, (err, res) => {

          if (err) {
            console.error(`Error Doing NS Propagation check against ${lookupServer}: ${err.message}. Polling will continue until the TTL has expired.`);
            return [];
          }

          if (res && Array.isArray(res) && res.length > 0) {

            //It's possible that there could have multiple records returned
            for(var i = 0; i < res.length; i++)
            {
              if(res[i] == expectedValue) return resolve(res[i]);
            }
            return reject(new Error("Couldn't find expected value"))

          }

          return [];

        })

      })

    }

    return processLoop(() => {

        return doAsyncResolve(hostname, recordType);

    }, (results) => {

      //look at the results and see if the value is correct
      console.log(`[resolver] Returned these values`,results);

      if (new Date().getTime() >= timeoutTime) {

        console.log("Timeout occurred waiting for DNS values to match expected.");

        return true;

      }

      if (results && Array.isArray(results) && results.length > 0) {

        let resLen = results.length;

        let count = 0;

        for (let ind = 0; ind < resLen; ind++) {

          if (results[ind] === expectedValue) {

            count++;

          }

        }

        if (count === resLen) {
          console.log(`DNS values match across the board ${count} : ${resLen}`);
          return true;
        }

      }

      return false;

    }, 5000)

  });

}



export function lookupIPs(hostlist:string[]) {

  let dnsResolver = new Resolver();

  function doAsyncResolve(hostname:string) {

    return new Promise((resolve, reject) => {

      dnsResolver.resolve4(hostname, (err, res) => {

        if (err) return reject(err);

        return resolve(res);

      })

    })

  }

  let iplist:string[] = [];

  return Promise.map(hostlist, (item:string) => {

    return doAsyncResolve(item).then((res) => {

      iplist.push.apply(iplist, res);

      return true;

    });

  }).then(() => {

    return Promise.resolve(iplist);

  })

}
