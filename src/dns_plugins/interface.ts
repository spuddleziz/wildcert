import * as Promise from "bluebird";



export default interface IDNSPlugin {

  init():Promise<any>

  getOptions()

  set(args, domain, challenge, keyAuthorisation, cb)
  get(args, domain, challenge, cb)
  remove(args, domain, challenge, cb)

  setIPv4(host:string, ips:string[]):Promise<any>
  setIPv6(host:string, ips:string[]):Promise<any>

  setRecord(domain, type, name, value, ttl):Promise<any>
  getRecord(domain, type, name):Promise<any>
  removeRecord(domain, type, name):Promise<any>

}
