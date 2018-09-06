import * as Promise from "bluebird";


export interface IServerPlugin {

  run(cert):Promise<any>

}
