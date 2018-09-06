import {IServerPlugin} from "./interface";
import * as Promise from "bluebird";
import {generateFullKeyChain, reloadService} from "./utils";
import * as fst from "fs";

const fs:any = Promise.promisifyAll(fst);


export default class HAProxyPlugin implements IServerPlugin {

  private _config;

  constructor(config) {

    this._config = config;

  }

  run(cert): Promise<any> {
    //create the certificate chain, save it then reload the service as required...

    return Promise.resolve().then(() => {

      let fullKeyChain = generateFullKeyChain(cert);

      console.log(`Writing Certificate Chain to ${this._config.certpath}`);

      return fs.writeFileAsync(this._config.certpath, fullKeyChain);

    }).then(() => {

      if (this._config.reload === true) {

        console.log("Reloading HAProxy Service Now");

        return reloadService("haproxy");

      }

      return true;

    });

  }

}

