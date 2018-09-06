
import * as child_process from "child_process";
import * as Promise from "bluebird";



export function generateFullKeyChain(certBundle):string {

  if (!certBundle.hasOwnProperty("cert") || !certBundle.hasOwnProperty("chain") || !certBundle.hasOwnProperty("privkey")) {

    throw new Error(`Unable to generate full chain for certificate as the required fields are missing`);

  }

  let fullKeyChain = `${certBundle.cert.trim()}
${certBundle.chain.trim()}
${certBundle.privkey.trim()}`;

  return fullKeyChain;

}


export function reloadService(serviceName:string):Promise<any> {

  return new Promise<any>((resolve, reject) => {

    child_process.exec(`systemctl reload ${serviceName}.service`, (err, stdout, stderr) => {

      if (err) {

        console.error(`Error trying to reload service: ${err.message}`);

      }

      resolve(true)

    });

  });

}
