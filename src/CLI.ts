require('source-map-support').install({
  handleUncaughtExceptions: false
});
import * as program from "commander"
import {Wildcert} from "./Wildcert";
import {WildcertConfig} from "./WildcertConfig";

//the wildcert cli class is the entry point for the command line interface and will process the supplied options...
export class WildcertCLI {

  public static run() {

    console.log("Running Wildcert CLI");

    program
      .arguments("<config_file>")
      .action(WildcertCLI.runWildcert)
      .parse(process.argv)

  }

  private static runWildcert(configfile) {

    console.log(`Loading Wildcert Config File: ${configfile}`);

    const wc = new Wildcert(WildcertConfig.ConfigFromFile(configfile));

    wc.run();

  }

}
