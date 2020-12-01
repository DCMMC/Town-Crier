const Migrations = artifacts.require("Migrations");
const TownCrier = artifacts.require("TownCrier");
const Application = artifacts.require("Application");

module.exports = function (deployer) {
  deployer.deploy(Migrations);
  deployer.deploy(TownCrier).then(
    function () {
      console.log(TownCrier.address);
      return deployer.deploy(Application, TownCrier.address);
    }
  )
};
