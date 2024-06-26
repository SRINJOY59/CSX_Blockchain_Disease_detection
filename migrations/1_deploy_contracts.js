const EncryptedStorage = artifacts.require("EncryptedStorage");

module.exports = function (deployer) {
    deployer.deploy(EncryptedStorage);
};
