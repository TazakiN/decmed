require("@nomicfoundation/hardhat-toolbox");

const { vars } = require("hardhat/config");

const IOTA_NETWORK_URL = vars.get("IOTA_NETWORK_URL");
const IOTA_ACCOUNT = vars.get("IOTA_ACCOUNT");

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: "0.8.28",
  ignition: {
    requiredConfirmations: 1,
  },
  networks: {
    iota: {
      url: IOTA_NETWORK_URL,
      chainId: 777,
      accounts: [IOTA_ACCOUNT],
    },
  },
};
