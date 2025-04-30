const { buildModule } = require("@nomicfoundation/hardhat-ignition/modules");

const HospitalModule = buildModule("HospitalModule", (m) => {
  const hospital = m.contract("Hospital");

  return { hospital };
});

module.exports = HospitalModule;
