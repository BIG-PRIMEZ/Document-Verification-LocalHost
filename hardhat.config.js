require("@nomiclabs/hardhat-ethers");
require("dotenv").config();

module.exports = {
  solidity: "0.8.0",
  networks: {
    hardhat: {
      chainId: 1337,  // Local Hardhat network chain ID
    },
    localhost: {
      url: "http://127.0.0.1:8545",  // Localhost node URL
    },
  },
};