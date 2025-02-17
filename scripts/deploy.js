const hre = require("hardhat");

async function main() {
  // Get the contract factory
  const DocumentVerification = await hre.ethers.getContractFactory("DocumentVerification");

  // Deploy the contract
  const documentVerification = await DocumentVerification.deploy();
  await documentVerification.deployed();

  console.log("DocumentVerification deployed to:", documentVerification.address);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });