/* eslint-disable @typescript-eslint/no-non-null-assertion */
import { hashPersonalMessage } from "@ethereumjs/util";
import { ArgumentTypeName } from "@pcd/pcd-types";
import {
  SemaphoreIdentityPCD,
  SemaphoreIdentityPCDPackage,
  SemaphoreIdentityPCDTypeName,
} from "@pcd/semaphore-identity-pcd";
import { MembershipProver, Poseidon, Tree } from "@personaelabs/spartan-ecdsa";
import { Identity } from "@semaphore-protocol/identity";
import assert from "assert";
import { ethers } from "ethers";
import "mocha";
import * as path from "path";
import {
  EthereumGroupPCD,
  EthereumGroupPCDPackage,
  GroupType,
  pubkeyMembershipConfig,
} from "../src/EthereumGroupPCD";

const zkeyFilePath: string = path.join(__dirname, "../artifacts/16.zkey");
const wasmFilePath: string = path.join(__dirname, "../artifacts/16.wasm");

/**
 * The offset that the hex representation of the public key starts at, without the 0x prefix and without the 04 prefix. That's what the zk-circuit expects.
 * https://github.com/indutny/elliptic/issues/86
 * https://dev.to/q9/finally-understanding-ethereum-accounts-1kpe
 */
const hexPubkeyOffset = 2 + 2;
async function groupProof(
  identity: SemaphoreIdentityPCD,
  wallet: ethers.Wallet
) {
  const signatureOfIdentityCommitment = await wallet.signMessage(
    identity.claim.identity.commitment.toString()
  );

  let msgHash = Buffer.from(
    ethers.utils
      .hashMessage(identity.claim.identity.commitment.toString())
      .slice(2),
    "hex"
  );

  msgHash = hashPersonalMessage(
    Buffer.from(identity.claim.identity.commitment.toString())
  );

  const poseidon = new Poseidon();
  await poseidon.initWasm();
  const treeDepth = 20; // Provided circuits have tree depth = 20
  const pubKeyTree = new Tree(treeDepth, poseidon);

  // Add some public keys to the tree
  for (const member of [
    "0x04b4d5188949bf70c4db5e965a9ea67b80407e8ee7fa3a260ccf86e9c0395fe82cba155fdff55829b3c862322aba402d00b563861b603879ee8ae211c34257d4ad",
    "0x042d21e6aa2021a991a82d08591fa0528d0bebe4ac9a34d851a74507327d930dec217380bd602fe48a143bb21106ab274d6a51aff396f0e4f7e1e3a8a673d46d83",
  ]) {
    pubKeyTree.insert(
      poseidon.hashPubKey(Buffer.from(member.slice(hexPubkeyOffset), "hex"))
    );
  }
  // Add the prover's public key to the tree
  const proverPubkeyBuffer: Buffer = Buffer.from(
    wallet.publicKey.slice(hexPubkeyOffset),
    "hex"
  );
  pubKeyTree.insert(poseidon.hashPubKey(proverPubkeyBuffer));
  const pubKeyIndex = pubKeyTree.indexOf(
    poseidon.hashPubKey(proverPubkeyBuffer)
  ); // == 2 in this test

  // Prove membership of the prover's public key in the tree
  const merkleProof = pubKeyTree.createProof(pubKeyIndex);
  const prover = new MembershipProver(pubkeyMembershipConfig);
  await prover.initWasm();
  return await prover.prove(
    signatureOfIdentityCommitment,
    msgHash,
    merkleProof
  );
}

async function happyPathEthGroupPCD() {
  const identity = await SemaphoreIdentityPCDPackage.prove({
    identity: new Identity(),
  });
  const serializedIdentity = await SemaphoreIdentityPCDPackage.serialize(
    identity
  );
  const wallet = ethers.Wallet.createRandom(null);
  const { proof, publicInput } = await groupProof(identity, wallet);

  const ethGroupPCD = await EthereumGroupPCDPackage.prove({
    ethereumGroupProof: {
      argumentType: ArgumentTypeName.String,
      value: Buffer.from(proof).toString("hex"),
    },
    identity: {
      argumentType: ArgumentTypeName.PCD,
      pcdType: SemaphoreIdentityPCDTypeName,
      value: serializedIdentity,
    },
    publicInput: publicInput,
    groupType: {
      argumentType: ArgumentTypeName.String,
      value: GroupType.PUBLICKEY,
    },
  });

  return ethGroupPCD;
}
let ethGroupPCD: EthereumGroupPCD;

describe("Ethereum Group PCD", function () {
  this.timeout(30 * 1000);

  this.beforeAll(async function () {
    await EthereumGroupPCDPackage.init!({
      zkeyFilePath,
      wasmFilePath,
    });
    ethGroupPCD = await happyPathEthGroupPCD();
  });

  it("should work", async function () {
    await EthereumGroupPCDPackage.verify(ethGroupPCD);
  });

  it("serializes", async function () {
    const newEthGroupPCD = await EthereumGroupPCDPackage.deserialize(
      (
        await EthereumGroupPCDPackage.serialize(ethGroupPCD)
      ).pcd
    );
    EthereumGroupPCDPackage.verify(newEthGroupPCD);
  });

  it("should not verify tampered inputs", async function () {
    const newEthGroupPCD = await EthereumGroupPCDPackage.deserialize(
      (
        await EthereumGroupPCDPackage.serialize(ethGroupPCD)
      ).pcd
    );
    EthereumGroupPCDPackage.verify(newEthGroupPCD);

    newEthGroupPCD.claim.publicInput.circuitPubInput.merkleRoot =
      newEthGroupPCD.claim.publicInput.circuitPubInput.merkleRoot + BigInt(1);

    assert.rejects(() => EthereumGroupPCDPackage.verify(newEthGroupPCD));
  });

  it("should not be able create a PCD with a different identity", async function () {
    const identity1 = await SemaphoreIdentityPCDPackage.prove({
      identity: new Identity(),
    });
    const wallet = ethers.Wallet.createRandom(null);
    const { proof, publicInput } = await groupProof(identity1, wallet);

    const identity2 = await SemaphoreIdentityPCDPackage.prove({
      identity: new Identity(),
    });
    const serializedIdentity2 = await SemaphoreIdentityPCDPackage.serialize(
      identity2
    );

    assert.rejects(() =>
      EthereumGroupPCDPackage.prove({
        ethereumGroupProof: {
          argumentType: ArgumentTypeName.String,
          value: Buffer.from(proof).toString("hex"),
        },
        identity: {
          argumentType: ArgumentTypeName.PCD,
          pcdType: SemaphoreIdentityPCDTypeName,
          value: serializedIdentity2,
        },
        publicInput: publicInput,
        groupType: {
          argumentType: ArgumentTypeName.String,
          value: GroupType.PUBLICKEY,
        },
      })
    );
  });

  it("should not be able to create a PCD with tampered merkle root", async function () {
    const identity = await SemaphoreIdentityPCDPackage.prove({
      identity: new Identity(),
    });
    const serializedIdentity = await SemaphoreIdentityPCDPackage.serialize(
      identity
    );
    const wallet = ethers.Wallet.createRandom(null);
    const { proof, publicInput } = await groupProof(identity, wallet);

    // Tamper with the merkle root
    publicInput.circuitPubInput.merkleRoot =
      publicInput.circuitPubInput.merkleRoot + BigInt(1);

    assert.rejects(() =>
      EthereumGroupPCDPackage.prove({
        ethereumGroupProof: {
          argumentType: ArgumentTypeName.String,
          value: Buffer.from(proof).toString("hex"),
        },
        identity: {
          argumentType: ArgumentTypeName.PCD,
          pcdType: SemaphoreIdentityPCDTypeName,
          value: serializedIdentity,
        },
        publicInput: publicInput,
        groupType: {
          argumentType: ArgumentTypeName.String,
          value: GroupType.PUBLICKEY,
        },
      })
    );
  });
});
