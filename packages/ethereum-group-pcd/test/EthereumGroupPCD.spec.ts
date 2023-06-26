/* eslint-disable @typescript-eslint/no-non-null-assertion */
import { hashPersonalMessage } from "@ethereumjs/util";
import { ArgumentTypeName } from "@pcd/pcd-types";
import {
  SemaphoreIdentityPCDPackage,
  SemaphoreIdentityPCDTypeName,
} from "@pcd/semaphore-identity-pcd";
import { MembershipProver, Poseidon, Tree } from "@personaelabs/spartan-ecdsa";
import { Identity } from "@semaphore-protocol/identity";
import { ethers } from "ethers";
import "mocha";
import * as path from "path";
import {
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
describe("Ethereum Group PCD", function () {
  this.timeout(30 * 1000);

  this.beforeAll(async function () {
    await EthereumGroupPCDPackage.init!({
      zkeyFilePath,
      wasmFilePath,
    });
  });

  it("should work", async function () {
    const wallet = ethers.Wallet.createRandom(null);
    const identity = await SemaphoreIdentityPCDPackage.prove({
      identity: new Identity(),
    });
    const serializedIdentity = await SemaphoreIdentityPCDPackage.serialize(
      identity
    );
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
    const { proof, publicInput } = await prover.prove(
      signatureOfIdentityCommitment,
      msgHash,
      merkleProof
    );

    const ethereumPCD = await EthereumGroupPCDPackage.prove({
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

    await EthereumGroupPCDPackage.verify(ethereumPCD);
  });

  // it("should not be able create a PCD from an invalid signature", async function () {
  // const wallet = ethers.Wallet.createRandom(null);
  // const identity = await SemaphoreIdentityPCDPackage.prove({
  // identity: new Identity(),
  // });
  // const serializedIdentity = await SemaphoreIdentityPCDPackage.serialize(
  // identity
  // );
  // const signatureOfIdentityCommitment = await wallet.signMessage(
  // identity.claim.identity.commitment.toString()
  // );
  // const mangledSignature =
  // signatureOfIdentityCommitment.substring(
  // 0,
  // signatureOfIdentityCommitment.length - 1
  // ) + "0";
  //
  // await assert.rejects(async () => {
  // await EthereumGroupPCDPackage.prove({
  // ethereumAddress: {
  // argumentType: ArgumentTypeName.String,
  // value: wallet.address,
  // },
  // ethereumSignatureOfCommitment: {
  // argumentType: ArgumentTypeName.String,
  // value: mangledSignature,
  // },
  // identity: {
  // argumentType: ArgumentTypeName.PCD,
  // pcdType: SemaphoreIdentityPCDTypeName,
  // value: serializedIdentity,
  // },
  // });
  // });
  // });
  //
  // it("should not be able create a PCD where identity does not match identity pcd", async function () {
  // const wallet = ethers.Wallet.createRandom(null);
  // const identity = await SemaphoreIdentityPCDPackage.prove({
  // identity: new Identity(),
  // });
  // const serializedIdentity = await SemaphoreIdentityPCDPackage.serialize(
  // identity
  // );
  // const signatureOfIdentityCommitment = await wallet.signMessage(
  // identity.claim.identity.commitment.toString()
  // );
  //
  // assert.rejects(() =>
  // EthereumGroupPCDPackage.prove({
  // ethereumAddress: {
  // argumentType: ArgumentTypeName.String,
  // value: wallet.address,
  // },
  // ethereumSignatureOfCommitment: {
  // argumentType: ArgumentTypeName.String,
  // value: signatureOfIdentityCommitment,
  // },
  // identity: {
  // argumentType: ArgumentTypeName.PCD,
  // pcdType: SemaphoreIdentityPCDTypeName,
  // value: serializedIdentity,
  // },
  // })
  // );
  // });
  //
  // it("should not be able verify a PCD whose Ethereum address was tampered with", async function () {
  // const wallet = ethers.Wallet.createRandom(null);
  // const identity = await SemaphoreIdentityPCDPackage.prove({
  // identity: new Identity(),
  // });
  // const serializedIdentity = await SemaphoreIdentityPCDPackage.serialize(
  // identity
  // );
  // const signatureOfIdentityCommitment = await wallet.signMessage(
  // identity.claim.identity.commitment.toString()
  // );
  //
  // const pcd = await EthereumGroupPCDPackage.prove({
  // ethereumAddress: {
  // argumentType: ArgumentTypeName.String,
  // value: wallet.address,
  // },
  // ethereumSignatureOfCommitment: {
  // argumentType: ArgumentTypeName.String,
  // value: signatureOfIdentityCommitment,
  // },
  // identity: {
  // argumentType: ArgumentTypeName.PCD,
  // pcdType: SemaphoreIdentityPCDTypeName,
  // value: serializedIdentity,
  // },
  // });
  //
  // const mangledAddress =
  // pcd.claim.ethereumAddress.substring(
  // 0,
  // pcd.claim.ethereumAddress.length - 1
  // ) + "0";
  //
  // pcd.claim.ethereumAddress = mangledAddress;
  //
  // assert.rejects(EthereumGroupPCDPackage.verify(pcd));
  // });
});
