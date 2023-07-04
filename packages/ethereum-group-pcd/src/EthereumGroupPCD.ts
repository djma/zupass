import {
  ArgumentTypeName,
  DisplayOptions,
  PCD,
  PCDArgument,
  PCDPackage,
  SerializedPCD,
  StringArgument,
} from "@pcd/pcd-types";
import {
  SemaphoreIdentityPCD,
  SemaphoreIdentityPCDPackage,
  SemaphoreIdentityPCDTypeName,
} from "@pcd/semaphore-identity-pcd";
import {
  SemaphoreSignaturePCD,
  SemaphoreSignaturePCDPackage,
} from "@pcd/semaphore-signature-pcd";
import {
  MembershipProver,
  MembershipVerifier,
  ProverConfig,
  PublicInput,
} from "@personaelabs/spartan-ecdsa";
import { ethers } from "ethers";
import { sha256 } from "js-sha256";
import JSONBig from "json-bigint";
import { v4 as uuid } from "uuid";
import { SemaphoreIdentityCardBody as EthereumGroupCardBody } from "./CardBody";

/**
 * All signature PCDs are 'namespaced' to this pseudo-random nullifier,
 * so that they cannot be reused by malicious actors across different
 * applications.
 */
export const STATIC_ETH_PCD_NULLIFIER = generateMessageHash(
  "hardcoded-nullifier"
);

/**
 * Hashes a message to be signed with sha256 and fits it into a baby jub jub field element.
 * @param signal The initial message.
 * @returns The outputted hash, fed in as a signal to the Semaphore proof.
 */
export function generateMessageHash(signal: string): bigint {
  // right shift to fit into a field element, which is 254 bits long
  // shift by 8 ensures we have a 253 bit element
  return BigInt("0x" + sha256(signal)) >> BigInt(8);
}

export const EthereumGroupPCDTypeName = "ethereum-group-pcd";

export interface EthereumGroupPCDInitArgs {
  // TODO: how do we distribute these in-package, so that consumers
  // of the package don't have to copy-paste these artifacts?
  // TODO: how do we account for different versions of the same type
  // of artifact? eg. this one is parameterized by group size. Should
  // we pre-generate a bunch of artifacts per possible group size?
  // Should we do code-gen?
  zkeyFilePath: string;
  wasmFilePath: string;
}

// We hardcode the externalNullifer to also be your identityCommitment
// so that your nullifier for specific groups is not revealed when
// a SemaphoreSignaturePCD is requested from a consumer application.
export interface EthereumGroupPCDArgs {
  identity: PCDArgument<SemaphoreIdentityPCD>;
  signatureOfIdentityCommitment: StringArgument;
  merkleProof: StringArgument;
  groupType: StringArgument;
}

export interface EthereumGroupPCDClaim {
  publicInput: PublicInput;
  groupType: GroupType;
}

export enum GroupType {
  PUBLICKEY = "publickey",
  ADDRESS = "address",
}

export interface EthereumGroupPCDProof {
  signatureProof: SerializedPCD<SemaphoreSignaturePCD>;
  /**
   * hex string
   */
  ethereumGroupProof: string;
}

export class EthereumGroupPCD
  implements PCD<EthereumGroupPCDClaim, EthereumGroupPCDProof>
{
  type = EthereumGroupPCDTypeName;
  claim: EthereumGroupPCDClaim;
  proof: EthereumGroupPCDProof;
  id: string;

  public constructor(
    id: string,
    claim: EthereumGroupPCDClaim,
    proof: EthereumGroupPCDProof
  ) {
    this.id = id;
    this.claim = claim;
    this.proof = proof;
  }
}

export async function init(args: EthereumGroupPCDInitArgs): Promise<void> {
  return SemaphoreSignaturePCDPackage.init!(args);
}

const isNode =
  typeof process !== "undefined" &&
  process.versions != null &&
  process.versions.node != null;

export let addrMembershipConfig: ProverConfig;
export let pubkeyMembershipConfig: ProverConfig;
if (isNode) {
  addrMembershipConfig = {
    circuit: __dirname.concat("/../artifacts/addr_membership.circuit"),
    witnessGenWasm: __dirname.concat("/../artifacts/addr_membership.wasm"),
  };

  pubkeyMembershipConfig = {
    circuit: __dirname.concat("/../artifacts/pubkey_membership.circuit"),
    witnessGenWasm: __dirname.concat("/../artifacts/pubkey_membership.wasm"),
  };
} else {
  addrMembershipConfig = {
    circuit:
      "https://storage.googleapis.com/personae-proving-keys/membership/addr_membership.circuit",
    witnessGenWasm:
      "https://storage.googleapis.com/personae-proving-keys/membership/addr_membership.wasm",
  };

  pubkeyMembershipConfig = {
    circuit:
      "https://storage.googleapis.com/personae-proving-keys/membership/pubkey_membership.circuit",
    witnessGenWasm:
      "https://storage.googleapis.com/personae-proving-keys/membership/pubkey_membership.wasm",
  };
}

export async function prove(
  args: EthereumGroupPCDArgs
): Promise<EthereumGroupPCD> {
  if (args.identity.value === undefined) {
    throw new Error(`missing argument identity`);
  }

  if (args.signatureOfIdentityCommitment.value === undefined) {
    throw new Error(`missing argument signatureOfIdentityCommitment`);
  }

  if (args.merkleProof.value === undefined) {
    throw new Error(`missing argument merkleProof`);
  }

  const deserializedIdentity = await SemaphoreIdentityPCDPackage.deserialize(
    args.identity.value.pcd
  );
  const message = deserializedIdentity.claim.identity.commitment.toString();
  const msgHash = ethers.utils.hashMessage(message);

  const prover = new MembershipProver(pubkeyMembershipConfig);
  await prover.initWasm();
  const { proof, publicInput } = await prover.prove(
    args.signatureOfIdentityCommitment.value,
    Buffer.from(msgHash.slice(2), "hex"),
    JSONBig({ useNativeBigInt: true }).parse(args.merkleProof.value)
  );

  const publicInputMsgHash = "0x" + publicInput.msgHash.toString("hex");

  if (msgHash !== publicInputMsgHash) {
    throw new Error(
      `public input message hash ${publicInputMsgHash} does not match commitment ${message} hash ${msgHash} `
    );
  }

  const semaphoreSignature = await SemaphoreSignaturePCDPackage.prove({
    identity: {
      argumentType: ArgumentTypeName.PCD,
      pcdType: SemaphoreIdentityPCDTypeName,
      value: args.identity.value,
    },
    signedMessage: {
      argumentType: ArgumentTypeName.String,
      value: Buffer.from(proof).toString("hex"),
    },
  });

  return new EthereumGroupPCD(
    uuid(),
    {
      publicInput: publicInput,
      groupType:
        args.groupType.value === "address"
          ? GroupType.ADDRESS
          : GroupType.PUBLICKEY,
    },
    {
      signatureProof: await SemaphoreSignaturePCDPackage.serialize(
        semaphoreSignature
      ),
      ethereumGroupProof: Buffer.from(proof).toString("hex"),
    }
  );
}

export async function verify(pcd: EthereumGroupPCD): Promise<boolean> {
  const semaphoreSignature = await SemaphoreSignaturePCDPackage.deserialize(
    pcd.proof.signatureProof.pcd
  );
  const proofValid = await SemaphoreSignaturePCDPackage.verify(
    semaphoreSignature
  );

  // the semaphore signature of the group membership proof must be valid
  if (!proofValid) {
    return false;
  }

  // the string that the semaphore signature signed must equal to the ethereum
  // signature of the commitment
  if (semaphoreSignature.claim.signedMessage !== pcd.proof.ethereumGroupProof) {
    return false;
  }

  const deserializedSignatureProof =
    await SemaphoreSignaturePCDPackage.deserialize(
      pcd.proof.signatureProof.pcd
    );

  const deserializedIdentity =
    deserializedSignatureProof.claim.identityCommitment;
  const message = deserializedIdentity;
  const msgHash = ethers.utils.hashMessage(message);

  const publicInputMsgHash =
    "0x" + pcd.claim.publicInput.msgHash.toString("hex");

  if (msgHash !== publicInputMsgHash) {
    return false;
  }

  const verifier = new MembershipVerifier(
    pcd.claim.groupType === GroupType.ADDRESS
      ? addrMembershipConfig
      : pubkeyMembershipConfig
  );
  await verifier.initWasm();
  const verifies = await verifier.verify(
    new Uint8Array(Buffer.from(pcd.proof.ethereumGroupProof, "hex")),
    pcd.claim.publicInput.serialize()
  );

  if (!verifies) {
    return false;
  }

  return true;
}

export async function serialize(
  pcd: EthereumGroupPCD
): Promise<SerializedPCD<EthereumGroupPCD>> {
  return {
    type: EthereumGroupPCDTypeName,
    pcd: JSONBig().stringify(pcd),
  } as SerializedPCD<EthereumGroupPCD>;
}

export async function deserialize(
  serialized: string
): Promise<EthereumGroupPCD> {
  return JSONBig().parse(serialized);
}

export function getDisplayOptions(pcd: EthereumGroupPCD): DisplayOptions {
  return {
    header:
      "Merkle Group " +
      pcd.claim.publicInput.circuitPubInput.merkleRoot
        .toString(16)
        .substring(0, 12),
    displayName: "eth-group-" + pcd.id.substring(0, 4),
  };
}

/**
 * PCD-conforming wrapper to sign messages using one's Semaphore public key. This is a small
 * extension of the existing Semaphore protocol, which is mostly geared at group signatures.
 * Find documentation of Semaphore here: https://semaphore.appliedzkp.org/docs/introduction
 */
export const EthereumGroupPCDPackage: PCDPackage<
  EthereumGroupPCDClaim,
  EthereumGroupPCDProof,
  EthereumGroupPCDArgs,
  EthereumGroupPCDInitArgs
> = {
  name: EthereumGroupPCDTypeName,
  renderCardBody: EthereumGroupCardBody,
  getDisplayOptions,
  init,
  prove,
  verify,
  serialize,
  deserialize,
};
